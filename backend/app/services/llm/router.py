"""Model routing, health checks, discovery and invocation accounting.

Routing is deterministic and conservative: only enabled providers whose last
health check succeeded are candidates. If nothing healthy exists the caller gets
``503 ai_unavailable``; the platform never fabricates a completion.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from math import ceil
from typing import Any
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.crypto import decrypt_secret, sha256_hex
from app.core.db import utcnow
from app.core.errors import AppError, ServiceUnavailable, ValidationFailure
from app.models.ai import AIInvocation, AIModel, AIProvider
from app.models.core import Organization
from app.services.llm.base import BaseProviderClient, ChatResult, ProviderError
from app.services.llm.ollama import OllamaClient
from app.services.llm.openai_compat import OpenAICompatibleClient
from app.services.llm.safety import redact_prompt

_SEMAPHORE = threading.BoundedSemaphore(max(1, int(settings.ai_max_concurrency)))
_ORG_SEMAPHORES: dict[UUID, threading.BoundedSemaphore] = {}
_ORG_SEMAPHORES_LOCK = threading.Lock()

OPENAI_COMPATIBLE_KINDS = {"vllm", "llamacpp", "openai_compatible"}


@dataclass
class Candidate:
    provider: AIProvider
    model: AIModel
    client: BaseProviderClient


@dataclass
class CompletionResult:
    content: str
    model: str
    provider_id: UUID
    provider_name: str
    task: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: int
    invocation_id: UUID
    parsed: Any = None
    parse_error: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)


@dataclass
class EmbeddingResult:
    embeddings: list[list[float]]
    model: str
    provider_id: UUID
    provider_name: str
    prompt_tokens: int
    invocation_id: UUID


def decrypt_api_key(provider: AIProvider) -> str | None:
    if not provider.api_key_encrypted:
        return None
    try:
        return decrypt_secret(provider.api_key_encrypted)
    except ValueError as exc:
        raise ProviderError("Provider API key cannot be decrypted; re-enter it") from exc


def client_for(provider: AIProvider, timeout: float | None = None) -> BaseProviderClient:
    key = decrypt_api_key(provider)
    effective_timeout = timeout if timeout is not None else float(settings.ai_request_timeout_seconds)
    if provider.kind == "ollama":
        return OllamaClient(
            provider.base_url,
            key,
            effective_timeout,
            allow_private=provider.is_local,
            allowed_private_cidrs=settings.ai_private_allowed_cidrs if provider.is_local else None,
        )
    if provider.kind in OPENAI_COMPATIBLE_KINDS:
        return OpenAICompatibleClient(
            provider.base_url,
            key,
            effective_timeout,
            allow_private=provider.is_local,
            allowed_private_cidrs=settings.ai_private_allowed_cidrs if provider.is_local else None,
        )
    raise ProviderError(f"Unsupported AI provider kind: {provider.kind}")


def _acquire_slot() -> None:
    if not _SEMAPHORE.acquire(timeout=max(1, int(settings.ai_request_timeout_seconds))):
        raise ServiceUnavailable("AI concurrency limit reached; retry later", code="ai_unavailable")


def _release_slot() -> None:
    _SEMAPHORE.release()


def _org_semaphore(org_id: UUID) -> threading.BoundedSemaphore:
    with _ORG_SEMAPHORES_LOCK:
        semaphore = _ORG_SEMAPHORES.get(org_id)
        if semaphore is None:
            semaphore = threading.BoundedSemaphore(max(1, int(settings.ai_max_concurrency_per_org)))
            _ORG_SEMAPHORES[org_id] = semaphore
        return semaphore


def _acquire_org_slot(org_id: UUID) -> None:
    """Per-tenant concurrency cap so one organization cannot starve the rest."""
    semaphore = _org_semaphore(org_id)
    if not semaphore.acquire(timeout=max(1, int(settings.ai_request_timeout_seconds))):
        raise ServiceUnavailable("AI concurrency limit reached for this organization", code="ai_unavailable")
    try:
        _acquire_slot()
    except ServiceUnavailable:
        semaphore.release()
        raise


def _release_org_slot(org_id: UUID) -> None:
    _SEMAPHORE.release()
    _org_semaphore(org_id).release()


def estimate_tokens(text: str) -> int:
    return max(1, ceil(len(text) / 4))


def estimate_messages_tokens(messages: list[dict[str, str]]) -> int:
    return sum(estimate_tokens(str(message.get("content", ""))) for message in messages)


def _budget_value(configured: dict[str, Any], key: str, default: int) -> int:
    value = configured.get(key, default)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        # A malformed budget must fail closed, never become unlimited.
        return 0
    return value


def _org_settings(org: Organization) -> dict[str, Any]:
    settings_payload = org.settings if isinstance(org.settings, dict) else {}
    return settings_payload


def assert_ai_budget(db: Session, org: Organization, *, estimated_tokens: int, requests: int = 1) -> None:
    """Enforce per-organization token/request budgets before outbound inference.

    Limits are read from ``Organization.settings["ai_budget"]`` and fall back to
    platform defaults. A zero or malformed limit blocks inference (fail closed).
    Usage is measured from the AIInvocation ledger, so restarts cannot reset it.
    """
    configured = _org_settings(org).get("ai_budget")
    budget = configured if isinstance(configured, dict) else {}
    daily_tokens = _budget_value(budget, "daily_tokens", settings.ai_daily_token_budget_per_org)
    monthly_tokens = _budget_value(budget, "monthly_tokens", settings.ai_monthly_token_budget_per_org)
    daily_requests = _budget_value(budget, "daily_requests", settings.ai_daily_request_budget_per_org)

    now = utcnow()
    day_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    month_start = day_start.replace(day=1)
    token_expr = AIInvocation.prompt_tokens + AIInvocation.completion_tokens
    day_tokens = int(
        db.execute(
            select(func.coalesce(func.sum(token_expr), 0)).where(
                AIInvocation.org_id == org.id, AIInvocation.created_at >= day_start
            )
        ).scalar_one()
    )
    month_tokens = int(
        db.execute(
            select(func.coalesce(func.sum(token_expr), 0)).where(
                AIInvocation.org_id == org.id, AIInvocation.created_at >= month_start
            )
        ).scalar_one()
    )
    day_requests = int(
        db.execute(
            select(func.count())
            .select_from(AIInvocation)
            .where(AIInvocation.org_id == org.id, AIInvocation.created_at >= day_start)
        ).scalar_one()
    )

    def _deny(message: str) -> None:
        raise AppError("ai_budget_exceeded", message, 429)

    if daily_tokens == 0:
        _deny("AI token budget is disabled by policy for this organization")
    if daily_requests == 0:
        _deny("AI request budget is disabled by policy for this organization")
    if day_requests + requests > daily_requests:
        _deny("Daily AI request budget exhausted for this organization")
    if day_tokens + estimated_tokens > daily_tokens:
        _deny("Daily AI token budget exhausted for this organization")
    if month_tokens + estimated_tokens > monthly_tokens:
        _deny("Monthly AI token budget exhausted for this organization")


def provider_allowed_for_org(provider: AIProvider, org: Organization) -> bool:
    """Local-first sovereignty gate for external inference providers."""
    if provider.is_local:
        return True
    if not settings.ai_allow_external_providers:
        return False
    ai_settings = _org_settings(org).get("ai")
    if not isinstance(ai_settings, dict) or not ai_settings.get("external_opt_in"):
        return False
    region = str((provider.config or {}).get("data_region", "")).strip().lower()
    return region.startswith("eu")


def _candidate_rows(
    db: Session, org: Organization, task: str, model_name: str | None
) -> list[tuple[AIProvider, AIModel]]:
    stmt = (
        select(AIProvider, AIModel)
        .join(AIModel, AIModel.provider_id == AIProvider.id)
        .where(
            AIProvider.enabled.is_(True),
            AIProvider.health_status == "healthy",
            AIModel.status == "available",
            or_(AIProvider.org_id == org.id, AIProvider.org_id.is_(None)),
        )
    )
    if model_name:
        stmt = stmt.where(AIModel.name == model_name)
    rows = [
        (provider, model)
        for provider, model in db.execute(stmt.order_by(AIProvider.name, AIModel.name)).all()
        if provider_allowed_for_org(provider, org)
    ]

    if model_name:
        return rows

    primary = [row for row in rows if task in (row[1].task_tags or [])]
    defaults = [
        row for row in rows if row[0].default_model and row[1].name == row[0].default_model and row not in primary
    ]
    chat_fallback = [
        row for row in rows if "chat" in (row[1].task_tags or []) and row not in primary and row not in defaults
    ]
    return primary + defaults + chat_fallback


def _candidates(db: Session, org: Organization, task: str, model_name: str | None) -> list[Candidate]:
    candidates: list[Candidate] = []
    seen: set[tuple[UUID, UUID]] = set()
    for provider, model in _candidate_rows(db, org, task, model_name):
        key = (provider.id, model.id)
        if key in seen:
            continue
        try:
            client = client_for(provider)
        except ProviderError:
            continue
        seen.add(key)
        candidates.append(Candidate(provider=provider, model=model, client=client))
    return candidates


def _record_invocation(
    db: Session,
    *,
    org_id: UUID,
    provider: AIProvider | None,
    model_name: str,
    task: str,
    prompt: str,
    prompt_tokens: int,
    completion_tokens: int,
    latency_ms: int,
    status: str,
    error: str | None,
    request_id: str | None,
) -> AIInvocation:
    invocation = AIInvocation(
        org_id=org_id,
        provider_id=provider.id if provider else None,
        model=model_name[:160] if model_name else "unknown",
        task=task[:60],
        prompt_hash=sha256_hex(prompt),
        prompt_redacted=redact_prompt(prompt),
        prompt_tokens=max(0, prompt_tokens),
        completion_tokens=max(0, completion_tokens),
        latency_ms=max(0, latency_ms),
        status=status,
        error=redact_prompt(error, 1000) if error else None,
        request_id=request_id[:64] if request_id else None,
    )
    db.add(invocation)
    db.flush()
    return invocation


def _mark_unhealthy(db: Session, provider: AIProvider, error: str) -> None:
    provider.health_status = "unhealthy"
    provider.last_health_at = utcnow()
    provider.last_health_error = redact_prompt(error, 1000)
    db.flush()


def _mark_healthy(db: Session, provider: AIProvider) -> None:
    provider.health_status = "healthy"
    provider.last_health_at = utcnow()
    provider.last_health_error = None
    db.flush()


def check_provider_health(db: Session, provider: AIProvider) -> dict[str, Any]:
    """Run a real read-only health check and persist the outcome."""
    try:
        client = client_for(provider)
    except ProviderError as exc:
        _mark_unhealthy(db, provider, str(exc))
        return {"healthy": False, "error": redact_prompt(str(exc), 500), "detail": {}}
    _acquire_slot()
    try:
        result = client.health()
    finally:
        _release_slot()
    if result.ok:
        _mark_healthy(db, provider)
        return {"healthy": True, "error": None, "detail": result.detail}
    _mark_unhealthy(db, provider, result.error or "Provider health check failed")
    return {"healthy": False, "error": redact_prompt(result.error or "", 500), "detail": result.detail}


def discover_models(db: Session, provider: AIProvider) -> dict[str, Any]:
    """Fetch the runtime's real model list and upsert metadata without inventing names."""
    try:
        client = client_for(provider)
        with _semaphore_guard():
            names = client.list_models()
    except ProviderError as exc:
        _mark_unhealthy(db, provider, str(exc))
        raise ServiceUnavailable(
            f"Model discovery failed: {redact_prompt(str(exc), 300)}", code="ai_discovery_failed"
        ) from exc

    created = 0
    updated = 0
    models: list[AIModel] = []
    for name in names:
        existing = db.execute(
            select(AIModel).where(AIModel.provider_id == provider.id, AIModel.name == name)
        ).scalar_one_or_none()
        if existing is None:
            existing = AIModel(
                provider_id=provider.id,
                name=name,
                display_name=name,
                task_tags=[],
                context_window=8192,
                max_output_tokens=2048,
                status="available",
            )
            db.add(existing)
            created += 1
        else:
            updated += 1
        models.append(existing)
    _mark_healthy(db, provider)
    provider.config = {
        **(provider.config or {}),
        "last_discovery_at": utcnow().isoformat(),
        "discovered_models": len(names),
    }
    db.flush()
    return {"models": models, "created": created, "updated": updated, "total": len(names)}


class _semaphore_guard:
    def __enter__(self) -> None:
        _acquire_slot()

    def __exit__(self, exc_type, exc, tb) -> None:  # type: ignore[no-untyped-def]
        _release_slot()


def complete(
    db: Session,
    *,
    org_id: UUID,
    task: str,
    messages: list[dict[str, str]],
    model_name: str | None = None,
    max_tokens: int | None = None,
    temperature: float = 0.2,
    expect_json: bool = False,
    request_id: str | None = None,
) -> CompletionResult:
    org = db.get(Organization, org_id)
    if org is None:
        raise ServiceUnavailable("Organization is not available for inference", code="ai_unavailable")
    prompt_tokens_estimate = estimate_messages_tokens(messages)
    requested_output = max_tokens if max_tokens is not None else 2048
    assert_ai_budget(db, org, estimated_tokens=prompt_tokens_estimate + requested_output)
    candidates = _candidates(db, org, task, model_name)
    if not candidates:
        raise ServiceUnavailable(
            "No configured, healthy AI provider/model is available for this task", code="ai_unavailable"
        )

    if model_name is not None and max_tokens is not None:
        best_output = max(candidate.model.max_output_tokens for candidate in candidates)
        if max_tokens > best_output:
            raise ValidationFailure(
                [
                    {
                        "field": "max_tokens",
                        "message": f"max_tokens exceeds the model maximum output of {best_output}",
                    }
                ]
            )

    prompt = "\n".join(str(message.get("content", "")) for message in messages)
    attempted: set[UUID] = set()
    last_error = "No candidate produced a response"
    skipped_for_context = False

    for candidate in candidates:
        if candidate.provider.id in attempted:
            continue
        model = candidate.model
        requested = max_tokens if max_tokens is not None else model.max_output_tokens
        effective_max = max(1, min(int(requested), int(model.max_output_tokens)))
        if prompt_tokens_estimate + effective_max > int(model.context_window):
            skipped_for_context = True
            if model_name is not None:
                raise ValidationFailure(
                    [
                        {
                            "field": "messages",
                            "message": (
                                f"Prompt requires {prompt_tokens_estimate} tokens plus {effective_max} output "
                                f"tokens, exceeding the model context window of {model.context_window}"
                            ),
                        }
                    ]
                )
            continue

        attempted.add(candidate.provider.id)
        started = time.perf_counter()
        _acquire_org_slot(org_id)
        try:
            chat = candidate.client.chat(
                model.name,
                messages,
                max_tokens=effective_max,
                temperature=max(0.0, min(2.0, float(temperature))),
            )
        except ProviderError as exc:
            latency_ms = int((time.perf_counter() - started) * 1000)
            last_error = str(exc)
            _record_invocation(
                db,
                org_id=org_id,
                provider=candidate.provider,
                model_name=model.name,
                task=task,
                prompt=prompt,
                prompt_tokens=prompt_tokens_estimate,
                completion_tokens=0,
                latency_ms=latency_ms,
                status="error",
                error=str(exc),
                request_id=request_id,
            )
            _mark_unhealthy(db, candidate.provider, str(exc))
            continue
        finally:
            _release_org_slot(org_id)

        latency_ms = int((time.perf_counter() - started) * 1000)
        parsed, parse_error = _parse_if_requested(chat, expect_json)
        invocation = _record_invocation(
            db,
            org_id=org_id,
            provider=candidate.provider,
            model_name=model.name,
            task=task,
            prompt=prompt,
            prompt_tokens=chat.prompt_tokens or prompt_tokens_estimate,
            completion_tokens=chat.completion_tokens or estimate_tokens(chat.content),
            latency_ms=latency_ms,
            status="success",
            error=None,
            request_id=request_id,
        )
        _mark_healthy(db, candidate.provider)
        return CompletionResult(
            content=chat.content,
            model=model.name,
            provider_id=candidate.provider.id,
            provider_name=candidate.provider.name,
            task=task,
            prompt_tokens=chat.prompt_tokens or prompt_tokens_estimate,
            completion_tokens=chat.completion_tokens or estimate_tokens(chat.content),
            latency_ms=latency_ms,
            invocation_id=invocation.id,
            parsed=parsed,
            parse_error=parse_error,
            raw=chat.raw,
        )

    if skipped_for_context and not attempted:
        raise ValidationFailure(
            [{"field": "messages", "message": "Prompt exceeds every available model context window"}]
        )
    raise ServiceUnavailable(f"AI providers were unavailable: {redact_prompt(last_error, 300)}", code="ai_unavailable")


def _parse_if_requested(chat: ChatResult, expect_json: bool) -> tuple[Any, str | None]:
    if not expect_json:
        return None, None
    try:
        return json.loads(chat.content), None
    except (ValueError, TypeError) as exc:
        return None, f"Invalid JSON returned by model: {exc}"[:500]


def embeddings(
    db: Session,
    *,
    org_id: UUID,
    inputs: list[str],
    model_name: str | None = None,
    task: str = "embeddings",
    request_id: str | None = None,
) -> EmbeddingResult:
    # ``model_name`` short-circuits tag filtering inside ``_candidate_rows`` so an
    # explicitly requested embedding model is honoured even without a task tag.
    org = db.get(Organization, org_id)
    if org is None:
        raise ServiceUnavailable("Organization is not available for inference", code="ai_unavailable")
    prompt_for_budget = "\n".join(inputs)
    assert_ai_budget(db, org, estimated_tokens=estimate_tokens(prompt_for_budget))
    candidates = _candidates(db, org, "embedding", model_name)
    if not candidates:
        raise ServiceUnavailable("No configured, healthy embedding provider is available", code="ai_unavailable")

    prompt = "\n".join(inputs)
    last_error = "No candidate produced embeddings"
    for candidate in candidates:
        started = time.perf_counter()
        _acquire_org_slot(org_id)
        try:
            vectors = candidate.client.embeddings(candidate.model.name, inputs)
        except ProviderError as exc:
            latency_ms = int((time.perf_counter() - started) * 1000)
            last_error = str(exc)
            _record_invocation(
                db,
                org_id=org_id,
                provider=candidate.provider,
                model_name=candidate.model.name,
                task=task,
                prompt=prompt,
                prompt_tokens=estimate_tokens(prompt),
                completion_tokens=0,
                latency_ms=latency_ms,
                status="error",
                error=str(exc),
                request_id=request_id,
            )
            _mark_unhealthy(db, candidate.provider, str(exc))
            continue
        finally:
            _release_org_slot(org_id)

        if len(vectors) != len(inputs) or any(not vector for vector in vectors):
            _mark_unhealthy(db, candidate.provider, "Embedding provider returned an incomplete batch")
            continue
        latency_ms = int((time.perf_counter() - started) * 1000)
        invocation = _record_invocation(
            db,
            org_id=org_id,
            provider=candidate.provider,
            model_name=candidate.model.name,
            task=task,
            prompt=prompt,
            prompt_tokens=estimate_tokens(prompt),
            completion_tokens=0,
            latency_ms=latency_ms,
            status="success",
            error=None,
            request_id=request_id,
        )
        _mark_healthy(db, candidate.provider)
        return EmbeddingResult(
            embeddings=vectors,
            model=candidate.model.name,
            provider_id=candidate.provider.id,
            provider_name=candidate.provider.name,
            prompt_tokens=estimate_tokens(prompt),
            invocation_id=invocation.id,
        )

    raise ServiceUnavailable(
        f"Embedding providers were unavailable: {redact_prompt(last_error, 300)}", code="ai_unavailable"
    )


def healthy_provider_summary(db: Session, org_id: UUID) -> dict[str, Any]:
    providers = list(
        db.execute(
            select(AIProvider)
            .where(or_(AIProvider.org_id == org_id, AIProvider.org_id.is_(None)))
            .order_by(AIProvider.name)
        ).scalars()
    )
    healthy = [provider for provider in providers if provider.enabled and provider.health_status == "healthy"]
    return {
        "providers_total": len(providers),
        "providers_enabled": sum(1 for provider in providers if provider.enabled),
        "providers_healthy": len(healthy),
        "available": bool(healthy),
        "providers": [
            {
                "id": str(provider.id),
                "name": provider.name,
                "kind": provider.kind,
                "enabled": provider.enabled,
                "health_status": provider.health_status,
                "last_health_at": provider.last_health_at,
                "last_health_error": provider.last_health_error,
            }
            for provider in providers
        ],
    }


__all__ = [
    "Candidate",
    "CompletionResult",
    "EmbeddingResult",
    "check_provider_health",
    "client_for",
    "complete",
    "decrypt_api_key",
    "discover_models",
    "embeddings",
    "estimate_messages_tokens",
    "estimate_tokens",
    "healthy_provider_summary",
]
