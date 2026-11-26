"""Shared helpers for the AI gateway module (scope checks, serialization)."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.audit import redact
from app.core.deps import RequestContext
from app.core.errors import Forbidden, NotFound, ValidationFailure
from app.core.ssrf import SSRFError, validate_outbound_url
from app.models.ai import AIModel, AIProvider
from app.modules.ai.schemas import ModelOut, ProviderOut


def is_platform_admin(ctx: RequestContext) -> bool:
    return bool(ctx.user and ctx.user.is_platform_admin) or ctx.role == "platform_admin"


def provider_visible_to(ctx: RequestContext, provider: AIProvider) -> bool:
    return provider.org_id is None or provider.org_id == ctx.org.id


def can_manage_provider(ctx: RequestContext, provider: AIProvider) -> bool:
    if provider.org_id is None:
        return is_platform_admin(ctx)
    return ctx.can("ai:admin")


def ensure_can_manage_provider(ctx: RequestContext, provider: AIProvider) -> None:
    if not can_manage_provider(ctx, provider):
        raise Forbidden("Only platform administrators can manage platform-wide AI providers")


def validate_provider_url(url: str) -> str:
    try:
        return validate_outbound_url(url.strip(), allow_private=True)
    except SSRFError as exc:
        raise ValidationFailure([{"field": "base_url", "message": str(exc)}]) from exc


def get_provider_or_404(db: Session, ctx: RequestContext, provider_id: UUID) -> AIProvider:
    provider = db.get(AIProvider, provider_id)
    if provider is None or not provider_visible_to(ctx, provider):
        raise NotFound("AI provider")
    return provider


def get_model_or_404(db: Session, ctx: RequestContext, model_id: UUID) -> tuple[AIModel, AIProvider]:
    row = db.execute(
        select(AIModel, AIProvider).join(AIProvider, AIProvider.id == AIModel.provider_id).where(AIModel.id == model_id)
    ).first()
    if row is None:
        raise NotFound("AI model")
    model, provider = row
    if not provider_visible_to(ctx, provider):
        raise NotFound("AI model")
    return model, provider


def provider_out(provider: AIProvider) -> ProviderOut:
    return ProviderOut(
        id=provider.id,
        org_id=provider.org_id,
        name=provider.name,
        kind=provider.kind,
        base_url=provider.base_url,
        default_model=provider.default_model,
        is_local=provider.is_local,
        enabled=provider.enabled,
        health_status=provider.health_status,
        last_health_at=provider.last_health_at,
        last_health_error=provider.last_health_error,
        last_error=provider.last_health_error,
        config=redact(provider.config or {}),
        has_api_key=bool(provider.api_key_encrypted),
        created_at=provider.created_at,
        updated_at=provider.updated_at,
    )


def model_out(model: AIModel, provider: AIProvider | None = None) -> ModelOut:
    return ModelOut(
        id=model.id,
        provider_id=model.provider_id,
        provider_name=provider.name if provider else None,
        name=model.name,
        display_name=model.display_name,
        task_tags=list(model.task_tags or []),
        context_window=model.context_window,
        max_output_tokens=model.max_output_tokens,
        status=model.status,
        evaluation=model.evaluation or {},
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def scoped_provider_filter(org_id: UUID) -> Any:
    return or_(AIProvider.org_id == org_id, AIProvider.org_id.is_(None))
