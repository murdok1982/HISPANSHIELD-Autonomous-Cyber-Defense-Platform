"""AI provider CRUD and real health checks."""

from __future__ import annotations

from datetime import UTC
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, or_, select

from app.core.config import settings
from app.core.crypto import encrypt_secret
from app.core.db import utcnow
from app.core.deps import RequestContext, require_permission
from app.core.errors import Conflict, Forbidden
from app.core.schemas import Page, paginate
from app.models.ai import AIModel, AIProvider
from app.modules.ai.common import (
    can_manage_provider,
    ensure_can_manage_provider,
    get_provider_or_404,
    is_platform_admin,
    model_out,
    provider_out,
    scoped_provider_filter,
    validate_provider_url,
)
from app.modules.ai.schemas import (
    ModelDiscoverOut,
    ProviderCreate,
    ProviderHealthOut,
    ProviderOut,
    ProviderPatch,
)
from app.services.llm.router import check_provider_health, discover_models

router = APIRouter(prefix="/providers", tags=["AI Gateway"])


@router.get("", response_model=Page[ProviderOut], summary="List AI providers visible to the organization")
def list_providers(
    ctx: RequestContext = Depends(require_permission("ai:read")),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    q: str | None = Query(default=None, max_length=120),
    scope: str = Query(default="all", pattern="^(all|organization|platform)$"),
) -> Page[ProviderOut]:
    stmt = select(AIProvider).where(scoped_provider_filter(ctx.org.id)).order_by(AIProvider.name)
    if scope == "organization":
        stmt = stmt.where(AIProvider.org_id == ctx.org.id)
    elif scope == "platform":
        stmt = stmt.where(AIProvider.org_id.is_(None))
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(AIProvider.name).like(needle), func.lower(AIProvider.kind).like(needle)))
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[ProviderOut](**paginate([provider_out(row) for row in rows], total, page, page_size))


@router.post("", response_model=ProviderOut, status_code=201, summary="Register an AI provider")
def create_provider(
    payload: ProviderCreate, ctx: RequestContext = Depends(require_permission("ai:admin"))
) -> ProviderOut:
    if payload.scope == "platform" and not is_platform_admin(ctx):
        raise Forbidden("Only platform administrators can create platform-wide AI providers")
    if not payload.is_local:
        if not settings.ai_allow_external_providers:
            raise Forbidden(
                "External AI providers are disabled on this platform; enable HS_AI_ALLOW_EXTERNAL_PROVIDERS "
                "and record the organization's external_opt_in before use"
            )
        region = str((payload.config or {}).get("data_region", "")).strip().lower()
        if not region.startswith("eu"):
            raise Forbidden("External AI providers must declare an EU data_region (sovereignty policy)")
    org_id = None if payload.scope == "platform" else ctx.org.id
    duplicate = ctx.db.execute(
        select(AIProvider).where(
            AIProvider.org_id.is_(None) if org_id is None else AIProvider.org_id == org_id,
            AIProvider.name == payload.name.strip(),
        )
    ).scalar_one_or_none()
    if duplicate is not None:
        raise Conflict("An AI provider with this name already exists")

    base_url = validate_provider_url(payload.base_url, is_local=payload.is_local)
    provider = AIProvider(
        org_id=org_id,
        name=payload.name.strip(),
        kind=payload.kind,
        base_url=base_url,
        default_model=payload.default_model,
        api_key_encrypted=encrypt_secret(payload.api_key) if payload.api_key else None,
        is_local=payload.is_local,
        enabled=payload.enabled,
        health_status="unknown",
        config=payload.config,
    )
    ctx.db.add(provider)
    ctx.db.flush()
    ctx.audit(
        action="ai.provider.create",
        resource_type="ai_provider",
        resource_id=str(provider.id),
        payload={
            "name": provider.name,
            "kind": provider.kind,
            "base_url": provider.base_url,
            "scope": payload.scope,
            "has_api_key": bool(provider.api_key_encrypted),
        },
        org_id=provider.org_id or ctx.org.id,
    )
    ctx.db.commit()
    ctx.db.refresh(provider)
    return provider_out(provider)


@router.get("/{provider_id}", response_model=ProviderOut, summary="Read an AI provider")
def get_provider(provider_id: UUID, ctx: RequestContext = Depends(require_permission("ai:read"))) -> ProviderOut:
    return provider_out(get_provider_or_404(ctx.db, ctx, provider_id))


@router.patch("/{provider_id}", response_model=ProviderOut, summary="Update an AI provider")
def update_provider(
    provider_id: UUID,
    payload: ProviderPatch,
    ctx: RequestContext = Depends(require_permission("ai:admin")),
) -> ProviderOut:
    provider = get_provider_or_404(ctx.db, ctx, provider_id)
    ensure_can_manage_provider(ctx, provider)
    changes = payload.model_dump(exclude_unset=True)
    if "base_url" in changes and changes["base_url"] is not None:
        effective_local = changes.get("is_local", provider.is_local)
        changes["base_url"] = validate_provider_url(changes["base_url"], is_local=bool(effective_local))
    if payload.clear_api_key:
        provider.api_key_encrypted = None
    if payload.api_key:
        provider.api_key_encrypted = encrypt_secret(payload.api_key)
    for field in ("name", "kind", "base_url", "default_model", "is_local", "enabled", "config"):
        if field in changes and changes[field] is not None:
            setattr(provider, field, changes[field])
    if "name" in changes and changes["name"]:
        provider.name = changes["name"].strip()
    if "enabled" in changes and changes["enabled"] is False:
        provider.health_status = "disabled"
    if "enabled" in changes and changes["enabled"] is True and provider.health_status == "disabled":
        provider.health_status = "unknown"
    ctx.audit(
        action="ai.provider.update",
        resource_type="ai_provider",
        resource_id=str(provider.id),
        payload={"fields": sorted(changes.keys()), "api_key_changed": bool(payload.api_key or payload.clear_api_key)},
        org_id=provider.org_id or ctx.org.id,
    )
    ctx.db.commit()
    ctx.db.refresh(provider)
    return provider_out(provider)


@router.delete(
    "/{provider_id}", status_code=204, response_class=Response, summary="Delete an AI provider and its models"
)
def delete_provider(provider_id: UUID, ctx: RequestContext = Depends(require_permission("ai:admin"))) -> Response:
    provider = get_provider_or_404(ctx.db, ctx, provider_id)
    ensure_can_manage_provider(ctx, provider)
    ctx.audit(
        action="ai.provider.delete",
        resource_type="ai_provider",
        resource_id=str(provider.id),
        payload={"name": provider.name, "kind": provider.kind},
        org_id=provider.org_id or ctx.org.id,
    )
    ctx.db.delete(provider)
    ctx.db.commit()
    return Response(status_code=204)


def _run_health_check(ctx: RequestContext, provider: AIProvider) -> ProviderHealthOut:
    result = check_provider_health(ctx.db, provider)
    ctx.audit(
        action="ai.provider.health_check",
        resource_type="ai_provider",
        resource_id=str(provider.id),
        outcome="success" if result["healthy"] else "failure",
        payload={"healthy": result["healthy"], "error": result["error"]},
        org_id=provider.org_id or ctx.org.id,
    )
    ctx.db.commit()
    ctx.db.refresh(provider)
    return ProviderHealthOut(
        provider_id=provider.id,
        healthy=bool(result["healthy"]),
        health_status=provider.health_status,
        error=result["error"],
        detail=result["detail"],
        checked_at=provider.last_health_at or utcnow().astimezone(UTC),
    )


@router.post("/{provider_id}/health", response_model=ProviderHealthOut, summary="Run a real provider health check")
def provider_health(
    provider_id: UUID, ctx: RequestContext = Depends(require_permission("ai:admin"))
) -> ProviderHealthOut:
    provider = get_provider_or_404(ctx.db, ctx, provider_id)
    ensure_can_manage_provider(ctx, provider)
    return _run_health_check(ctx, provider)


@router.post("/{provider_id}/test", response_model=ProviderHealthOut, summary="Alias for the provider health check")
def provider_health_alias(
    provider_id: UUID, ctx: RequestContext = Depends(require_permission("ai:admin"))
) -> ProviderHealthOut:
    provider = get_provider_or_404(ctx.db, ctx, provider_id)
    ensure_can_manage_provider(ctx, provider)
    return _run_health_check(ctx, provider)


@router.post(
    "/{provider_id}/discover",
    response_model=ModelDiscoverOut,
    summary="Discover the runtime's real model list and upsert metadata",
)
def discover_provider_models(
    provider_id: UUID, ctx: RequestContext = Depends(require_permission("ai:admin"))
) -> ModelDiscoverOut:
    provider = get_provider_or_404(ctx.db, ctx, provider_id)
    ensure_can_manage_provider(ctx, provider)
    try:
        result = discover_models(ctx.db, provider)
    except Exception:
        # Persist the degraded health state before surfacing the error.
        ctx.db.commit()
        raise
    ctx.audit(
        action="ai.provider.discover",
        resource_type="ai_provider",
        resource_id=str(provider.id),
        payload={"discovered": result["total"], "created": result["created"], "updated": result["updated"]},
        org_id=provider.org_id or ctx.org.id,
    )
    ctx.db.commit()
    ctx.db.refresh(provider)
    return ModelDiscoverOut(
        provider_id=provider.id,
        provider_name=provider.name,
        discovered=result["total"],
        created=result["created"],
        updated=result["updated"],
        models=[model_out(model, provider) for model in result["models"]],
    )


@router.get("/{provider_id}/models", summary="List models known for a provider")
def provider_models(provider_id: UUID, ctx: RequestContext = Depends(require_permission("ai:read"))) -> dict:
    provider = get_provider_or_404(ctx.db, ctx, provider_id)
    rows = list(
        ctx.db.execute(select(AIModel).where(AIModel.provider_id == provider.id).order_by(AIModel.name)).scalars()
    )
    return {
        "provider_id": str(provider.id),
        "provider_name": provider.name,
        "models": [
            {
                "id": str(model.id),
                "name": model.name,
                "task_tags": list(model.task_tags or []),
                "status": model.status,
                "context_window": model.context_window,
                "max_output_tokens": model.max_output_tokens,
            }
            for model in rows
        ],
        "count": len(rows),
    }


__all__ = ["can_manage_provider", "router"]
