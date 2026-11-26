"""AI model registry, discovery, evaluation and evaluation history."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, or_, select

from app.core.db import utcnow
from app.core.deps import RequestContext, require_permission
from app.core.errors import Conflict, ValidationFailure
from app.core.schemas import Page, paginate
from app.models.ai import AIModel, AIProvider
from app.modules.ai.common import (
    ensure_can_manage_provider,
    get_model_or_404,
    get_provider_or_404,
    model_out,
    provider_visible_to,
    scoped_provider_filter,
)
from app.modules.ai.schemas import EvaluateRequest, ModelCreate, ModelOut, ModelPatch

router = APIRouter(prefix="/models", tags=["AI Gateway"])


@router.get("", response_model=Page[ModelOut], summary="List model registry entries")
def list_models(
    ctx: RequestContext = Depends(require_permission("ai:read")),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    provider_id: UUID | None = Query(default=None),
    task: str | None = Query(default=None, max_length=60),
    status: str | None = Query(default=None, pattern="^(available|disabled|deprecated)$"),
    q: str | None = Query(default=None, max_length=160),
) -> Page[ModelOut]:
    stmt = (
        select(AIModel, AIProvider)
        .join(AIProvider, AIProvider.id == AIModel.provider_id)
        .where(scoped_provider_filter(ctx.org.id))
        .order_by(AIProvider.name, AIModel.name)
    )
    if provider_id:
        stmt = stmt.where(AIModel.provider_id == provider_id)
    if task:
        stmt = stmt.where(AIModel.task_tags.contains([task]))
    if status:
        stmt = stmt.where(AIModel.status == status)
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(AIModel.name).like(needle), func.lower(AIModel.display_name).like(needle)))
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).all()
    return Page[ModelOut](**paginate([model_out(model, provider) for model, provider in rows], total, page, page_size))


@router.post("", response_model=ModelOut, status_code=201, summary="Register model metadata")
def create_model(payload: ModelCreate, ctx: RequestContext = Depends(require_permission("ai:admin"))) -> ModelOut:
    provider = get_provider_or_404(ctx.db, ctx, payload.provider_id)
    ensure_can_manage_provider(ctx, provider)
    if payload.max_output_tokens > payload.context_window:
        raise ValidationFailure(
            [{"field": "max_output_tokens", "message": "max_output_tokens must not exceed context_window"}]
        )
    duplicate = ctx.db.execute(
        select(AIModel).where(AIModel.provider_id == provider.id, AIModel.name == payload.name.strip())
    ).scalar_one_or_none()
    if duplicate is not None:
        raise Conflict("This model is already registered for the provider")
    model = AIModel(
        provider_id=provider.id,
        name=payload.name.strip(),
        display_name=payload.display_name or payload.name.strip(),
        task_tags=payload.task_tags,
        context_window=payload.context_window,
        max_output_tokens=payload.max_output_tokens,
        status=payload.status,
        evaluation={},
    )
    ctx.db.add(model)
    ctx.db.flush()
    ctx.audit(
        action="ai.model.create",
        resource_type="ai_model",
        resource_id=str(model.id),
        payload={"provider_id": str(provider.id), "name": model.name, "task_tags": model.task_tags},
        org_id=provider.org_id or ctx.org.id,
    )
    ctx.db.commit()
    ctx.db.refresh(model)
    return model_out(model, provider)


@router.get("/{model_id}", response_model=ModelOut, summary="Read a model registry entry")
def get_model(model_id: UUID, ctx: RequestContext = Depends(require_permission("ai:read"))) -> ModelOut:
    model, provider = get_model_or_404(ctx.db, ctx, model_id)
    return model_out(model, provider)


@router.patch("/{model_id}", response_model=ModelOut, summary="Update model metadata")
def update_model(
    model_id: UUID,
    payload: ModelPatch,
    ctx: RequestContext = Depends(require_permission("ai:admin")),
) -> ModelOut:
    model, provider = get_model_or_404(ctx.db, ctx, model_id)
    ensure_can_manage_provider(ctx, provider)
    changes = payload.model_dump(exclude_unset=True)
    for field in ("display_name", "task_tags", "context_window", "max_output_tokens", "status"):
        if field in changes and changes[field] is not None:
            setattr(model, field, changes[field])
    if model.max_output_tokens > model.context_window:
        raise ValidationFailure(
            [{"field": "max_output_tokens", "message": "max_output_tokens must not exceed context_window"}]
        )
    ctx.audit(
        action="ai.model.update",
        resource_type="ai_model",
        resource_id=str(model.id),
        payload={"fields": sorted(changes.keys())},
        org_id=provider.org_id or ctx.org.id,
    )
    ctx.db.commit()
    ctx.db.refresh(model)
    return model_out(model, provider)


@router.delete("/{model_id}", status_code=204, response_class=Response, summary="Remove a model registry entry")
def delete_model(model_id: UUID, ctx: RequestContext = Depends(require_permission("ai:admin"))) -> Response:
    model, provider = get_model_or_404(ctx.db, ctx, model_id)
    ensure_can_manage_provider(ctx, provider)
    ctx.audit(
        action="ai.model.delete",
        resource_type="ai_model",
        resource_id=str(model.id),
        payload={"name": model.name, "provider_id": str(provider.id)},
        org_id=provider.org_id or ctx.org.id,
    )
    ctx.db.delete(model)
    ctx.db.commit()
    return Response(status_code=204)


@router.post("/{model_id}/evaluate", summary="Evaluate a model with a deterministic rubric")
def evaluate_model(
    model_id: UUID,
    payload: EvaluateRequest,
    ctx: RequestContext = Depends(require_permission("ai:use")),
) -> dict:
    model, provider = get_model_or_404(ctx.db, ctx, model_id)
    if not provider_visible_to(ctx, provider):
        raise ValidationFailure([{"field": "model_id", "message": "Model is not available"}])
    from app.modules.ai.evaluation import evaluate_model_cases

    try:
        summary = evaluate_model_cases(ctx.db, ctx.org.id, model, provider, payload, request_id=ctx.request_id)
    except Exception:
        ctx.db.commit()
        raise
    ctx.audit(
        action="ai.model.evaluation",
        resource_type="ai_model",
        resource_id=str(model.id),
        payload={"passed": summary["passed"], "total": summary["total"], "score": summary["score"]},
        org_id=provider.org_id or ctx.org.id,
    )
    ctx.db.commit()
    return summary


@router.get("/{model_id}/evaluations", summary="Read stored evaluation results")
def get_evaluations(model_id: UUID, ctx: RequestContext = Depends(require_permission("ai:read"))) -> dict:
    model, _provider = get_model_or_404(ctx.db, ctx, model_id)
    evaluation = model.evaluation or {}
    return {
        "model_id": str(model.id),
        "model": model.name,
        "latest": evaluation.get("latest"),
        "history": evaluation.get("history", []),
        "evaluated_at": (evaluation.get("latest") or {}).get("evaluated_at") or utcnow().isoformat(),
    }


__all__ = ["router"]
