"""SOAR API: playbook authoring/validation, dry-runs and durable executions."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.core.deps import RequestContext, require_permission
from app.core.errors import Conflict, Forbidden, NotFound, ValidationFailure
from app.core.schemas import Page, paginate
from app.models.core import Approval
from app.models.events import Alert
from app.models.incidents import Incident, Playbook, PlaybookExecution
from app.modules.soar.schemas import (
    ExecutionCreate,
    ExecutionDetail,
    ExecutionOut,
    ExecutionStart,
    PlaybookCreate,
    PlaybookOut,
    PlaybookPatch,
    ResumeOut,
    SimulateRequest,
    StepOut,
    ValidateRequest,
    ValidationIssue,
    ValidationResult,
)
from app.modules.soar.validation import validate_definition
from app.services.broker import BrokerActor
from app.services.playbook_engine import (
    create_execution,
    ordered_steps,
    resume_execution,
    run_execution,
    simulate_playbook,
)

router = APIRouter(prefix="/soar", tags=["SOAR & Automation"])

_PLAYBOOK_SORTS = {
    "created_at": Playbook.created_at,
    "updated_at": Playbook.updated_at,
    "published_at": Playbook.published_at,
    "name": Playbook.name,
    "version": Playbook.version,
    "status": Playbook.status,
}
_EXECUTION_SORTS = {
    "started_at": PlaybookExecution.started_at,
    "finished_at": PlaybookExecution.finished_at,
    "status": PlaybookExecution.status,
}


def _actor(ctx: RequestContext) -> BrokerActor:
    return BrokerActor.from_context(ctx)


def _get_playbook(ctx: RequestContext, playbook_id: UUID) -> Playbook:
    playbook = ctx.db.get(Playbook, playbook_id)
    if playbook is None or (playbook.org_id is not None and playbook.org_id != ctx.org.id):
        raise NotFound("Playbook")
    return playbook


def _assert_writable(ctx: RequestContext, playbook: Playbook) -> None:
    if playbook.org_id is None and not (ctx.user and ctx.user.is_platform_admin):
        raise Forbidden("Global playbooks can only be modified by platform administrators")


def _get_execution(ctx: RequestContext, execution_id: UUID) -> PlaybookExecution:
    execution = ctx.db.get(PlaybookExecution, execution_id)
    if execution is None or execution.org_id != ctx.org.id:
        raise NotFound("Execution")
    return execution


def _detail(db: Session, execution: PlaybookExecution) -> ExecutionDetail:
    steps = ordered_steps(db, execution.id)
    approval_status = None
    if execution.approval_id:
        approval = db.get(Approval, execution.approval_id)
        approval_status = approval.status if approval else None
    base = ExecutionOut.model_validate(execution)
    return ExecutionDetail(
        **base.model_dump(),
        steps=[StepOut.model_validate(step) for step in steps],
        approval_status=approval_status,
    )


def _merged_definition(definition: dict[str, Any], triggers: dict[str, Any] | None) -> dict[str, Any]:
    merged = dict(definition)
    if triggers is not None:
        merged["triggers"] = triggers
    return merged


def _validation_result(definition: dict[str, Any], level: str) -> ValidationResult:
    try:
        normalized = validate_definition(definition, min_autonomy_level=level)
    except ValidationFailure as exc:
        return ValidationResult(
            valid=False,
            errors=[ValidationIssue(**detail) for detail in exc.details],
        )
    return ValidationResult(valid=True, normalized=normalized)


@router.get("/playbooks", response_model=Page[PlaybookOut], summary="List playbooks")
def list_playbooks(
    ctx: RequestContext = Depends(require_permission("playbook:read")),
    status: str | None = Query(default=None, pattern="^(draft|published|archived)$"),
    q: str | None = Query(default=None, max_length=200),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    sort: str = Query(default="updated_at"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
) -> Page[PlaybookOut]:
    if sort not in _PLAYBOOK_SORTS:
        raise ValidationFailure([{"field": "sort", "message": f"Sort must be one of: {', '.join(_PLAYBOOK_SORTS)}"}])
    stmt = select(Playbook).where(or_(Playbook.org_id == ctx.org.id, Playbook.org_id.is_(None)))
    if status:
        stmt = stmt.where(Playbook.status == status)
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Playbook.name).like(needle),
                func.lower(func.coalesce(Playbook.description, "")).like(needle),
            )
        )
    column = _PLAYBOOK_SORTS[sort]
    stmt = stmt.order_by(column.asc() if order == "asc" else column.desc(), Playbook.id.asc())
    total = ctx.db.execute(select(func.count()).select_from(stmt.order_by(None).subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[PlaybookOut](**paginate([PlaybookOut.model_validate(row) for row in rows], total, page, page_size))


@router.post("/playbooks/validate", response_model=ValidationResult, summary="Validate a definition")
def validate_payload(
    payload: ValidateRequest, ctx: RequestContext = Depends(require_permission("playbook:write"))
) -> ValidationResult:
    definition = _merged_definition(payload.definition, payload.triggers)
    return _validation_result(definition, payload.min_autonomy_level)


@router.post("/playbooks", response_model=PlaybookOut, status_code=201, summary="Create a draft playbook")
def create_playbook(
    payload: PlaybookCreate, ctx: RequestContext = Depends(require_permission("playbook:write"))
) -> PlaybookOut:
    definition = _merged_definition(payload.definition, payload.triggers)
    normalized = validate_definition(definition, min_autonomy_level=payload.min_autonomy_level)
    playbook = Playbook(
        org_id=ctx.org.id,
        name=payload.name.strip(),
        description=payload.description,
        version=1,
        status="draft",
        trigger=normalized["triggers"],
        definition=normalized,
        min_autonomy_level=payload.min_autonomy_level,
        created_by=ctx.actor_id,
    )
    ctx.db.add(playbook)
    ctx.db.flush()
    ctx.audit(
        action="playbook.create",
        resource_type="playbook",
        resource_id=str(playbook.id),
        payload={"name": playbook.name, "version": 1, "steps": len(normalized["steps"])},
    )
    ctx.db.commit()
    ctx.db.refresh(playbook)
    return PlaybookOut.model_validate(playbook)


@router.get("/playbooks/{playbook_id}", response_model=PlaybookOut, summary="Read a playbook")
def get_playbook(playbook_id: UUID, ctx: RequestContext = Depends(require_permission("playbook:read"))) -> PlaybookOut:
    return PlaybookOut.model_validate(_get_playbook(ctx, playbook_id))


@router.patch("/playbooks/{playbook_id}", response_model=PlaybookOut, summary="Edit a playbook")
def update_playbook(
    playbook_id: UUID,
    payload: PlaybookPatch,
    ctx: RequestContext = Depends(require_permission("playbook:write")),
) -> PlaybookOut:
    playbook = _get_playbook(ctx, playbook_id)
    _assert_writable(ctx, playbook)
    if playbook.status == "archived":
        raise Conflict("Archived playbooks cannot be edited")
    data = payload.model_dump(exclude_unset=True)
    current_definition = dict(playbook.definition or {})
    if payload.definition is not None:
        current_definition = _merged_definition(payload.definition, payload.triggers)
    elif payload.triggers is not None:
        current_definition["triggers"] = payload.triggers
    level = payload.min_autonomy_level or playbook.min_autonomy_level
    normalized = validate_definition(current_definition, min_autonomy_level=level)

    if playbook.status == "published":
        # Immutable published versions: edits create the next draft version.
        new_playbook = Playbook(
            org_id=playbook.org_id,
            name=(payload.name or playbook.name).strip(),
            description=payload.description if "description" in data else playbook.description,
            version=playbook.version + 1,
            status="draft",
            trigger=normalized["triggers"],
            definition=normalized,
            min_autonomy_level=level,
            created_by=ctx.actor_id,
        )
        ctx.db.add(new_playbook)
        ctx.db.flush()
        ctx.audit(
            action="playbook.version.create",
            resource_type="playbook",
            resource_id=str(new_playbook.id),
            payload={
                "name": new_playbook.name,
                "version": new_playbook.version,
                "based_on": str(playbook.id),
            },
        )
        ctx.db.commit()
        ctx.db.refresh(new_playbook)
        return PlaybookOut.model_validate(new_playbook)

    if payload.name is not None:
        playbook.name = payload.name.strip()
    if "description" in data:
        playbook.description = payload.description
    playbook.definition = normalized
    playbook.trigger = normalized["triggers"]
    playbook.min_autonomy_level = level
    ctx.audit(
        action="playbook.update",
        resource_type="playbook",
        resource_id=str(playbook.id),
        payload={"version": playbook.version, "fields": sorted(data.keys())},
    )
    ctx.db.commit()
    ctx.db.refresh(playbook)
    return PlaybookOut.model_validate(playbook)


@router.post("/playbooks/{playbook_id}/validate", response_model=ValidationResult, summary="Validate a stored playbook")
def validate_playbook(
    playbook_id: UUID, ctx: RequestContext = Depends(require_permission("playbook:read"))
) -> ValidationResult:
    playbook = _get_playbook(ctx, playbook_id)
    return _validation_result(playbook.definition or {}, playbook.min_autonomy_level)


@router.post("/playbooks/{playbook_id}/simulate", summary="Dry-run a playbook against a context")
def simulate(
    playbook_id: UUID,
    payload: SimulateRequest,
    ctx: RequestContext = Depends(require_permission("playbook:execute")),
) -> dict[str, Any]:
    playbook = _get_playbook(ctx, playbook_id)
    incident_id = payload.incident_id
    if incident_id is not None:
        incident = ctx.db.get(Incident, incident_id)
        if incident is None or incident.org_id != ctx.org.id:
            raise NotFound("Incident")
    return simulate_playbook(
        ctx.db,
        org=ctx.org,
        playbook=playbook,
        context=payload.context,
        incident_id=incident_id,
    )


@router.post("/playbooks/{playbook_id}/publish", response_model=PlaybookOut, summary="Publish a draft playbook")
def publish_playbook(
    playbook_id: UUID, ctx: RequestContext = Depends(require_permission("playbook:write"))
) -> PlaybookOut:
    playbook = _get_playbook(ctx, playbook_id)
    _assert_writable(ctx, playbook)
    if playbook.status == "published":
        raise Conflict("The playbook is already published")
    if playbook.status == "archived":
        raise Conflict("Archived playbooks cannot be published")
    normalized = validate_definition(playbook.definition or {}, min_autonomy_level=playbook.min_autonomy_level)
    previous = list(
        ctx.db.execute(
            select(Playbook).where(
                Playbook.org_id == playbook.org_id,
                Playbook.name == playbook.name,
                Playbook.status == "published",
                Playbook.id != playbook.id,
            )
        ).scalars()
    )
    for row in previous:
        row.status = "archived"
        ctx.audit(
            action="playbook.archive",
            resource_type="playbook",
            resource_id=str(row.id),
            payload={"reason": "superseded", "by": str(playbook.id)},
        )
    playbook.definition = normalized
    playbook.trigger = normalized["triggers"]
    playbook.status = "published"
    playbook.published_at = utcnow()
    ctx.audit(
        action="playbook.publish",
        resource_type="playbook",
        resource_id=str(playbook.id),
        payload={"version": playbook.version, "steps": len(normalized["steps"])},
    )
    ctx.db.commit()
    ctx.db.refresh(playbook)
    return PlaybookOut.model_validate(playbook)


@router.post("/playbooks/{playbook_id}/archive", response_model=PlaybookOut, summary="Archive a playbook")
def archive_playbook(
    playbook_id: UUID, ctx: RequestContext = Depends(require_permission("playbook:write"))
) -> PlaybookOut:
    playbook = _get_playbook(ctx, playbook_id)
    _assert_writable(ctx, playbook)
    if playbook.status == "archived":
        raise Conflict("The playbook is already archived")
    playbook.status = "archived"
    ctx.audit(
        action="playbook.archive",
        resource_type="playbook",
        resource_id=str(playbook.id),
        payload={"version": playbook.version},
    )
    ctx.db.commit()
    ctx.db.refresh(playbook)
    return PlaybookOut.model_validate(playbook)


def _resolve_trigger_scope(
    ctx: RequestContext,
    incident_id: UUID | None,
    alert_id: UUID | None,
    context: dict[str, Any],
) -> tuple[UUID | None, dict[str, Any], str]:
    merged = dict(context)
    trigger = "manual"
    alert: Alert | None = None
    if alert_id is not None:
        alert = ctx.db.get(Alert, alert_id)
        if alert is None or alert.org_id != ctx.org.id:
            raise NotFound("Alert")
        trigger = "alert"
        merged.setdefault(
            "alert",
            {
                "id": str(alert.id),
                "title": alert.title,
                "severity": alert.severity,
                "status": alert.status,
                "count": alert.count,
                "mitre": alert.mitre,
                "risk_score": alert.risk_score,
                "incident_id": str(alert.incident_id) if alert.incident_id else None,
            },
        )
        if incident_id is None and alert.incident_id is not None:
            incident_id = alert.incident_id
        elif incident_id is not None and alert.incident_id is not None and alert.incident_id != incident_id:
            raise Conflict("The alert is linked to a different incident")
    if incident_id is not None:
        incident = ctx.db.get(Incident, incident_id)
        if incident is None or incident.org_id != ctx.org.id:
            raise NotFound("Incident")
        if alert_id is None:
            trigger = "incident"
        merged.setdefault(
            "incident",
            {
                "id": str(incident.id),
                "ref": incident.ref,
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
                "priority": incident.priority,
                "mitre": incident.mitre,
                "affected_asset_ids": incident.affected_asset_ids,
            },
        )
    return incident_id, merged, trigger


def _start(
    ctx: RequestContext,
    playbook: Playbook,
    *,
    incident_id: UUID | None,
    alert_id: UUID | None,
    context: dict[str, Any],
    dry_run: bool,
    requested_level: str | None,
) -> PlaybookExecution:
    if playbook.status != "published":
        raise Conflict("Only published playbooks can be executed")
    incident_id, merged, trigger = _resolve_trigger_scope(ctx, incident_id, alert_id, context)
    execution = create_execution(
        ctx.db,
        org=ctx.org,
        playbook=playbook,
        actor=_actor(ctx),
        trigger=trigger,
        context=merged,
        incident_id=incident_id,
        dry_run=dry_run,
        requested_level=requested_level,
    )
    return run_execution(ctx.db, execution, _actor(ctx))


@router.post(
    "/playbooks/{playbook_id}/execute",
    response_model=ExecutionDetail,
    status_code=201,
    summary="Execute a published playbook",
)
def execute_playbook(
    playbook_id: UUID,
    payload: ExecutionStart,
    response: Response,
    ctx: RequestContext = Depends(require_permission("playbook:execute")),
) -> ExecutionDetail:
    playbook = _get_playbook(ctx, playbook_id)
    execution = _start(
        ctx,
        playbook,
        incident_id=payload.incident_id,
        alert_id=payload.alert_id,
        context=payload.context,
        dry_run=payload.dry_run,
        requested_level=payload.requested_level,
    )
    if execution.status == "waiting_approval":
        response.status_code = 202
    return _detail(ctx.db, execution)


@router.get("/executions", response_model=Page[ExecutionOut], summary="List playbook executions")
def list_executions(
    ctx: RequestContext = Depends(require_permission("playbook:read")),
    status: str | None = Query(default=None, max_length=30),
    playbook_id: UUID | None = Query(default=None),
    incident_id: UUID | None = Query(default=None),
    dry_run: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    sort: str = Query(default="started_at"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
) -> Page[ExecutionOut]:
    if sort not in _EXECUTION_SORTS:
        raise ValidationFailure([{"field": "sort", "message": f"Sort must be one of: {', '.join(_EXECUTION_SORTS)}"}])
    stmt = select(PlaybookExecution).where(PlaybookExecution.org_id == ctx.org.id)
    if status:
        stmt = stmt.where(PlaybookExecution.status == status)
    if playbook_id:
        stmt = stmt.where(PlaybookExecution.playbook_id == playbook_id)
    if incident_id:
        stmt = stmt.where(PlaybookExecution.incident_id == incident_id)
    if dry_run is not None:
        stmt = stmt.where(PlaybookExecution.dry_run.is_(dry_run))
    column = _EXECUTION_SORTS[sort]
    stmt = stmt.order_by(column.asc() if order == "asc" else column.desc(), PlaybookExecution.id.asc())
    total = ctx.db.execute(select(func.count()).select_from(stmt.order_by(None).subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[ExecutionOut](**paginate([ExecutionOut.model_validate(row) for row in rows], total, page, page_size))


@router.post("/executions", response_model=ExecutionDetail, status_code=201, summary="Trigger an execution")
def trigger_execution(
    payload: ExecutionCreate,
    response: Response,
    ctx: RequestContext = Depends(require_permission("playbook:execute")),
) -> ExecutionDetail:
    playbook = _get_playbook(ctx, payload.playbook_id)
    execution = _start(
        ctx,
        playbook,
        incident_id=payload.incident_id,
        alert_id=payload.alert_id,
        context=payload.context,
        dry_run=payload.dry_run,
        requested_level=payload.requested_level,
    )
    if execution.status == "waiting_approval":
        response.status_code = 202
    return _detail(ctx.db, execution)


@router.get("/executions/{execution_id}", response_model=ExecutionDetail, summary="Read an execution")
def get_execution(
    execution_id: UUID, ctx: RequestContext = Depends(require_permission("playbook:read"))
) -> ExecutionDetail:
    return _detail(ctx.db, _get_execution(ctx, execution_id))


@router.get(
    "/executions/{execution_id}/steps",
    response_model=list[StepOut],
    summary="Read execution steps in order",
)
def get_execution_steps(
    execution_id: UUID, ctx: RequestContext = Depends(require_permission("playbook:read"))
) -> list[StepOut]:
    execution = _get_execution(ctx, execution_id)
    return [StepOut.model_validate(step) for step in ordered_steps(ctx.db, execution.id)]


@router.post("/executions/{execution_id}/resume", response_model=ResumeOut, summary="Resume after an approval")
def resume(execution_id: UUID, ctx: RequestContext = Depends(require_permission("playbook:execute"))) -> ResumeOut:
    execution = _get_execution(ctx, execution_id)
    if execution.status != "waiting_approval":
        raise Conflict("The execution is not waiting for approval")
    approval = ctx.db.get(Approval, execution.approval_id) if execution.approval_id else None
    resumed = True
    reason: str | None = None
    if approval is not None and approval.status in {"rejected", "expired"}:
        resumed = False
        reason = f"approval_{approval.status}"
    execution = resume_execution(ctx.db, execution, _actor(ctx))
    return ResumeOut(execution=_detail(ctx.db, execution), resumed=resumed, reason=reason)


__all__ = ["router"]
