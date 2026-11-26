"""Autonomous defence API: policy previews, brokered execution and rollback."""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, or_, select

from app.core.db import utcnow
from app.core.deps import RequestContext, require_permission
from app.core.errors import (
    Conflict,
    NotFound,
    PolicyDenied,
    ServiceUnavailable,
    ValidationFailure,
)
from app.core.schemas import Page, paginate
from app.models.core import Approval
from app.models.incidents import Incident, Remediation
from app.modules.defence.schemas import (
    ActionCatalogueOut,
    DefenceExecuteResult,
    EffectiveKillSwitchesOut,
    EvaluateRequest,
    ExecuteRequest,
    PolicySnapshotOut,
    RemediationOut,
    SimulateRequest,
    VerifyRequest,
    VerifyResult,
)
from app.modules.defence.service import (
    catalogue_payload,
    connector_preview,
    effective_kill_switches,
    ot_asset_violation,
    rollback_action_for,
)
from app.services.actions import ACTIONS, get_action, level_index
from app.services.broker import BrokerActor, execute_action, rollback_action
from app.services.connectors.base import AdapterResult, ConnectorError
from app.services.connectors.runtime import instantiate_adapter, select_connector
from app.services.policy_engine import active_policy_snapshot, evaluate

router = APIRouter(prefix="/defence", tags=["Autonomous Defence"])

_REMEDIATION_SORTS = {
    "executed_at": Remediation.executed_at,
    "status": Remediation.status,
    "action_type": Remediation.action_type,
    "risk_level": Remediation.risk_level,
}
_APPROVAL_TTL = timedelta(hours=24)


def _actor(ctx: RequestContext) -> BrokerActor:
    return BrokerActor.from_context(ctx)


def _validate_incident(ctx: RequestContext, incident_id: UUID | None, allow_none: bool = True) -> Incident | None:
    if incident_id is None:
        if allow_none:
            return None
        raise ValidationFailure([{"field": "incident_id", "message": "incident_id is required"}])
    incident = ctx.db.get(Incident, incident_id)
    if incident is None or incident.org_id != ctx.org.id:
        raise NotFound("Incident")
    return incident


def _get_remediation(ctx: RequestContext, remediation_id: UUID) -> Remediation:
    remediation = ctx.db.get(Remediation, remediation_id)
    if remediation is None or remediation.org_id != ctx.org.id:
        raise NotFound("Remediation")
    return remediation


def _exceeds_ceiling(ctx: RequestContext, requested_level: str | None) -> bool:
    return bool(requested_level and level_index(requested_level) > level_index(ctx.org.autonomy_level))


def _denial(ctx: RequestContext, action_type: str, reason: str, effective_level: str) -> dict[str, Any]:
    definition = get_action(action_type)
    return {
        "allowed": False,
        "reason": reason,
        "action": definition.key if definition else None,
        "effective_level": effective_level,
        "org_max_level": ctx.org.autonomy_level,
        "requires_approval": True,
        "approved": False,
        "kill_switch_engaged": False,
        "risk": definition.risk if definition else "unknown",
        "reversible": definition.reversible if definition else False,
        "constraints": {"requested_level": effective_level},
        "policy_id": None,
    }


def _ceiling_denial(ctx: RequestContext, requested_level: str, action_type: str) -> dict[str, Any]:
    return _denial(
        ctx,
        action_type,
        f"Requested autonomy level {requested_level} exceeds the organization ceiling {ctx.org.autonomy_level}",
        requested_level,
    )


def _audit_denial(ctx: RequestContext, payload: ExecuteRequest, reason: str) -> None:
    ctx.audit(
        action="defence.action.denied",
        resource_type="remediation",
        resource_id=str(payload.incident_id) if payload.incident_id else None,
        outcome="failure",
        payload={
            "action_type": payload.action_type,
            "target_type": payload.target_type,
            "target_id": payload.target_id,
            "reason": reason[:500],
        },
    )
    ctx.db.commit()


@router.get("/actions", response_model=ActionCatalogueOut, summary="Defensive action catalogue and policy preview")
def list_actions(ctx: RequestContext = Depends(require_permission("defence:read"))) -> ActionCatalogueOut:
    def decision_for(action_type: str):
        return evaluate(ctx.db, ctx.org, action_type, dry_run=True)

    payload = catalogue_payload(ctx.db, ctx.org, decision_for)
    return ActionCatalogueOut(
        **payload,
        policy=active_policy_snapshot(ctx.db, ctx.org.id),
    )


@router.post("/evaluate", summary="Evaluate an action against policy without executing")
def evaluate_action(
    payload: EvaluateRequest, ctx: RequestContext = Depends(require_permission("defence:read"))
) -> dict[str, Any]:
    _validate_incident(ctx, payload.incident_id)
    if payload.requested_level and _exceeds_ceiling(ctx, payload.requested_level):
        return _ceiling_denial(ctx, payload.requested_level, payload.action_type)
    violation = ot_asset_violation(ctx.db, ctx.org.id, payload.action_type, payload.target_id)
    if violation:
        definition = get_action(payload.action_type)
        return _denial(
            ctx,
            payload.action_type,
            violation,
            definition.min_level if definition else "A4",
        )
    decision = evaluate(
        ctx.db,
        ctx.org,
        payload.action_type,
        target_type=payload.target_type,
        target_id=payload.target_id,
        requested_level=payload.requested_level,
        dry_run=True,
    )
    return decision.as_dict()


@router.post("/simulate", summary="Simulate an action and return its execution plan")
def simulate_action(
    payload: SimulateRequest, ctx: RequestContext = Depends(require_permission("defence:read"))
) -> dict[str, Any]:
    _validate_incident(ctx, payload.incident_id)
    ot_violation = ot_asset_violation(ctx.db, ctx.org.id, payload.action_type, payload.target_id)
    if payload.requested_level and _exceeds_ceiling(ctx, payload.requested_level):
        decision_payload = _ceiling_denial(ctx, payload.requested_level, payload.action_type)
        return {
            "decision": decision_payload,
            "plan": {
                "would_execute": False,
                "requires_approval": True,
                "approval_satisfied": False,
                "connector": connector_preview(ctx.db, ctx.org.id, payload.action_type),
                "target_type": payload.target_type,
                "target_id": payload.target_id,
                "parameters": payload.parameters,
                "reason": decision_payload["reason"],
                "note": "Simulation only; no connector request is sent",
            },
        }
    if ot_violation:
        definition = get_action(payload.action_type)
        decision_payload = _denial(
            ctx,
            payload.action_type,
            ot_violation,
            definition.min_level if definition else "A4",
        )
        return {
            "decision": decision_payload,
            "plan": {
                "would_execute": False,
                "requires_approval": True,
                "approval_satisfied": False,
                "connector": connector_preview(ctx.db, ctx.org.id, payload.action_type),
                "target_type": payload.target_type,
                "target_id": payload.target_id,
                "parameters": payload.parameters,
                "reason": ot_violation,
                "note": "Simulation only; no connector request is sent",
            },
        }
    decision = evaluate(
        ctx.db,
        ctx.org,
        payload.action_type,
        target_type=payload.target_type,
        target_id=payload.target_id,
        requested_level=payload.requested_level,
        dry_run=True,
    )
    return {
        "decision": decision.as_dict(),
        "plan": {
            "would_execute": decision.allowed,
            "requires_approval": decision.requires_approval,
            "approval_satisfied": decision.approved,
            "connector": connector_preview(ctx.db, ctx.org.id, payload.action_type),
            "target_type": payload.target_type,
            "target_id": payload.target_id,
            "parameters": payload.parameters,
            "note": "Simulation only; no connector request is sent",
        },
    }


@router.post("/execute", response_model=DefenceExecuteResult, summary="Execute or request approval for an action")
def execute_defensive_action(
    payload: ExecuteRequest,
    response: Response,
    ctx: RequestContext = Depends(require_permission("defence:execute")),
) -> DefenceExecuteResult:
    _validate_incident(ctx, payload.incident_id)
    if payload.requested_level and _exceeds_ceiling(ctx, payload.requested_level):
        _audit_denial(
            ctx,
            payload,
            f"Requested autonomy level {payload.requested_level} exceeds the organization ceiling "
            f"{ctx.org.autonomy_level}",
        )
        raise PolicyDenied(
            f"Requested autonomy level {payload.requested_level} exceeds the organization ceiling "
            f"{ctx.org.autonomy_level}"
        )
    action = get_action(payload.action_type)
    if action is None or action.internal:
        _audit_denial(ctx, payload, "Unknown or internal action; only catalogue actions can be executed")
        raise PolicyDenied("Unknown action; only catalogue actions can be executed")

    violation = ot_asset_violation(ctx.db, ctx.org.id, payload.action_type, payload.target_id)
    if violation:
        _audit_denial(ctx, payload, violation)
        raise PolicyDenied(violation)

    actor = _actor(ctx)
    decision = evaluate(
        ctx.db,
        ctx.org,
        payload.action_type,
        target_type=payload.target_type,
        target_id=payload.target_id,
        requested_level=payload.requested_level,
        approved=payload.approval_id is not None,
        dry_run=payload.dry_run,
    )

    if not decision.allowed:
        approvable = evaluate(
            ctx.db,
            ctx.org,
            payload.action_type,
            target_type=payload.target_type,
            target_id=payload.target_id,
            requested_level=payload.requested_level,
            approved=True,
            dry_run=payload.dry_run,
        )
        if payload.dry_run:
            plan = {
                "would_execute": approvable.allowed,
                "requires_approval": decision.requires_approval,
                "connector": connector_preview(ctx.db, ctx.org.id, payload.action_type),
                "target_type": payload.target_type,
                "target_id": payload.target_id,
                "parameters": payload.parameters,
                "note": "Simulation only; no approval request is created",
            }
            return DefenceExecuteResult(
                status="simulated",
                approval_required=decision.requires_approval,
                decision=decision.as_dict(),
                result={"plan": plan},
            )
        if decision.requires_approval and approvable.allowed and payload.approval_id is None:
            approval = Approval(
                org_id=ctx.org.id,
                request_type="defensive_action",
                resource_type="incident" if payload.incident_id else "remediation",
                resource_id=str(payload.incident_id) if payload.incident_id else None,
                payload={
                    "action_type": payload.action_type,
                    "target_type": payload.target_type,
                    "target_id": payload.target_id,
                    "parameters": payload.parameters,
                    "incident_id": str(payload.incident_id) if payload.incident_id else None,
                    "requested_level": payload.requested_level,
                    "connector_id": str(payload.connector_id) if payload.connector_id else None,
                },
                status="pending",
                requested_by=(ctx.actor_email or ctx.actor_id or "system")[:64],
                requested_by_user_id=ctx.user.id if ctx.user else None,
                expires_at=utcnow() + _APPROVAL_TTL,
            )
            ctx.db.add(approval)
            ctx.db.flush()
            remediation = Remediation(
                org_id=ctx.org.id,
                incident_id=payload.incident_id,
                action_type=payload.action_type,
                target_type=payload.target_type,
                target_id=payload.target_id,
                parameters=payload.parameters,
                status="pending_approval",
                risk_level=decision.risk,
                autonomy_level=decision.effective_level,
                authorization_id=approval.id,
            )
            ctx.db.add(remediation)
            ctx.db.flush()
            ctx.audit(
                action="defence.approval.requested",
                resource_type="remediation",
                resource_id=str(remediation.id),
                payload={
                    "approval_id": str(approval.id),
                    "action_type": payload.action_type,
                    "target_type": payload.target_type,
                    "target_id": payload.target_id,
                    "reason": decision.reason,
                },
            )
            ctx.db.commit()
            ctx.db.refresh(remediation)
            response.status_code = 202
            return DefenceExecuteResult(
                status="pending_approval",
                approval_required=True,
                approval_id=approval.id,
                remediation_id=remediation.id,
                decision=approvable.as_dict(),
                remediation=RemediationOut.model_validate(remediation),
            )
        _audit_denial(ctx, payload, decision.reason)
        raise PolicyDenied(decision.reason, details=[decision.as_dict()])

    if payload.dry_run:
        result = execute_action(
            ctx.db,
            org=ctx.org,
            actor=actor,
            action_type=payload.action_type,
            target_type=payload.target_type,
            target_id=payload.target_id,
            parameters=payload.parameters,
            incident_id=payload.incident_id,
            approval_id=payload.approval_id,
            connector_id=payload.connector_id,
            requested_level=payload.requested_level,
            dry_run=True,
        )
        ctx.audit(
            action="defence.action.simulated",
            resource_type="remediation",
            resource_id=payload.incident_id and str(payload.incident_id) or None,
            payload={"action_type": payload.action_type, "target_id": payload.target_id},
        )
        ctx.db.commit()
        return DefenceExecuteResult(
            status="simulated",
            approval_required=decision.requires_approval,
            decision=result.decision.as_dict(),
            result=result.as_dict(),
        )

    remediation = Remediation(
        org_id=ctx.org.id,
        incident_id=payload.incident_id,
        action_type=payload.action_type,
        target_type=payload.target_type,
        target_id=payload.target_id,
        parameters=payload.parameters,
        status="pending",
        risk_level=decision.risk,
        autonomy_level=decision.effective_level,
        authorization_id=payload.approval_id,
    )
    ctx.db.add(remediation)
    ctx.db.flush()
    try:
        result = execute_action(
            ctx.db,
            org=ctx.org,
            actor=actor,
            action_type=payload.action_type,
            target_type=payload.target_type,
            target_id=payload.target_id,
            parameters=payload.parameters,
            incident_id=payload.incident_id,
            approval_id=payload.approval_id,
            connector_id=payload.connector_id,
            requested_level=payload.requested_level,
            remediation=remediation,
        )
    except PolicyDenied as exc:
        remediation.status = "denied"
        ctx.db.commit()
        _audit_denial(ctx, payload, str(exc))
        raise
    except ServiceUnavailable:
        remediation.status = "failed"
        ctx.db.commit()
        raise
    ctx.db.refresh(remediation)
    return DefenceExecuteResult(
        status=result.status,
        approval_required=decision.requires_approval,
        approval_id=payload.approval_id,
        remediation_id=remediation.id,
        decision=result.decision.as_dict(),
        remediation=RemediationOut.model_validate(remediation),
        result=result.as_dict(),
    )


@router.get("/remediations", response_model=Page[RemediationOut], summary="List remediations")
def list_remediations(
    ctx: RequestContext = Depends(require_permission("defence:read")),
    status: str | None = Query(default=None, max_length=30),
    action_type: str | None = Query(default=None, max_length=80),
    target_type: str | None = Query(default=None, max_length=40),
    incident_id: UUID | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    sort: str = Query(default="executed_at"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
) -> Page[RemediationOut]:
    if sort not in _REMEDIATION_SORTS:
        raise ValidationFailure([{"field": "sort", "message": f"Sort must be one of: {', '.join(_REMEDIATION_SORTS)}"}])
    stmt = select(Remediation).where(Remediation.org_id == ctx.org.id)
    if status:
        stmt = stmt.where(Remediation.status == status)
    if action_type:
        stmt = stmt.where(Remediation.action_type == action_type)
    if target_type:
        stmt = stmt.where(Remediation.target_type == target_type)
    if incident_id:
        stmt = stmt.where(Remediation.incident_id == incident_id)
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Remediation.target_id).like(needle),
                func.lower(Remediation.action_type).like(needle),
            )
        )
    column = _REMEDIATION_SORTS[sort]
    stmt = stmt.order_by(column.asc() if order == "asc" else column.desc(), Remediation.id.asc())
    total = ctx.db.execute(select(func.count()).select_from(stmt.order_by(None).subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[RemediationOut](
        **paginate([RemediationOut.model_validate(row) for row in rows], total, page, page_size)
    )


@router.get("/remediations/{remediation_id}", response_model=RemediationOut, summary="Read a remediation")
def get_remediation(
    remediation_id: UUID, ctx: RequestContext = Depends(require_permission("defence:read"))
) -> RemediationOut:
    return RemediationOut.model_validate(_get_remediation(ctx, remediation_id))


@router.post(
    "/remediations/{remediation_id}/execute",
    response_model=RemediationOut,
    summary="Execute an approved remediation",
)
def execute_remediation(
    remediation_id: UUID, ctx: RequestContext = Depends(require_permission("defence:execute"))
) -> RemediationOut:
    remediation = _get_remediation(ctx, remediation_id)
    if remediation.status not in {"pending", "pending_approval", "proposed", "approved"}:
        raise Conflict(f"Remediation cannot be executed from status '{remediation.status}'")
    if remediation.authorization_id is not None:
        approval = ctx.db.get(Approval, remediation.authorization_id)
        if approval is None or approval.org_id != ctx.org.id:
            raise NotFound("Approval")
        if approval.expires_at and approval.expires_at < utcnow():
            raise Conflict("The approval for this remediation has expired")
        if approval.status != "approved":
            raise Conflict(f"The approval is '{approval.status}'; execution is blocked")
    try:
        execute_action(
            ctx.db,
            org=ctx.org,
            actor=_actor(ctx),
            action_type=remediation.action_type,
            target_type=remediation.target_type,
            target_id=remediation.target_id,
            parameters={key: value for key, value in remediation.parameters.items() if key != "_step_key"},
            incident_id=remediation.incident_id,
            approval_id=remediation.authorization_id,
            remediation=remediation,
        )
    except PolicyDenied as exc:
        remediation.status = "denied"
        ctx.db.commit()
        raise exc
    except ServiceUnavailable:
        ctx.db.commit()
        raise
    ctx.db.refresh(remediation)
    return RemediationOut.model_validate(remediation)


@router.post(
    "/remediations/{remediation_id}/rollback",
    response_model=RemediationOut,
    summary="Roll back a reversible remediation",
)
def rollback_remediation(
    remediation_id: UUID, ctx: RequestContext = Depends(require_permission("defence:execute"))
) -> RemediationOut:
    remediation = _get_remediation(ctx, remediation_id)
    rollback_type = rollback_action_for(remediation.action_type)
    if rollback_type is None:
        raise Conflict(f"Action '{remediation.action_type}' is not reversible by the platform")
    if remediation.status != "executed":
        raise Conflict("Only executed remediations can be rolled back")
    rollback_action(
        ctx.db,
        org=ctx.org,
        actor=_actor(ctx),
        remediation=remediation,
        rollback_action_type=rollback_type,
    )
    ctx.db.refresh(remediation)
    return RemediationOut.model_validate(remediation)


@router.post(
    "/remediations/{remediation_id}/verify",
    response_model=VerifyResult,
    summary="Re-check the recorded post-action verification",
)
def verify_remediation(
    remediation_id: UUID,
    payload: VerifyRequest,
    ctx: RequestContext = Depends(require_permission("defence:execute")),
) -> VerifyResult:
    remediation = _get_remediation(ctx, remediation_id)
    if remediation.status != "executed":
        raise Conflict("Only executed remediations can be verified")
    definition = ACTIONS.get(remediation.action_type)
    if definition is None or definition.capability is None:
        raise ValidationFailure([{"field": "action_type", "message": "This action has no connector verification"}])
    recorded = dict(remediation.verification or {})
    verified = bool(recorded.get("verified"))
    rechecked = False
    if payload.recheck:
        try:
            connector = select_connector(ctx.db, ctx.org.id, definition.capability)
            adapter = instantiate_adapter(connector)
            params = {key: value for key, value in remediation.parameters.items() if key != "_step_key"}
            check = adapter.verify(
                definition.capability,
                params,
                AdapterResult(ok=True, data=recorded),
            )
        except ConnectorError as exc:
            raise ServiceUnavailable("The connector could not verify the remediation") from exc
        rechecked = True
        verified = check.ok
        recorded["recheck"] = {
            "ok": check.ok,
            "data": check.data,
            "checked_at": utcnow().isoformat(),
            "connector_id": str(connector.id),
        }
        remediation.verification = recorded
        remediation.verified_at = utcnow() if check.ok else remediation.verified_at
        ctx.audit(
            action="defence.remediation.verify",
            resource_type="remediation",
            resource_id=str(remediation.id),
            outcome="success" if check.ok else "failure",
            payload={"connector_id": str(connector.id), "capability": definition.capability},
        )
        ctx.db.commit()
        ctx.db.refresh(remediation)
    return VerifyResult(
        remediation_id=remediation.id,
        recorded=recorded,
        verified=verified,
        rechecked=rechecked,
        checked_at=utcnow(),
    )


@router.get(
    "/kill-switches/effective",
    response_model=EffectiveKillSwitchesOut,
    summary="Effective global, organization, autonomy and connector kill switches",
)
def get_effective_kill_switches(
    ctx: RequestContext = Depends(require_permission("defence:read")),
) -> EffectiveKillSwitchesOut:
    return EffectiveKillSwitchesOut(**effective_kill_switches(ctx.db, ctx.org.id))


@router.get("/policy/snapshot", response_model=PolicySnapshotOut, summary="Active autonomy policy snapshot")
def policy_snapshot(
    ctx: RequestContext = Depends(require_permission("defence:read")),
) -> PolicySnapshotOut:
    snapshot = active_policy_snapshot(ctx.db, ctx.org.id)
    definition = snapshot.get("definition") or {}
    return PolicySnapshotOut(
        org_id=ctx.org.id,
        autonomy_level=ctx.org.autonomy_level,
        approval_threshold=str(definition.get("require_approval_from", "A3")),
        policy_id=snapshot.get("policy_id"),
        policy_version=snapshot.get("version"),
        definition=definition,
        evaluated_at=snapshot["evaluated_at"],
        kill_switches=EffectiveKillSwitchesOut(**effective_kill_switches(ctx.db, ctx.org.id)),
    )


__all__ = ["router"]
