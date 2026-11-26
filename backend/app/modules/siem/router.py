"""SIEM API: detection rules, Sigma import, rule testing, alerts and promotion."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, or_, select

from app.core.deps import RequestContext, require_any_permission, require_permission
from app.core.errors import ValidationFailure
from app.core.schemas import Page, paginate
from app.models.events import Alert, DetectionRule
from app.modules.siem import service
from app.modules.siem.schemas import (
    AlertBulkRequest,
    AlertBulkResponse,
    AlertDetail,
    AlertPatch,
    AlertSummary,
    IncidentSummary,
    PromoteRequest,
    PromoteResponse,
    RuleCreate,
    RuleOut,
    RulePatch,
    RuleTestRequest,
    SigmaImportRequest,
    SigmaImportResponse,
    SigmaImportSkipped,
    SigmaRule,
)

router = APIRouter(prefix="/siem", tags=["SIEM: Detection & Alerts"])

ALERT_SORT_COLUMNS = {
    "created_at": Alert.created_at,
    "last_seen": Alert.last_seen,
    "severity": Alert.severity,
    "risk_score": Alert.risk_score,
    "count": Alert.count,
}


def _rule_out(rule: DetectionRule) -> RuleOut:
    return RuleOut(**service.serialize_rule(rule))


def _is_platform_admin(ctx: RequestContext) -> bool:
    return bool(ctx.user and ctx.user.is_platform_admin)


def _like(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped.lower()}%"


def _rule_names(ctx: RequestContext, alerts: list[Alert]) -> dict[UUID, str]:
    rule_ids = {alert.rule_id for alert in alerts if alert.rule_id is not None}
    if not rule_ids:
        return {}
    rows = ctx.db.execute(select(DetectionRule.id, DetectionRule.name).where(DetectionRule.id.in_(rule_ids))).all()
    return {row[0]: row[1] for row in rows}


# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------


@router.get("/rules/templates", summary="Builtin detection rule templates")
def rules_templates(ctx: RequestContext = Depends(require_permission("alert:read"))) -> list[dict[str, Any]]:
    return service.rule_templates()


@router.post("/rules/import", response_model=SigmaImportResponse, summary="Import a Sigma rule subset")
def import_sigma_rules(
    payload: SigmaRule | SigmaImportRequest,
    ctx: RequestContext = Depends(require_permission("alert:write")),
) -> SigmaImportResponse:
    rules = [payload] if isinstance(payload, SigmaRule) else payload.rules
    imported, skipped = service.import_sigma(
        ctx.db,
        org_id=ctx.org.id,
        actor_id=ctx.actor_id,
        rules=rules,
    )
    ctx.audit(
        action="detection_rule.import",
        resource_type="detection_rule",
        payload={
            "imported": len(imported),
            "skipped": len(skipped),
            "names": [rule.name for rule in imported][:20],
        },
    )
    ctx.db.commit()
    return SigmaImportResponse(
        imported=[_rule_out(rule) for rule in imported],
        skipped=[SigmaImportSkipped(**item) for item in skipped],
    )


@router.get("/rules", response_model=Page[RuleOut], summary="List organization and global detection rules")
def list_rules(
    ctx: RequestContext = Depends(require_permission("alert:read")),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    scope: str = Query(default="all", pattern="^(all|organization|global)$"),
    enabled: bool | None = Query(default=None),
    q: str | None = Query(default=None, max_length=120),
) -> Page[RuleOut]:
    if scope == "organization":
        stmt = select(DetectionRule).where(DetectionRule.org_id == ctx.org.id)
    elif scope == "global":
        stmt = select(DetectionRule).where(DetectionRule.org_id.is_(None))
    else:
        stmt = select(DetectionRule).where(or_(DetectionRule.org_id == ctx.org.id, DetectionRule.org_id.is_(None)))
    if enabled is not None:
        stmt = stmt.where(DetectionRule.enabled.is_(enabled))
    if q:
        stmt = stmt.where(func.lower(DetectionRule.name).like(_like(q), escape="\\"))
    stmt = stmt.order_by(DetectionRule.updated_at.desc(), DetectionRule.name.asc())
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[RuleOut](**paginate([_rule_out(rule) for rule in rows], total, page, page_size))


@router.post("/rules", response_model=RuleOut, status_code=201, summary="Create a detection rule")
def create_rule(payload: RuleCreate, ctx: RequestContext = Depends(require_permission("alert:write"))) -> RuleOut:
    rule = service.create_rule(
        ctx.db,
        org_id=ctx.org.id,
        actor_id=ctx.actor_id,
        payload=payload,
        is_platform_admin=_is_platform_admin(ctx),
    )
    ctx.audit(
        action="detection_rule.create",
        resource_type="detection_rule",
        resource_id=str(rule.id),
        payload={"name": rule.name, "severity": rule.severity, "scope": "global" if rule.org_id is None else "org"},
        org_id=None if rule.org_id is None else ctx.org.id,
    )
    ctx.db.commit()
    return _rule_out(rule)


@router.get("/rules/{rule_id}", response_model=RuleOut, summary="Read a detection rule")
def get_rule(rule_id: UUID, ctx: RequestContext = Depends(require_permission("alert:read"))) -> RuleOut:
    return _rule_out(service.rule_or_404(ctx.db, ctx.org.id, rule_id))


@router.patch("/rules/{rule_id}", response_model=RuleOut, summary="Update a detection rule (versioned)")
def update_rule(
    rule_id: UUID,
    payload: RulePatch,
    ctx: RequestContext = Depends(require_permission("alert:write")),
) -> RuleOut:
    rule = service.rule_or_404(ctx.db, ctx.org.id, rule_id)
    previous_version = rule.version
    service.update_rule(ctx.db, rule=rule, payload=payload, is_platform_admin=_is_platform_admin(ctx))
    ctx.audit(
        action="detection_rule.update",
        resource_type="detection_rule",
        resource_id=str(rule.id),
        payload={
            "fields": sorted(payload.model_fields_set),
            "previous_version": previous_version,
            "version": rule.version,
        },
        org_id=None if rule.org_id is None else ctx.org.id,
    )
    ctx.db.commit()
    ctx.db.refresh(rule)
    return _rule_out(rule)


@router.delete(
    "/rules/{rule_id}",
    status_code=204,
    response_class=Response,
    summary="Delete a detection rule",
)
def delete_rule(rule_id: UUID, ctx: RequestContext = Depends(require_permission("alert:write"))) -> Response:
    rule = service.rule_or_404(ctx.db, ctx.org.id, rule_id)
    ctx.audit(
        action="detection_rule.delete",
        resource_type="detection_rule",
        resource_id=str(rule.id),
        payload={"name": rule.name, "scope": "global" if rule.org_id is None else "org"},
        org_id=None if rule.org_id is None else ctx.org.id,
    )
    service.delete_rule(ctx.db, rule=rule, is_platform_admin=_is_platform_admin(ctx))
    ctx.db.commit()
    return Response(status_code=204)


@router.post("/rules/{rule_id}/enable", response_model=RuleOut, summary="Enable a detection rule")
def enable_rule(rule_id: UUID, ctx: RequestContext = Depends(require_permission("alert:write"))) -> RuleOut:
    rule = service.rule_or_404(ctx.db, ctx.org.id, rule_id)
    service.set_rule_enabled(ctx.db, rule=rule, enabled=True, is_platform_admin=_is_platform_admin(ctx))
    ctx.audit(
        action="detection_rule.enable",
        resource_type="detection_rule",
        resource_id=str(rule.id),
        org_id=None if rule.org_id is None else ctx.org.id,
    )
    ctx.db.commit()
    return _rule_out(rule)


@router.post("/rules/{rule_id}/disable", response_model=RuleOut, summary="Disable a detection rule")
def disable_rule(rule_id: UUID, ctx: RequestContext = Depends(require_permission("alert:write"))) -> RuleOut:
    rule = service.rule_or_404(ctx.db, ctx.org.id, rule_id)
    service.set_rule_enabled(ctx.db, rule=rule, enabled=False, is_platform_admin=_is_platform_admin(ctx))
    ctx.audit(
        action="detection_rule.disable",
        resource_type="detection_rule",
        resource_id=str(rule.id),
        org_id=None if rule.org_id is None else ctx.org.id,
    )
    ctx.db.commit()
    return _rule_out(rule)


@router.post("/rules/{rule_id}/test", summary="Evaluate a rule against sample or stored events")
def test_rule(
    rule_id: UUID,
    payload: RuleTestRequest,
    ctx: RequestContext = Depends(require_permission("alert:read")),
) -> dict[str, Any]:
    rule = service.rule_or_404(ctx.db, ctx.org.id, rule_id)
    return service.test_rule(
        ctx.db,
        org_id=ctx.org.id,
        rule=rule,
        samples=payload.events,
        event_ids=payload.event_ids,
        apply_threshold=payload.apply_threshold,
    )


# ---------------------------------------------------------------------------
# MITRE coverage
# ---------------------------------------------------------------------------


@router.get("/mitre/coverage", summary="MITRE ATT&CK technique coverage from alerts and events")
def mitre_coverage(
    ctx: RequestContext = Depends(require_any_permission("event:read", "alert:read")),
) -> dict[str, Any]:
    return service.mitre_coverage(ctx.db, ctx.org.id)


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


@router.get("/alerts/stats", summary="Alert statistics and 24h volume")
def alert_stats(
    ctx: RequestContext = Depends(require_permission("alert:read")),
    hours: int = Query(default=24, ge=1, le=168),
) -> dict[str, Any]:
    return service.alert_stats(ctx.db, ctx.org.id, hours=hours)


@router.post("/alerts/bulk", response_model=AlertBulkResponse, summary="Bulk triage up to 100 alerts")
def bulk_alerts(
    payload: AlertBulkRequest,
    ctx: RequestContext = Depends(require_permission("alert:write")),
) -> AlertBulkResponse:
    updated, skipped, ids = service.bulk_update_alerts(
        ctx.db,
        org_id=ctx.org.id,
        ids=payload.ids,
        status=payload.status,
        assignee_id=payload.assignee_id,
        assignee_set="assignee_id" in payload.model_fields_set,
        note=payload.note,
        actor=ctx.actor_email or ctx.actor_id,
    )
    ctx.audit(
        action="alert.bulk_update",
        resource_type="alert",
        payload={
            "updated": updated,
            "skipped": skipped,
            "status": payload.status,
            "has_note": bool(payload.note),
        },
    )
    ctx.db.commit()
    return AlertBulkResponse(updated=updated, skipped=skipped, ids=ids)


@router.get("/alerts", response_model=Page[AlertSummary], summary="List and filter alerts")
def list_alerts(
    ctx: RequestContext = Depends(require_permission("alert:read")),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    status: str | None = Query(default=None, pattern="^(new|triaged|investigating|closed|benign)$"),
    severity: str | None = Query(default=None, pattern="^(informational|low|medium|high|critical)$"),
    rule_id: UUID | None = Query(default=None),
    assignee_id: UUID | None = Query(default=None),
    incident_id: UUID | None = Query(default=None),
    created_from: datetime | None = Query(default=None),
    created_to: datetime | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    sort: str = Query(default="created_at"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
) -> Page[AlertSummary]:
    from datetime import UTC

    def ensure(value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)

    start, end = ensure(created_from), ensure(created_to)
    if start and end and start > end:
        raise ValidationFailure([{"field": "created_from", "message": "created_from must be before created_to"}])
    stmt = select(Alert).where(Alert.org_id == ctx.org.id)
    if status:
        stmt = stmt.where(Alert.status == status)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if rule_id is not None:
        service.rule_or_404(ctx.db, ctx.org.id, rule_id)
        stmt = stmt.where(Alert.rule_id == rule_id)
    if assignee_id is not None:
        stmt = stmt.where(Alert.assignee_id == assignee_id)
    if incident_id is not None:
        stmt = stmt.where(Alert.incident_id == incident_id)
    if start:
        stmt = stmt.where(Alert.created_at >= start)
    if end:
        stmt = stmt.where(Alert.created_at <= end)
    if q:
        stmt = stmt.where(func.lower(Alert.title).like(_like(q), escape="\\"))
    column = ALERT_SORT_COLUMNS.get(sort)
    if column is None:
        raise ValidationFailure([{"field": "sort", "message": f"Unsupported sort column: {sort}"}])
    stmt = stmt.order_by(column.asc() if order == "asc" else column.desc(), Alert.id.desc())
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    names = _rule_names(ctx, rows)
    items = [
        AlertSummary(**service.serialize_alert(alert, rule_name=names.get(alert.rule_id) if alert.rule_id else None))
        for alert in rows
    ]
    return Page[AlertSummary](**paginate(items, total, page, page_size))


@router.get("/alerts/{alert_id}", response_model=AlertDetail, summary="Read an alert with evidence")
def get_alert(alert_id: UUID, ctx: RequestContext = Depends(require_permission("alert:read"))) -> AlertDetail:
    alert = service.alert_or_404(ctx.db, ctx.org.id, alert_id)
    rule = ctx.db.get(DetectionRule, alert.rule_id) if alert.rule_id else None
    return AlertDetail(**service.serialize_alert(alert, rule_name=rule.name if rule else None, detail=True))


@router.patch("/alerts/{alert_id}", response_model=AlertDetail, summary="Triage an alert")
def triage_alert(
    alert_id: UUID,
    payload: AlertPatch,
    ctx: RequestContext = Depends(require_permission("alert:write")),
) -> AlertDetail:
    alert = service.alert_or_404(ctx.db, ctx.org.id, alert_id)
    previous_status = alert.status
    service.triage_alert(
        ctx.db,
        alert=alert,
        status=payload.status,
        assignee_id=payload.assignee_id,
        assignee_set="assignee_id" in payload.model_fields_set,
        note=payload.note,
        actor=ctx.actor_email or ctx.actor_id,
    )
    ctx.audit(
        action="alert.triage",
        resource_type="alert",
        resource_id=str(alert.id),
        payload={
            "previous_status": previous_status,
            "status": alert.status,
            "assignee_id": str(alert.assignee_id) if alert.assignee_id else None,
            "has_note": bool(payload.note),
        },
    )
    ctx.db.commit()
    ctx.db.refresh(alert)
    rule = ctx.db.get(DetectionRule, alert.rule_id) if alert.rule_id else None
    return AlertDetail(**service.serialize_alert(alert, rule_name=rule.name if rule else None, detail=True))


@router.post(
    "/alerts/{alert_id}/promote",
    response_model=PromoteResponse,
    status_code=201,
    summary="Promote an alert to an incident",
)
def promote_alert(
    alert_id: UUID,
    payload: PromoteRequest,
    ctx: RequestContext = Depends(require_permission("incident:write")),
) -> PromoteResponse:
    alert = service.alert_or_404(ctx.db, ctx.org.id, alert_id)
    incident = service.promote_alert(ctx, alert, payload.title, payload.description)
    ctx.audit(
        action="alert.promote",
        resource_type="alert",
        resource_id=str(alert.id),
        payload={
            "incident_id": str(incident.id),
            "incident_ref": incident.ref,
            "severity": incident.severity,
        },
    )
    ctx.db.commit()
    ctx.db.refresh(incident)
    return PromoteResponse(
        incident=IncidentSummary(
            id=incident.id,
            ref=incident.ref,
            title=incident.title,
            severity=incident.severity,
            status=incident.status,
            priority=incident.priority,
            detected_at=incident.detected_at,
        ),
        alert_id=alert.id,
        incident_id=incident.id,
    )


__all__ = ["router"]
