"""Executive and SOC overview aggregates plus global search."""

from __future__ import annotations

from datetime import UTC, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select

from app.core.db import utcnow
from app.core.deps import RequestContext, get_context, require_permission
from app.core.errors import ValidationFailure
from app.models.assets import Asset, Vulnerability
from app.models.connectors import Connector
from app.models.core import KillSwitch
from app.models.events import Alert, SecurityEvent
from app.models.incidents import Incident
from app.models.ti import ThreatIndicator

router = APIRouter(prefix="/overview", tags=["SOC Overview"])


def _counts_by(db, model, column, org_id, extra=None):  # type: ignore[no-untyped-def]
    stmt = select(column, func.count()).where(model.org_id == org_id).group_by(column)
    if extra is not None:
        stmt = stmt.where(extra)
    return {str(key): int(value) for key, value in db.execute(stmt).all()}


def _risk_score(
    *,
    critical_incidents: int,
    high_incidents: int,
    critical_vulns: int,
    kev_vulns: int,
    exposed_findings: int,
    unhealthy_connectors: int,
    kill_switch: bool,
) -> tuple[int, list[dict[str, Any]]]:
    components = [
        ("critical_incidents", min(35, critical_incidents * 12)),
        ("high_incidents", min(20, high_incidents * 5)),
        ("critical_vulnerabilities", min(15, critical_vulns * 2)),
        ("known_exploited_vulnerabilities", min(15, kev_vulns * 3)),
        ("exposed_attack_surface", min(10, exposed_findings * 2)),
        ("degraded_connectors", min(10, unhealthy_connectors * 2)),
        ("kill_switch_engaged", 5 if kill_switch else 0),
    ]
    score = min(100, sum(value for _, value in components))
    return score, [{"factor": name, "points": value} for name, value in components if value]


def _series(db, model, timestamp_column, org_id, hours: int, granularity: str = "hour") -> list[dict[str, Any]]:
    since = utcnow() - timedelta(hours=hours)
    bucket = func.date_trunc(granularity, timestamp_column)
    rows = db.execute(
        select(bucket, func.count())
        .where(model.org_id == org_id, timestamp_column >= since)
        .group_by(bucket)
        .order_by(bucket)
    ).all()
    by_bucket = {row[0].astimezone(UTC).isoformat(): int(row[1]) for row in rows}
    series: list[dict[str, Any]] = []
    cursor = since.replace(minute=0, second=0, microsecond=0)
    if granularity == "day":
        cursor = cursor.replace(hour=0)
    step = timedelta(days=1) if granularity == "day" else timedelta(hours=1)
    while cursor <= utcnow():
        key = cursor.isoformat()
        series.append({"timestamp": key, "value": by_bucket.get(key, 0)})
        cursor += step
    return series


@router.get("/executive", summary="Executive risk overview")
def executive_overview(ctx: RequestContext = Depends(require_permission("org:read"))) -> dict[str, Any]:
    org_id = ctx.org.id
    db = ctx.db

    asset_counts = _counts_by(db, Asset, Asset.kind, org_id)
    alert_severity = _counts_by(
        db, Alert, Alert.severity, org_id, Alert.status.in_(["new", "triaged", "investigating"])
    )
    incident_severity = _counts_by(
        db, Incident, Incident.severity, org_id, Incident.status.notin_(["closed", "recovered"])
    )
    vuln_severity = _counts_by(db, Vulnerability, Vulnerability.severity, org_id, Vulnerability.status == "open")
    connector_status = _counts_by(db, Connector, Connector.status, org_id)

    events_24h = db.execute(
        select(func.count())
        .select_from(SecurityEvent)
        .where(SecurityEvent.org_id == org_id, SecurityEvent.occurred_at >= utcnow() - timedelta(hours=24))
    ).scalar_one()
    indicators_active = db.execute(
        select(func.count())
        .select_from(ThreatIndicator)
        .where(
            or_(ThreatIndicator.org_id == org_id, ThreatIndicator.org_id.is_(None)), ThreatIndicator.active.is_(True)
        )
    ).scalar_one()
    kev_vulns = db.execute(
        select(func.count())
        .select_from(Vulnerability)
        .where(Vulnerability.org_id == org_id, Vulnerability.kev.is_(True), Vulnerability.status == "open")
    ).scalar_one()
    kill_switch = (
        db.execute(
            select(func.count())
            .select_from(KillSwitch)
            .where(KillSwitch.engaged.is_(True), or_(KillSwitch.org_id == org_id, KillSwitch.org_id.is_(None)))
        ).scalar_one()
        > 0
    )
    unhealthy = sum(value for key, value in connector_status.items() if key in {"degraded", "unhealthy"})

    risk_score, risk_factors = _risk_score(
        critical_incidents=incident_severity.get("critical", 0),
        high_incidents=incident_severity.get("high", 0),
        critical_vulns=vuln_severity.get("critical", 0),
        kev_vulns=int(kev_vulns),
        exposed_findings=asset_counts.get("service", 0),
        unhealthy_connectors=unhealthy,
        kill_switch=kill_switch,
    )

    recent_incidents = list(
        db.execute(
            select(Incident).where(Incident.org_id == org_id).order_by(Incident.detected_at.desc()).limit(6)
        ).scalars()
    )
    top_assets = list(
        db.execute(
            select(Asset, func.count(Vulnerability.id).label("vuln_count"))
            .join(Vulnerability, Vulnerability.asset_id == Asset.id)
            .where(Asset.org_id == org_id, Vulnerability.status == "open")
            .group_by(Asset.id)
            .order_by(func.count(Vulnerability.id).desc())
            .limit(5)
        ).all()
    )
    connectors = list(
        db.execute(select(Connector).where(Connector.org_id == org_id).order_by(Connector.name).limit(12)).scalars()
    )

    resolved = list(
        db.execute(
            select(Incident.detected_at, Incident.resolved_at).where(
                Incident.org_id == org_id, Incident.resolved_at.isnot(None)
            )
        ).all()
    )
    mttr_minutes = (
        sum((resolved_at - detected_at).total_seconds() / 60 for detected_at, resolved_at in resolved) / len(resolved)
        if resolved
        else None
    )

    return {
        "generated_at": utcnow().isoformat(),
        "organization": {"id": str(ctx.org.id), "name": ctx.org.name, "autonomy_level": ctx.org.autonomy_level},
        "risk": {
            "score": risk_score,
            "level": "critical"
            if risk_score >= 75
            else "high"
            if risk_score >= 50
            else "medium"
            if risk_score >= 25
            else "low",
            "factors": risk_factors,
        },
        "totals": {
            "assets": sum(asset_counts.values()),
            "assets_by_kind": asset_counts,
            "open_alerts": sum(alert_severity.values()),
            "open_alerts_by_severity": alert_severity,
            "open_incidents": sum(incident_severity.values()),
            "open_incidents_by_severity": incident_severity,
            "open_vulnerabilities": sum(vuln_severity.values()),
            "open_vulnerabilities_by_severity": vuln_severity,
            "known_exploited": int(kev_vulns),
            "events_24h": int(events_24h),
            "active_indicators": int(indicators_active),
            "connectors": connector_status,
            "kill_switch_engaged": kill_switch,
        },
        "mttr_minutes": round(mttr_minutes, 1) if mttr_minutes is not None else None,
        "trends": {
            "events_24h": _series(db, SecurityEvent, SecurityEvent.occurred_at, org_id, 24),
            "alerts_7d": _series(db, Alert, Alert.created_at, org_id, 168, "day"),
            "incidents_7d": _series(db, Incident, Incident.detected_at, org_id, 168, "day"),
        },
        "recent_incidents": [
            {
                "id": str(item.id),
                "ref": item.ref,
                "title": item.title,
                "severity": item.severity,
                "status": item.status,
                "detected_at": item.detected_at,
            }
            for item in recent_incidents
        ],
        "top_vulnerable_assets": [
            {
                "id": str(asset.id),
                "name": asset.name,
                "kind": asset.kind,
                "criticality": asset.criticality,
                "open_vulnerabilities": int(count),
            }
            for asset, count in top_assets
        ],
        "connectors": [
            {
                "id": str(item.id),
                "name": item.name,
                "type": item.connector_type,
                "status": item.status,
                "last_health_at": item.last_health_at,
            }
            for item in connectors
        ],
        "data_classification": "demo" if ctx.org.is_demo else "operational",
    }


@router.get("/soc", summary="SOC command center snapshot")
def soc_overview(ctx: RequestContext = Depends(require_permission("event:read"))) -> dict[str, Any]:
    org_id = ctx.org.id
    db = ctx.db
    since = utcnow() - timedelta(hours=1)
    recent_events = list(
        db.execute(
            select(SecurityEvent)
            .where(SecurityEvent.org_id == org_id)
            .order_by(SecurityEvent.occurred_at.desc())
            .limit(25)
        ).scalars()
    )
    new_alerts = list(
        db.execute(
            select(Alert)
            .where(Alert.org_id == org_id, Alert.status == "new")
            .order_by(Alert.created_at.desc())
            .limit(20)
        ).scalars()
    )
    active_incidents = list(
        db.execute(
            select(Incident)
            .where(Incident.org_id == org_id, Incident.status.notin_(["closed", "recovered"]))
            .order_by(Incident.severity.desc(), Incident.detected_at.desc())
            .limit(12)
        ).scalars()
    )
    event_rate = db.execute(
        select(func.count())
        .select_from(SecurityEvent)
        .where(SecurityEvent.org_id == org_id, SecurityEvent.occurred_at >= since)
    ).scalar_one()
    return {
        "generated_at": utcnow().isoformat(),
        "events_last_hour": int(event_rate),
        "events_per_minute": round(int(event_rate) / 60, 2),
        "recent_events": [
            {
                "id": event.id,
                "event_uid": event.event_uid,
                "occurred_at": event.occurred_at,
                "severity_id": event.severity_id,
                "class_uid": event.class_uid,
                "class_name": event.class_name,
                "message": event.message,
                "src_ip": event.src_ip,
                "dst_ip": event.dst_ip,
                "host_name": event.host_name,
                "user_name": event.user_name,
                "source_connector": event.source_connector,
                "mitre_techniques": event.mitre_techniques,
                "ioc_matches": event.ioc_matches,
                "raw": event.raw,
                "normalized": event.normalized,
                "raw_format": event.raw_format,
            }
            for event in recent_events
        ],
        "new_alerts": [
            {
                "id": str(alert.id),
                "title": alert.title,
                "severity": alert.severity,
                "status": alert.status,
                "count": alert.count,
                "last_seen": alert.last_seen,
                "mitre": alert.mitre,
                "risk_score": alert.risk_score,
            }
            for alert in new_alerts
        ],
        "data_classification": "demo" if ctx.org.is_demo else "operational",
        "active_incidents": [
            {
                "id": str(incident.id),
                "ref": incident.ref,
                "title": incident.title,
                "severity": incident.severity,
                "status": incident.status,
                "detected_at": incident.detected_at,
                "assignee_id": str(incident.assignee_id) if incident.assignee_id else None,
            }
            for incident in active_incidents
        ],
    }


@router.get("/search", summary="Global search across SOC entities")
def global_search(
    q: str = Query(min_length=2, max_length=120),
    ctx: RequestContext = Depends(get_context),
) -> dict[str, Any]:
    needle = f"%{q.lower()}%"
    org_id = ctx.org.id
    results: list[dict[str, Any]] = []

    if ctx.can("incident:read"):
        for incident in ctx.db.execute(
            select(Incident)
            .where(
                Incident.org_id == org_id,
                or_(func.lower(Incident.title).like(needle), func.lower(Incident.ref).like(needle)),
            )
            .limit(5)
        ).scalars():
            results.append(
                {
                    "type": "incident",
                    "id": str(incident.id),
                    "title": incident.title,
                    "subtitle": incident.ref,
                    "severity": incident.severity,
                }
            )
    if ctx.can("asset:read"):
        for asset in ctx.db.execute(
            select(Asset)
            .where(
                Asset.org_id == org_id,
                or_(func.lower(Asset.name).like(needle), func.lower(Asset.asset_key).like(needle)),
            )
            .limit(5)
        ).scalars():
            results.append(
                {
                    "type": "asset",
                    "id": str(asset.id),
                    "title": asset.name,
                    "subtitle": f"{asset.kind} · {asset.asset_key}",
                    "severity": None,
                }
            )
    if ctx.can("ti:read"):
        for indicator in ctx.db.execute(
            select(ThreatIndicator)
            .where(ThreatIndicator.org_id == org_id, func.lower(ThreatIndicator.value).like(needle))
            .limit(5)
        ).scalars():
            results.append(
                {
                    "type": "indicator",
                    "id": str(indicator.id),
                    "title": indicator.value,
                    "subtitle": indicator.indicator_type,
                    "severity": indicator.severity,
                }
            )
    if ctx.can("alert:read"):
        for alert in ctx.db.execute(
            select(Alert).where(Alert.org_id == org_id, func.lower(Alert.title).like(needle)).limit(5)
        ).scalars():
            results.append(
                {
                    "type": "alert",
                    "id": str(alert.id),
                    "title": alert.title,
                    "subtitle": alert.status,
                    "severity": alert.severity,
                }
            )
    if ctx.can("connector:read"):
        for connector in ctx.db.execute(
            select(Connector).where(Connector.org_id == org_id, func.lower(Connector.name).like(needle)).limit(5)
        ).scalars():
            results.append(
                {
                    "type": "connector",
                    "id": str(connector.id),
                    "title": connector.name,
                    "subtitle": connector.connector_type,
                    "severity": None,
                }
            )

    return {"query": q, "count": len(results), "results": results[:25]}


@router.get("/notifications", summary="Recent in-app notifications")
def notifications(ctx: RequestContext = Depends(require_permission("org:read"))) -> list[dict[str, Any]]:
    from app.models.core import Notification

    rows = ctx.db.execute(
        select(Notification)
        .where(
            Notification.org_id == ctx.org.id,
            or_(Notification.user_id.is_(None), Notification.user_id == (ctx.user.id if ctx.user else None)),
        )
        .order_by(Notification.created_at.desc())
        .limit(30)
    ).scalars()
    return [
        {
            "id": str(item.id),
            "kind": item.kind,
            "title": item.title,
            "body": item.body,
            "resource_type": item.resource_type,
            "resource_id": item.resource_id,
            "read_at": item.read_at,
            "created_at": item.created_at,
        }
        for item in rows
    ]


@router.post("/notifications/{notification_id}/read", summary="Mark a notification as read")
def mark_notification_read(
    notification_id: str, ctx: RequestContext = Depends(require_permission("org:read"))
) -> dict[str, Any]:
    from uuid import UUID

    from app.core.errors import NotFound
    from app.models.core import Notification

    try:
        parsed = UUID(notification_id)
    except ValueError as exc:
        raise ValidationFailure([{"field": "notification_id", "message": "Invalid identifier"}]) from exc
    item = ctx.db.get(Notification, parsed)
    if item is None or item.org_id != ctx.org.id:
        raise NotFound("Notification")
    item.read_at = utcnow()
    ctx.db.commit()
    return {"id": str(item.id), "read_at": item.read_at}
