"""Incident lifecycle primitives shared by the API and the SOAR engine.

The state machine is deliberately explicit: transitions outside the documented
``new -> triage -> investigating -> contained -> eradicated -> recovered ->
closed`` path are rejected with a 409. Closing additionally requires an
incident:close permission (enforced by the router), a root cause and lessons
learned, and every transition is appended to the append-only timeline.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.core.errors import Conflict, ValidationFailure
from app.models.assets import Asset
from app.models.core import Membership, Organization
from app.models.events import Alert
from app.models.incidents import Incident, IncidentTimeline

SEVERITIES = ("info", "low", "medium", "high", "critical")
_PRIORITY_BY_SEVERITY = {"info": 5, "low": 4, "medium": 3, "high": 2, "critical": 1}
_SLA_HOURS = {1: 4, 2: 8, 3: 24, 4: 72, 5: 168}

TRANSITIONS: dict[str, set[str]] = {
    "new": {"triage"},
    "triage": {"investigating"},
    "investigating": {"contained"},
    "contained": {"eradicated"},
    "eradicated": {"recovered"},
    "recovered": {"closed"},
    "closed": set(),
}

MIN_CLOSE_TEXT = 10
MAX_CLOSE_TEXT = 20000


def normalize_severity(value: str) -> str:
    """Accept the canonical labels and normalise legacy P1..P5 aliases."""
    lowered = (value or "").strip().lower()
    aliases = {"p1": "critical", "p2": "high", "p3": "medium", "p4": "low", "p5": "info"}
    lowered = aliases.get(lowered, lowered)
    if lowered not in SEVERITIES:
        raise ValidationFailure([{"field": "severity", "message": "Severity must be one of: " + ", ".join(SEVERITIES)}])
    return lowered


def severity_priority(severity: str) -> int:
    return _PRIORITY_BY_SEVERITY[severity]


def sla_due_for(priority: int, detected_at: datetime) -> datetime:
    return detected_at + timedelta(hours=_SLA_HOURS.get(priority, 24))


def generate_ref(db: Session, org_id: UUID) -> str:
    """Allocate the next ``HS-YYYY-NNNN`` reference for an organization.

    A per-organization/year advisory lock serialises allocation, and the loop
    also guards the global unique constraint on ``incidents.ref`` in case two
    tenants reach the same number.
    """
    year = utcnow().year
    prefix = f"HS-{year}-"
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
        {"key": f"incident_ref:{org_id}:{year}"},
    )
    highest = db.execute(
        select(func.max(Incident.ref)).where(Incident.org_id == org_id, Incident.ref.like(f"{prefix}%"))
    ).scalar_one_or_none()
    sequence = 0
    if highest:
        try:
            sequence = int(highest.rsplit("-", 1)[-1])
        except ValueError:
            sequence = 0
    for _ in range(10_000):
        sequence += 1
        if sequence > 9999:
            raise Conflict("The yearly incident reference space is exhausted")
        candidate = f"{prefix}{sequence:04d}"
        exists = db.execute(select(Incident.id).where(Incident.ref == candidate).limit(1)).scalar_one_or_none()
        if exists is None:
            return candidate
    raise Conflict("Unable to allocate a unique incident reference")


def add_timeline_entry(
    db: Session,
    incident: Incident,
    *,
    kind: str,
    summary: str,
    actor: str | None,
    detail: dict[str, Any] | None = None,
    at: datetime | None = None,
) -> IncidentTimeline:
    entry = IncidentTimeline(
        incident_id=incident.id,
        org_id=incident.org_id,
        at=at or utcnow(),
        kind=kind,
        actor=(actor or "")[:200] or None,
        summary=summary[:500],
        detail=detail or {},
    )
    db.add(entry)
    db.flush()
    return entry


def create_incident_core(
    db: Session,
    org: Organization,
    *,
    title: str,
    severity: str,
    description: str | None = None,
    priority: int | None = None,
    assignee_id: UUID | None = None,
    commander_id: UUID | None = None,
    detected_at: datetime | None = None,
    mitre: list[str] | None = None,
    affected_asset_ids: list[str] | None = None,
    sla_due_at: datetime | None = None,
    created_by: str | None = None,
    actor: str | None = None,
) -> Incident:
    severity = normalize_severity(severity)
    priority = priority or severity_priority(severity)
    detected = detected_at or utcnow()
    incident = Incident(
        org_id=org.id,
        ref=generate_ref(db, org.id),
        title=title.strip(),
        description=(description or "").strip() or None,
        severity=severity,
        status="new",
        priority=priority,
        assignee_id=assignee_id,
        commander_id=commander_id,
        detected_at=detected,
        sla_due_at=sla_due_at or sla_due_for(priority, detected),
        mitre=mitre or [],
        affected_asset_ids=affected_asset_ids or [],
        created_by=created_by,
    )
    db.add(incident)
    db.flush()
    add_timeline_entry(
        db,
        incident,
        kind="created",
        summary=f"Incident {incident.ref} created",
        actor=actor,
        detail={"severity": severity, "priority": priority, "title": incident.title},
        at=incident.created_at,
    )
    return incident


def validate_asset_ids(db: Session, org_id: UUID, asset_ids: list[str]) -> list[str]:
    """Ensure every referenced asset belongs to the caller's organization."""
    normalised: list[str] = []
    for value in asset_ids:
        try:
            asset_uuid = UUID(str(value))
        except (ValueError, TypeError) as exc:
            raise ValidationFailure([{"field": "affected_asset_ids", "message": f"Invalid asset id: {value}"}]) from exc
        normalised.append(str(asset_uuid))
    if not normalised:
        return []
    found = {
        str(row)
        for row in db.execute(
            select(Asset.id).where(Asset.org_id == org_id, Asset.id.in_([UUID(v) for v in normalised]))
        ).scalars()
    }
    missing = [value for value in normalised if value not in found]
    if missing:
        raise ValidationFailure(
            [{"field": "affected_asset_ids", "message": f"Unknown assets: {', '.join(missing[:5])}"}]
        )
    return normalised


def validate_assignee(db: Session, org_id: UUID, user_id: UUID | None, field: str) -> None:
    if user_id is None:
        return
    membership = db.execute(
        select(Membership).where(
            Membership.org_id == org_id,
            Membership.user_id == user_id,
            Membership.status == "active",
        )
    ).scalar_one_or_none()
    if membership is None:
        raise ValidationFailure([{"field": field, "message": "The user is not an active member of this organization"}])


def transition_incident(
    db: Session,
    incident: Incident,
    target: str,
    *,
    actor: str | None,
    root_cause: str | None = None,
    lessons_learned: str | None = None,
    note: str | None = None,
) -> Incident:
    """Apply a validated lifecycle transition and write the timeline entry."""
    if target not in TRANSITIONS:
        raise ValidationFailure([{"field": "status", "message": f"Unknown incident status: {target}"}])
    if target == incident.status:
        raise Conflict("The incident is already in this status")
    allowed = TRANSITIONS.get(incident.status, set())
    if target not in allowed:
        raise Conflict(
            f"Invalid status transition: {incident.status} -> {target}. Allowed: {', '.join(sorted(allowed)) or 'none'}"
        )

    if target == "closed":
        effective_root = (root_cause if root_cause is not None else incident.root_cause) or ""
        effective_lessons = (lessons_learned if lessons_learned is not None else incident.lessons_learned) or ""
        if len(effective_root.strip()) < MIN_CLOSE_TEXT:
            raise ValidationFailure(
                [
                    {
                        "field": "root_cause",
                        "message": f"A root cause of at least {MIN_CLOSE_TEXT} characters is required to close",
                    }
                ]
            )
        if len(effective_lessons.strip()) < MIN_CLOSE_TEXT:
            raise ValidationFailure(
                [
                    {
                        "field": "lessons_learned",
                        "message": f"Lessons learned of at least {MIN_CLOSE_TEXT} characters are required to close",
                    }
                ]
            )
        if len(effective_root) > MAX_CLOSE_TEXT or len(effective_lessons) > MAX_CLOSE_TEXT:
            raise ValidationFailure(
                [{"field": "root_cause", "message": f"Close-out fields are limited to {MAX_CLOSE_TEXT} characters"}]
            )
        incident.root_cause = effective_root.strip()
        incident.lessons_learned = effective_lessons.strip()

    previous = incident.status
    now = utcnow()
    incident.status = target
    if target == "contained":
        incident.contained_at = now
    elif target == "recovered":
        incident.resolved_at = now
    elif target == "closed":
        incident.closed_at = now

    add_timeline_entry(
        db,
        incident,
        kind="status_change",
        summary=f"Status changed from {previous} to {target}",
        actor=actor,
        detail={"from": previous, "to": target, "note": note},
        at=now,
    )
    db.flush()
    return incident


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 2) if values else None


def incident_metrics(db: Session, org_id: UUID) -> dict[str, Any]:
    """MTTD/MTTR and open workload computed from persisted records only."""
    incidents = list(db.execute(select(Incident).where(Incident.org_id == org_id)).scalars())

    detection_lags: list[float] = []
    resolution_times: list[float] = []
    for incident in incidents:
        first_alert = db.execute(
            select(func.min(Alert.first_seen)).where(Alert.org_id == org_id, Alert.incident_id == incident.id)
        ).scalar_one_or_none()
        baseline = first_alert or incident.created_at
        lag = (incident.detected_at - baseline).total_seconds()
        if lag >= 0:
            detection_lags.append(lag)
        if incident.closed_at is not None:
            resolution_times.append((incident.closed_at - incident.detected_at).total_seconds())
        elif incident.resolved_at is not None:
            resolution_times.append((incident.resolved_at - incident.detected_at).total_seconds())

    open_by_severity = dict.fromkeys(SEVERITIES, 0)
    for incident in incidents:
        if incident.status != "closed":
            open_by_severity[incident.severity] = open_by_severity.get(incident.severity, 0) + 1

    return {
        "open_total": sum(open_by_severity.values()),
        "open_by_severity": open_by_severity,
        "closed_total": sum(1 for incident in incidents if incident.status == "closed"),
        "total": len(incidents),
        "mttd_seconds": _mean(detection_lags),
        "mttr_seconds": _mean(resolution_times),
        "computed_at": utcnow(),
    }


def parse_uuid(value: str) -> UUID | None:
    try:
        return uuid.UUID(str(value))
    except (ValueError, TypeError):
        return None


__all__ = [
    "SEVERITIES",
    "TRANSITIONS",
    "add_timeline_entry",
    "create_incident_core",
    "generate_ref",
    "incident_metrics",
    "normalize_severity",
    "severity_priority",
    "sla_due_for",
    "transition_incident",
    "validate_asset_ids",
    "validate_assignee",
]
