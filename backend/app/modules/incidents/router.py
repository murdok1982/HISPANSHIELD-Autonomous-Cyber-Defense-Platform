"""Incident response API: lifecycle, timeline, evidence and metrics."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.core.deps import RequestContext, require_permission
from app.core.errors import Conflict, Forbidden, NotFound, ValidationFailure
from app.core.schemas import Page, paginate
from app.models.assets import Asset
from app.models.events import Alert
from app.models.incidents import Evidence, Incident, IncidentTimeline, Remediation
from app.modules.incidents.schemas import (
    AlertLink,
    AssetSummary,
    EvidenceOut,
    IncidentCreate,
    IncidentDetail,
    IncidentMetricsOut,
    IncidentOut,
    IncidentPatch,
    RemediationLink,
    StatusChange,
    TimelineCreate,
    TimelineOut,
)
from app.modules.incidents.service import (
    add_timeline_entry,
    create_incident_core,
    incident_metrics,
    normalize_severity,
    parse_uuid,
    transition_incident,
    validate_asset_ids,
    validate_assignee,
)
from app.services import forensic_evidence

router = APIRouter(prefix="/incidents", tags=["Incident Response"])

_SORT_COLUMNS = {
    "created_at": Incident.created_at,
    "updated_at": Incident.updated_at,
    "detected_at": Incident.detected_at,
    "severity": Incident.severity,
    "priority": Incident.priority,
    "status": Incident.status,
    "ref": Incident.ref,
}
_KIND_RE = re.compile(r"^[a-z][a-z0-9_.-]{1,39}$")


def _get_incident(db: Session, org_id: UUID, incident_id: UUID) -> Incident:
    incident = db.get(Incident, incident_id)
    if incident is None or incident.org_id != org_id:
        raise NotFound("Incident")
    return incident


def _get_evidence(db: Session, org_id: UUID, evidence_id: UUID) -> Evidence:
    record = db.get(Evidence, evidence_id)
    if record is None or record.org_id != org_id:
        raise NotFound("Evidence")
    return record


def _incident_detail(db: Session, incident: Incident) -> IncidentDetail:
    timeline = list(
        db.execute(
            select(IncidentTimeline)
            .where(IncidentTimeline.incident_id == incident.id, IncidentTimeline.org_id == incident.org_id)
            .order_by(IncidentTimeline.at.asc())
        ).scalars()
    )
    evidence = list(
        db.execute(
            select(Evidence)
            .where(Evidence.incident_id == incident.id, Evidence.org_id == incident.org_id)
            .order_by(Evidence.collected_at.desc())
        ).scalars()
    )
    alerts = list(
        db.execute(
            select(Alert)
            .where(Alert.incident_id == incident.id, Alert.org_id == incident.org_id)
            .order_by(Alert.last_seen.desc())
        ).scalars()
    )
    remediations = list(
        db.execute(
            select(Remediation)
            .where(Remediation.incident_id == incident.id, Remediation.org_id == incident.org_id)
            .order_by(Remediation.executed_at.desc().nulls_last(), Remediation.id.asc())
        ).scalars()
    )
    asset_uuids = [value for value in (parse_uuid(item) for item in incident.affected_asset_ids) if value]
    assets = (
        list(db.execute(select(Asset).where(Asset.org_id == incident.org_id, Asset.id.in_(asset_uuids))).scalars())
        if asset_uuids
        else []
    )
    base = IncidentOut.model_validate(incident)
    return IncidentDetail(
        **base.model_dump(),
        timeline=[TimelineOut.model_validate(row) for row in timeline],
        evidence=[EvidenceOut.model_validate(row) for row in evidence],
        alerts=[AlertLink.model_validate(row) for row in alerts],
        remediations=[RemediationLink.model_validate(row) for row in remediations],
        assets=[AssetSummary.model_validate(row) for row in assets],
    )


@router.get("/metrics", response_model=IncidentMetricsOut, summary="Incident MTTD/MTTR and open workload")
def get_metrics(ctx: RequestContext = Depends(require_permission("incident:read"))) -> IncidentMetricsOut:
    return IncidentMetricsOut(**incident_metrics(ctx.db, ctx.org.id))


@router.get("", response_model=Page[IncidentOut], summary="List incidents")
def list_incidents(
    ctx: RequestContext = Depends(require_permission("incident:read")),
    status: str | None = Query(
        default=None,
        pattern="^(new|triage|investigating|contained|eradicated|recovered|closed)$",
    ),
    severity: str | None = Query(default=None, pattern="^(info|low|medium|high|critical)$"),
    assignee: UUID | None = Query(default=None),
    incident_date_from: datetime | None = Query(default=None, alias="date_from"),
    incident_date_to: datetime | None = Query(default=None, alias="date_to"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    q: str | None = Query(default=None, max_length=200),
    sort: str = Query(default="created_at"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
) -> Page[IncidentOut]:
    if sort not in _SORT_COLUMNS:
        raise ValidationFailure([{"field": "sort", "message": f"Sort must be one of: {', '.join(_SORT_COLUMNS)}"}])
    stmt = select(Incident).where(Incident.org_id == ctx.org.id)
    if status:
        stmt = stmt.where(Incident.status == status)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    if assignee:
        stmt = stmt.where(Incident.assignee_id == assignee)
    if incident_date_from:
        stmt = stmt.where(Incident.detected_at >= incident_date_from)
    if incident_date_to:
        stmt = stmt.where(Incident.detected_at <= incident_date_to)
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Incident.ref).like(needle),
                func.lower(Incident.title).like(needle),
                func.lower(func.coalesce(Incident.description, "")).like(needle),
            )
        )
    column = _SORT_COLUMNS[sort]
    stmt = stmt.order_by(column.asc() if order == "asc" else column.desc(), Incident.id.asc())
    total = ctx.db.execute(select(func.count()).select_from(stmt.order_by(None).subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[IncidentOut](**paginate([IncidentOut.model_validate(row) for row in rows], total, page, page_size))


@router.post("", response_model=IncidentDetail, status_code=201, summary="Create an incident")
def create_incident(
    payload: IncidentCreate, ctx: RequestContext = Depends(require_permission("incident:write"))
) -> IncidentDetail:
    severity = normalize_severity(payload.severity)
    asset_ids = validate_asset_ids(ctx.db, ctx.org.id, payload.affected_asset_ids)
    validate_assignee(ctx.db, ctx.org.id, payload.assignee_id, "assignee_id")
    validate_assignee(ctx.db, ctx.org.id, payload.commander_id, "commander_id")
    incident = create_incident_core(
        ctx.db,
        ctx.org,
        title=payload.title,
        severity=severity,
        description=payload.description,
        priority=payload.priority,
        assignee_id=payload.assignee_id,
        commander_id=payload.commander_id,
        detected_at=payload.detected_at,
        mitre=payload.mitre,
        affected_asset_ids=asset_ids,
        sla_due_at=payload.sla_due_at,
        created_by=ctx.actor_id,
        actor=ctx.actor_email or ctx.actor_id,
    )
    ctx.audit(
        action="incident.create",
        resource_type="incident",
        resource_id=str(incident.id),
        payload={"ref": incident.ref, "severity": incident.severity, "title": incident.title},
    )
    ctx.db.commit()
    ctx.db.refresh(incident)
    return _incident_detail(ctx.db, incident)


@router.get("/{incident_id}", response_model=IncidentDetail, summary="Read an incident with related records")
def get_incident(
    incident_id: UUID, ctx: RequestContext = Depends(require_permission("incident:read"))
) -> IncidentDetail:
    incident = _get_incident(ctx.db, ctx.org.id, incident_id)
    return _incident_detail(ctx.db, incident)


@router.patch("/{incident_id}", response_model=IncidentDetail, summary="Update, triage, assign or re-severity")
def update_incident(
    incident_id: UUID,
    payload: IncidentPatch,
    ctx: RequestContext = Depends(require_permission("incident:write")),
) -> IncidentDetail:
    incident = _get_incident(ctx.db, ctx.org.id, incident_id)
    if incident.status == "closed":
        raise Conflict("Closed incidents are immutable; reopen is not supported by this endpoint")
    data = payload.model_dump(exclude_unset=True)
    timeline_notes: list[tuple[str, str, dict[str, Any]]] = []

    if "title" in data:
        if not data["title"]:
            raise ValidationFailure([{"field": "title", "message": "Title cannot be empty"}])
        incident.title = data["title"]
    if "description" in data:
        incident.description = data["description"]
    if "severity" in data and data["severity"] is not None:
        severity = normalize_severity(data["severity"])
        if severity != incident.severity:
            timeline_notes.append(
                ("severity_change", f"Severity changed from {incident.severity} to {severity}", {"to": severity})
            )
            incident.severity = severity
            if "priority" not in data:
                from app.modules.incidents.service import severity_priority

                incident.priority = severity_priority(severity)
    if "priority" in data and data["priority"] is not None:
        incident.priority = data["priority"]
    if "assignee_id" in data:
        validate_assignee(ctx.db, ctx.org.id, data["assignee_id"], "assignee_id")
        if data["assignee_id"] != incident.assignee_id:
            timeline_notes.append(
                (
                    "assignment",
                    "Assignee updated",
                    {"assignee_id": str(data["assignee_id"]) if data["assignee_id"] else None},
                )
            )
        incident.assignee_id = data["assignee_id"]
    if "commander_id" in data:
        validate_assignee(ctx.db, ctx.org.id, data["commander_id"], "commander_id")
        if data["commander_id"] != incident.commander_id:
            timeline_notes.append(
                (
                    "commander",
                    "Incident commander updated",
                    {"commander_id": str(data["commander_id"]) if data["commander_id"] else None},
                )
            )
        incident.commander_id = data["commander_id"]
    if "mitre" in data and data["mitre"] is not None:
        incident.mitre = data["mitre"]
    if "affected_asset_ids" in data and data["affected_asset_ids"] is not None:
        incident.affected_asset_ids = validate_asset_ids(ctx.db, ctx.org.id, data["affected_asset_ids"])
    if "detected_at" in data and data["detected_at"] is not None:
        incident.detected_at = data["detected_at"]
    if "sla_due_at" in data:
        incident.sla_due_at = data["sla_due_at"]
    if incident.sla_due_at is None:
        from app.modules.incidents.service import sla_due_for

        incident.sla_due_at = sla_due_for(incident.priority, incident.detected_at)

    for kind, summary, detail in timeline_notes:
        add_timeline_entry(
            ctx.db,
            incident,
            kind=kind,
            summary=summary,
            actor=ctx.actor_email or ctx.actor_id,
            detail=detail,
        )
    if timeline_notes or data:
        ctx.audit(
            action="incident.update",
            resource_type="incident",
            resource_id=str(incident.id),
            payload={"ref": incident.ref, "fields": sorted(data.keys())},
        )
    ctx.db.commit()
    ctx.db.refresh(incident)
    return _incident_detail(ctx.db, incident)


@router.post("/{incident_id}/status", response_model=IncidentDetail, summary="Apply a lifecycle transition")
def change_status(
    incident_id: UUID,
    payload: StatusChange,
    ctx: RequestContext = Depends(require_permission("incident:write")),
) -> IncidentDetail:
    incident = _get_incident(ctx.db, ctx.org.id, incident_id)
    if payload.status == "closed":
        ctx.require("incident:close")
    transition_incident(
        ctx.db,
        incident,
        payload.status,
        actor=ctx.actor_email or ctx.actor_id,
        root_cause=payload.root_cause,
        lessons_learned=payload.lessons_learned,
        note=payload.note,
    )
    ctx.audit(
        action="incident.status_change",
        resource_type="incident",
        resource_id=str(incident.id),
        payload={"ref": incident.ref, "status": incident.status},
    )
    ctx.db.commit()
    ctx.db.refresh(incident)
    return _incident_detail(ctx.db, incident)


@router.get("/{incident_id}/timeline", response_model=Page[TimelineOut], summary="Read the append-only timeline")
def get_timeline(
    incident_id: UUID,
    ctx: RequestContext = Depends(require_permission("incident:read")),
    kind: str | None = Query(default=None, max_length=30),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=100, ge=1, le=200),
) -> Page[TimelineOut]:
    incident = _get_incident(ctx.db, ctx.org.id, incident_id)
    stmt = select(IncidentTimeline).where(
        IncidentTimeline.incident_id == incident.id, IncidentTimeline.org_id == ctx.org.id
    )
    if kind:
        stmt = stmt.where(IncidentTimeline.kind == kind)
    stmt = stmt.order_by(IncidentTimeline.at.asc(), IncidentTimeline.id.asc())
    total = ctx.db.execute(select(func.count()).select_from(stmt.order_by(None).subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[TimelineOut](**paginate([TimelineOut.model_validate(row) for row in rows], total, page, page_size))


@router.post("/{incident_id}/timeline", response_model=TimelineOut, status_code=201, summary="Add a timeline note")
def add_timeline_note(
    incident_id: UUID,
    payload: TimelineCreate,
    ctx: RequestContext = Depends(require_permission("incident:write")),
) -> TimelineOut:
    incident = _get_incident(ctx.db, ctx.org.id, incident_id)
    entry = add_timeline_entry(
        ctx.db,
        incident,
        kind=payload.kind,
        summary=payload.summary,
        actor=ctx.actor_email or ctx.actor_id,
        detail=payload.detail,
    )
    ctx.audit(
        action="incident.timeline.add",
        resource_type="incident",
        resource_id=str(incident.id),
        payload={"kind": payload.kind, "entry_id": str(entry.id)},
    )
    ctx.db.commit()
    ctx.db.refresh(entry)
    return TimelineOut.model_validate(entry)


@router.post("/{incident_id}/evidence", response_model=EvidenceOut, status_code=201, summary="Upload evidence")
def upload_evidence(
    incident_id: UUID,
    file: Annotated[UploadFile, File(description="Evidence file (<=25MB)")],
    title: Annotated[str | None, Form(max_length=300)] = None,
    kind: Annotated[str | None, Form(max_length=40)] = None,
    description: Annotated[str | None, Form(max_length=20000)] = None,
    sealed: Annotated[bool, Form()] = False,
    ctx: RequestContext = Depends(require_permission("incident:write")),
) -> EvidenceOut:
    incident = _get_incident(ctx.db, ctx.org.id, incident_id)
    if kind is not None and not _KIND_RE.match(kind):
        raise ValidationFailure([{"field": "kind", "message": "Invalid evidence kind"}])
    display_title = (title or file.filename or "Evidence").strip()[:300]
    if not display_title:
        raise ValidationFailure([{"field": "title", "message": "Evidence title cannot be empty"}])

    stored = forensic_evidence.store_evidence_stream(
        file.file,
        original_filename=file.filename,
        org_id=ctx.org.id,
        incident_id=incident.id,
        max_bytes=forensic_evidence.MAX_EVIDENCE_BYTES,
    )
    now = utcnow()
    actor = ctx.actor_email or ctx.actor_id
    chain: list[dict[str, Any]] = [
        {
            "at": now.isoformat(),
            "action": "collected",
            "actor": actor,
            "sha256": stored.sha256,
            "size_bytes": stored.size_bytes,
            "content_type": stored.content_type,
            "source_filename": stored.safe_filename,
        }
    ]
    if sealed:
        chain.append({"at": now.isoformat(), "action": "sealed", "actor": actor, "sha256": stored.sha256})
    record = Evidence(
        org_id=ctx.org.id,
        incident_id=incident.id,
        kind=kind or stored.kind,
        title=display_title,
        description=(description or "").strip() or None,
        sha256=stored.sha256,
        storage_path=stored.storage_path,
        content_type=stored.content_type,
        size_bytes=stored.size_bytes,
        collected_by=(actor or "")[:120] or None,
        collected_at=now,
        chain_of_custody=chain,
        sealed=sealed,
    )
    ctx.db.add(record)
    ctx.db.flush()
    add_timeline_entry(
        ctx.db,
        incident,
        kind="evidence",
        summary=f"Evidence attached: {display_title}"[:500],
        actor=actor,
        detail={"evidence_id": str(record.id), "sha256": stored.sha256, "size_bytes": stored.size_bytes},
    )
    ctx.audit(
        action="incident.evidence.upload",
        resource_type="evidence",
        resource_id=str(record.id),
        payload={
            "incident_id": str(incident.id),
            "sha256": stored.sha256,
            "size_bytes": stored.size_bytes,
            "content_type": stored.content_type,
        },
    )
    ctx.db.commit()
    ctx.db.refresh(record)
    return EvidenceOut.model_validate(record)


@router.get("/evidence/{evidence_id}/download", summary="Download an evidence file")
def download_evidence(
    evidence_id: UUID, ctx: RequestContext = Depends(require_permission("incident:read"))
) -> FileResponse:
    # Reading evidence is restricted to responders/analysts (incident:write);
    # a viewer without it gets a 403 and a denial is written to the audit trail.
    if not ctx.can("incident:write"):
        ctx.audit(
            action="incident.evidence.download",
            resource_type="evidence",
            resource_id=str(evidence_id),
            outcome="failure",
            payload={"reason": "insufficient_role"},
        )
        ctx.db.commit()
        raise Forbidden("Evidence access requires a responder or analyst role")
    record = _get_evidence(ctx.db, ctx.org.id, evidence_id)
    try:
        path = forensic_evidence.resolve_storage_path(record.storage_path)
    except FileNotFoundError as exc:
        raise NotFound("Evidence file") from exc
    suffix = re.sub(r"[^a-z0-9.]", "", (record.storage_path.rsplit(".", 1)[-1] or "").lower())[:10]
    display_name = f"{forensic_evidence.sanitize_filename(record.title)}{f'.{suffix}' if suffix else ''}"
    ctx.audit(
        action="incident.evidence.download",
        resource_type="evidence",
        resource_id=str(record.id),
        payload={"incident_id": str(record.incident_id) if record.incident_id else None},
    )
    ctx.db.commit()
    return FileResponse(
        path,
        media_type=record.content_type,
        headers={
            "Content-Disposition": forensic_evidence.content_disposition(display_name),
            "X-Content-SHA256": record.sha256,
            "Cache-Control": "no-store",
        },
    )


@router.post("/evidence/{evidence_id}/seal", response_model=EvidenceOut, summary="Seal an evidence record")
def seal_evidence(
    evidence_id: UUID, ctx: RequestContext = Depends(require_permission("incident:write"))
) -> EvidenceOut:
    record = _get_evidence(ctx.db, ctx.org.id, evidence_id)
    if record.sealed:
        raise Conflict("The evidence record is already sealed")
    now = utcnow()
    actor = ctx.actor_email or ctx.actor_id
    chain = list(record.chain_of_custody or [])
    chain.append({"at": now.isoformat(), "action": "sealed", "actor": actor, "sha256": record.sha256})
    record.chain_of_custody = chain
    record.sealed = True
    ctx.audit(
        action="incident.evidence.seal",
        resource_type="evidence",
        resource_id=str(record.id),
        payload={"sha256": record.sha256},
    )
    ctx.db.commit()
    ctx.db.refresh(record)
    return EvidenceOut.model_validate(record)


__all__ = ["router"]
