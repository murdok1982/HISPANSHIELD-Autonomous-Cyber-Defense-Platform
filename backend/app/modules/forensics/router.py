"""Digital forensics API: cases, evidence integrity, custody and bounded export."""

from __future__ import annotations

import csv
import io
import json
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from fastapi.responses import StreamingResponse
from sqlalchemy import func, or_, select

from app.core.db import utcnow
from app.core.deps import RequestContext, require_permission
from app.core.schemas import Page, paginate
from app.models.events import Alert
from app.models.incidents import Evidence, Incident, IncidentTimeline
from app.modules.forensics import service
from app.modules.forensics.schemas import (
    CaseAlertOut,
    CaseDetailOut,
    CaseOut,
    ChainOfCustodyOut,
    EvidenceOut,
    HashVerificationOut,
    TimelineEntryOut,
)

router = APIRouter(prefix="/forensics", tags=["Forensics"])

CSV_COLUMNS = ("at", "kind", "actor", "summary", "detail")


# --------------------------------------------------------------------------- #
# Cases
# --------------------------------------------------------------------------- #
@router.get("/cases", response_model=Page[CaseOut], summary="List incident cases with evidence counts")
def list_cases(
    ctx: RequestContext = Depends(require_permission("incident:read")),
    status: str | None = Query(default=None, max_length=30),
    severity: str | None = Query(default=None, pattern="^(low|medium|high|critical)$"),
    q: str | None = Query(default=None, max_length=200),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
) -> Page[CaseOut]:
    evidence_count = (
        select(func.count(Evidence.id)).where(Evidence.incident_id == Incident.id).correlate(Incident).scalar_subquery()
    )
    alert_count = (
        select(func.count(Alert.id)).where(Alert.incident_id == Incident.id).correlate(Incident).scalar_subquery()
    )
    stmt = (
        select(Incident, evidence_count.label("evidence_count"), alert_count.label("alert_count"))
        .where(Incident.org_id == ctx.org.id)
        .order_by(Incident.detected_at.desc())
    )
    if status:
        stmt = stmt.where(Incident.status == status)
    if severity:
        stmt = stmt.where(Incident.severity == severity)
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Incident.ref).like(needle),
                func.lower(Incident.title).like(needle),
                func.lower(func.coalesce(Incident.description, "")).like(needle),
            )
        )
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).all()
    items = []
    for incident, evidence_total, alerts_total in rows:
        items.append(
            CaseOut(
                id=incident.id,
                ref=incident.ref,
                title=incident.title,
                description=incident.description,
                severity=incident.severity,
                status=incident.status,
                priority=incident.priority,
                detected_at=incident.detected_at,
                contained_at=incident.contained_at,
                resolved_at=incident.resolved_at,
                closed_at=incident.closed_at,
                mitre=incident.mitre,
                evidence_count=int(evidence_total),
                alert_count=int(alerts_total),
            )
        )
    return Page[CaseOut](**paginate(items, total, page, page_size))


@router.get("/cases/{incident_id}", response_model=CaseDetailOut, summary="Case timeline, evidence and alerts")
def get_case(incident_id: UUID, ctx: RequestContext = Depends(require_permission("incident:read"))) -> CaseDetailOut:
    incident = service.get_incident(ctx.db, ctx.org.id, incident_id)
    timeline = list(
        ctx.db.execute(
            select(IncidentTimeline)
            .where(IncidentTimeline.incident_id == incident.id)
            .order_by(IncidentTimeline.at.asc())
        ).scalars()
    )
    evidence = list(
        ctx.db.execute(
            select(Evidence).where(Evidence.incident_id == incident.id).order_by(Evidence.collected_at.asc())
        ).scalars()
    )
    alerts = list(
        ctx.db.execute(
            select(Alert).where(Alert.incident_id == incident.id).order_by(Alert.created_at.desc())
        ).scalars()
    )
    return CaseDetailOut(
        case=CaseOut(**service.case_view(ctx.db, incident)),
        timeline=[TimelineEntryOut.model_validate(entry) for entry in timeline],
        evidence=[EvidenceOut(**service.evidence_view(item)) for item in evidence],
        alerts=[
            CaseAlertOut(
                id=alert.id,
                title=alert.title,
                severity=alert.severity,
                status=alert.status,
                first_seen=alert.first_seen,
                last_seen=alert.last_seen,
                count=alert.count,
                mitre=alert.mitre,
            )
            for alert in alerts
        ],
    )


@router.post(
    "/cases/{incident_id}/export",
    summary="Export a case bundle (ZIP + manifest) bounded to 100 MB",
)
def export_case(
    incident_id: UUID, ctx: RequestContext = Depends(require_permission("incident:read"))
) -> StreamingResponse:
    incident = service.get_incident(ctx.db, ctx.org.id, incident_id)
    evidence_items = list(
        ctx.db.execute(
            select(Evidence).where(Evidence.incident_id == incident.id).order_by(Evidence.collected_at.asc())
        ).scalars()
    )
    content, result = service.build_case_manifest(ctx.db, ctx, incident, evidence_items)
    ctx.audit(
        action="forensics.case.export",
        resource_type="incident",
        resource_id=str(incident.id),
        payload={
            "ref": incident.ref,
            "size_bytes": result["size_bytes"],
            "sha256": result["sha256"],
            "evidence_included": result["evidence_included"],
            "evidence_missing": result["evidence_missing"],
            "evidence_errors": result["evidence_errors"],
        },
    )
    ctx.db.commit()
    headers = {
        "Content-Disposition": f'attachment; filename="{result["filename"]}"',
        "X-Content-SHA256": result["sha256"],
        "X-Content-Length": str(result["size_bytes"]),
        "X-Evidence-Included": str(result["evidence_included"]),
        "X-Evidence-Missing": str(result["evidence_missing"]),
    }
    return StreamingResponse(iter([content]), media_type="application/zip", headers=headers)


# --------------------------------------------------------------------------- #
# Evidence
# --------------------------------------------------------------------------- #
@router.get("/evidence", response_model=Page[EvidenceOut], summary="List evidence with filters")
def list_evidence(
    ctx: RequestContext = Depends(require_permission("incident:read")),
    incident_id: UUID | None = Query(default=None),
    kind: str | None = Query(default=None, max_length=40),
    sealed: bool | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
) -> Page[EvidenceOut]:
    stmt = select(Evidence).where(Evidence.org_id == ctx.org.id).order_by(Evidence.collected_at.desc())
    if incident_id is not None:
        stmt = stmt.where(Evidence.incident_id == incident_id)
    if kind:
        stmt = stmt.where(Evidence.kind == kind)
    if sealed is not None:
        stmt = stmt.where(Evidence.sealed.is_(sealed))
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Evidence.title).like(needle),
                func.lower(func.coalesce(Evidence.description, "")).like(needle),
                func.lower(Evidence.sha256).like(needle),
            )
        )
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[EvidenceOut](
        **paginate([EvidenceOut(**service.evidence_view(row)) for row in rows], total, page, page_size)
    )


@router.post(
    "/evidence/{evidence_id}/verify-hash",
    response_model=HashVerificationOut,
    summary="Recompute the evidence SHA-256 and append a custody entry",
)
def verify_evidence_hash(
    evidence_id: UUID, ctx: RequestContext = Depends(require_permission("incident:write"))
) -> HashVerificationOut:
    evidence = service.get_evidence(ctx.db, ctx.org.id, evidence_id)
    result = service.verify_evidence_hash(ctx.db, ctx, evidence)
    return HashVerificationOut(**result)


@router.get(
    "/evidence/{evidence_id}/chain-of-custody",
    response_model=ChainOfCustodyOut,
    summary="Read the chain of custody for an evidence item",
)
def get_chain_of_custody(
    evidence_id: UUID, ctx: RequestContext = Depends(require_permission("incident:read"))
) -> ChainOfCustodyOut:
    evidence = service.get_evidence(ctx.db, ctx.org.id, evidence_id)
    entries = list(evidence.chain_of_custody or [])
    verified = [
        entry.get("at")
        for entry in entries
        if isinstance(entry, dict) and entry.get("action") == "verify_hash" and isinstance(entry.get("at"), str)
    ]
    return ChainOfCustodyOut(
        evidence_id=evidence.id,
        incident_id=evidence.incident_id,
        sha256=evidence.sha256,
        sealed=evidence.sealed,
        entries=entries,
        last_verified_at=verified[-1] if verified else None,
    )


# --------------------------------------------------------------------------- #
# Timeline export
# --------------------------------------------------------------------------- #
@router.get("/timeline/export", summary="Export an incident timeline as CSV or JSON")
def export_timeline(
    ctx: RequestContext = Depends(require_permission("incident:read")),
    incident_id: UUID = Query(...),
    format: str = Query(default="csv", pattern="^(csv|json)$"),
) -> Response:
    incident = service.get_incident(ctx.db, ctx.org.id, incident_id)
    rows = service.timeline_rows(ctx.db, incident)
    if format == "json":
        payload = json.dumps(
            {
                "incident_id": str(incident.id),
                "ref": incident.ref,
                "generated_at": utcnow().isoformat(),
                "entry_count": len(rows),
                "entries": rows,
            },
            default=str,
            ensure_ascii=False,
        )
        filename = f"case-{service.safe_filename(incident.ref, 'case', 40)}-timeline.json"
        return Response(
            content=payload,
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for row in rows:
        writer.writerow(
            [
                service.csv_safe(row["at"].isoformat() if hasattr(row["at"], "isoformat") else row["at"]),
                service.csv_safe(row["kind"]),
                service.csv_safe(row["actor"] or ""),
                service.csv_safe(row["summary"]),
                service.csv_safe(json.dumps(row["detail"], default=str, ensure_ascii=False)),
            ]
        )
    filename = f"case-{service.safe_filename(incident.ref, 'case', 40)}-timeline.csv"
    return Response(
        content=buffer.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


__all__ = ["router"]
