"""Event fabric API: ingest sources, public/authenticated ingestion, search and retention."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Path, Query, Request, Response
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.db import get_db, utcnow
from app.core.deps import RequestContext, require_any_permission, require_permission
from app.core.errors import AppError, Conflict, NotFound, Unauthorized, ValidationFailure
from app.core.rate_limit import enforce
from app.core.schemas import Page, paginate
from app.models.connectors import Connector
from app.models.events import IngestSource, SecurityEvent
from app.modules.events import service
from app.modules.events.schemas import (
    BulkIngestRequest,
    BulkIngestResponse,
    EventDetail,
    EventSummary,
    IngestResponse,
    IngestSourceCreate,
    IngestSourceCreated,
    IngestSourceOut,
    IngestSourcePatch,
    IngestSourceTokenRotated,
    RetentionPolicyOut,
    RetentionPolicyUpdate,
    RetentionPurgeResult,
)
from app.services.normalization import ParseError, parse_payload, sanitize_text

router = APIRouter(tags=["Security Events & SIEM Ingest"])

_sources_write = require_any_permission("event:ingest", "settings:write")

SORT_COLUMNS = {
    "occurred_at": SecurityEvent.occurred_at,
    "received_at": SecurityEvent.received_at,
    "severity_id": SecurityEvent.severity_id,
    "class_uid": SecurityEvent.class_uid,
    "id": SecurityEvent.id,
}


def _utc(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


def _like(term: str) -> str:
    escaped = term.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return f"%{escaped.lower()}%"


def _source_or_404(db: Session, org_id: UUID, source_id: UUID) -> IngestSource:
    source = db.get(IngestSource, source_id)
    if source is None or source.org_id != org_id:
        raise NotFound("Ingest source")
    return source


def _created_response(source: IngestSource, token: str, secret: str | None) -> dict[str, Any]:
    payload = service.serialize_source(source)
    payload["token"] = token
    payload["hmac_secret"] = secret
    return payload


# ---------------------------------------------------------------------------
# Ingest sources (tenant scoped)
# ---------------------------------------------------------------------------


@router.get("/ingest-sources", response_model=Page[IngestSourceOut], summary="List ingestion sources")
def list_ingest_sources(
    ctx: RequestContext = Depends(require_permission("event:read")),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    enabled: bool | None = Query(default=None),
    kind: str | None = Query(default=None, pattern="^(api|webhook|syslog)$"),
    q: str | None = Query(default=None, max_length=120),
) -> Page[IngestSourceOut]:
    stmt = select(IngestSource).where(IngestSource.org_id == ctx.org.id).order_by(IngestSource.name.asc())
    if enabled is not None:
        stmt = stmt.where(IngestSource.enabled.is_(enabled))
    if kind:
        stmt = stmt.where(IngestSource.kind == kind)
    if q:
        stmt = stmt.where(func.lower(IngestSource.name).like(_like(q), escape="\\"))
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    items = [IngestSourceOut(**service.serialize_source(row)) for row in rows]
    return Page[IngestSourceOut](**paginate(items, total, page, page_size))


@router.post(
    "/ingest-sources",
    response_model=IngestSourceCreated,
    status_code=201,
    summary="Create an ingestion source and reveal its token exactly once",
)
def create_ingest_source(
    payload: IngestSourceCreate,
    ctx: RequestContext = Depends(_sources_write),
) -> dict[str, Any]:
    if payload.connector_id is not None:
        connector = ctx.db.get(Connector, payload.connector_id)
        if connector is None or connector.org_id != ctx.org.id:
            raise NotFound("Connector")
    source, token, secret = service.create_source(
        ctx.db,
        org_id=ctx.org.id,
        name=payload.name,
        kind=payload.kind,
        parser=payload.parser,
        enabled=payload.enabled,
        config=payload.config,
        created_by=ctx.actor_id,
        connector_id=payload.connector_id,
        hmac_secret=payload.hmac_secret,
        generate_secret=payload.generate_hmac_secret,
    )
    ctx.audit(
        action="ingest_source.create",
        resource_type="ingest_source",
        resource_id=str(source.id),
        payload={
            "name": source.name,
            "kind": source.kind,
            "parser": source.parser,
            "has_hmac_secret": bool(secret),
        },
    )
    ctx.db.commit()
    return _created_response(source, token, secret)


@router.get("/ingest-sources/{source_id}", response_model=IngestSourceOut, summary="Read an ingestion source")
def get_ingest_source(
    source_id: UUID,
    ctx: RequestContext = Depends(require_permission("event:read")),
) -> IngestSourceOut:
    return IngestSourceOut(**service.serialize_source(_source_or_404(ctx.db, ctx.org.id, source_id)))


@router.patch("/ingest-sources/{source_id}", response_model=IngestSourceOut, summary="Update an ingestion source")
def update_ingest_source(
    source_id: UUID,
    payload: IngestSourcePatch,
    ctx: RequestContext = Depends(_sources_write),
) -> IngestSourceOut:
    source = _source_or_404(ctx.db, ctx.org.id, source_id)
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        if value is None:
            continue
        if field == "name":
            value = sanitize_text(value, max_length=160)
        setattr(source, field, value)
    ctx.audit(
        action="ingest_source.update",
        resource_type="ingest_source",
        resource_id=str(source.id),
        payload={"fields": sorted(changes.keys()), "enabled": source.enabled},
    )
    ctx.db.commit()
    ctx.db.refresh(source)
    return IngestSourceOut(**service.serialize_source(source))


@router.delete(
    "/ingest-sources/{source_id}",
    status_code=204,
    response_class=Response,
    summary="Delete an ingestion source",
)
def delete_ingest_source(source_id: UUID, ctx: RequestContext = Depends(_sources_write)) -> Response:
    source = _source_or_404(ctx.db, ctx.org.id, source_id)
    ctx.audit(
        action="ingest_source.delete",
        resource_type="ingest_source",
        resource_id=str(source.id),
        payload={"name": source.name, "kind": source.kind},
    )
    ctx.db.delete(source)
    ctx.db.commit()
    return Response(status_code=204)


@router.post(
    "/ingest-sources/{source_id}/enable",
    response_model=IngestSourceOut,
    summary="Enable an ingestion source",
)
def enable_ingest_source(source_id: UUID, ctx: RequestContext = Depends(_sources_write)) -> IngestSourceOut:
    source = _source_or_404(ctx.db, ctx.org.id, source_id)
    source.enabled = True
    ctx.audit(
        action="ingest_source.enable",
        resource_type="ingest_source",
        resource_id=str(source.id),
    )
    ctx.db.commit()
    ctx.db.refresh(source)
    return IngestSourceOut(**service.serialize_source(source))


@router.post(
    "/ingest-sources/{source_id}/disable",
    response_model=IngestSourceOut,
    summary="Disable an ingestion source without deleting it",
)
def disable_ingest_source(source_id: UUID, ctx: RequestContext = Depends(_sources_write)) -> IngestSourceOut:
    source = _source_or_404(ctx.db, ctx.org.id, source_id)
    source.enabled = False
    ctx.audit(
        action="ingest_source.disable",
        resource_type="ingest_source",
        resource_id=str(source.id),
    )
    ctx.db.commit()
    ctx.db.refresh(source)
    return IngestSourceOut(**service.serialize_source(source))


@router.post(
    "/ingest-sources/{source_id}/rotate-token",
    response_model=IngestSourceTokenRotated,
    summary="Rotate the ingestion token (the previous token is invalidated immediately)",
)
def rotate_ingest_token(
    source_id: UUID,
    ctx: RequestContext = Depends(_sources_write),
) -> IngestSourceTokenRotated:
    source = _source_or_404(ctx.db, ctx.org.id, source_id)
    token = service.rotate_source_token(ctx.db, source)
    ctx.audit(
        action="ingest_source.rotate_token",
        resource_type="ingest_source",
        resource_id=str(source.id),
        payload={"name": source.name},
    )
    ctx.db.commit()
    return IngestSourceTokenRotated(id=source.id, token=token, rotated_at=utcnow())


# ---------------------------------------------------------------------------
# Public ingestion (token authenticated, rate limited, no session)
# ---------------------------------------------------------------------------


@router.post(
    "/ingest/{source_token}",
    response_model=IngestResponse,
    summary="Submit events with a scoped ingestion token",
    responses={401: {"description": "Invalid token or signature"}, 413: {"description": "Payload too large"}},
)
async def ingest_with_token(
    source_token: str,
    request: Request,
    db: Session = Depends(get_db),
    x_hispa_signature: str | None = Header(default=None, alias="X-HISPA-Signature"),
    x_hs_signature: str | None = Header(default=None, alias="X-HS-Signature"),
) -> IngestResponse:
    client_ip = request.client.host if request.client else None
    # Rate-limit by caller IP first: unknown tokens must not be enumerable via timing.
    enforce(f"ingest:ip:{client_ip or 'unknown'}", service.INGEST_RATE_LIMIT * 4, service.INGEST_RATE_WINDOW)
    body = await request.body()
    if not body:
        raise ValidationFailure([{"field": "body", "message": "Request body is required"}])
    if len(body) > service.MAX_BODY_BYTES:
        raise AppError("payload_too_large", "Payload exceeds the 1 MiB ingest limit", 413)

    source = service.resolve_source_by_token(db, source_token)
    if source is None or not source.enabled:
        # Identical response for unknown and disabled sources.
        raise Unauthorized("Invalid ingestion token")
    enforce(
        f"ingest:source:{source.id}",
        service.INGEST_RATE_LIMIT,
        service.INGEST_RATE_WINDOW,
    )

    signature = x_hispa_signature or x_hs_signature
    if not service.verify_source_signature(source, body, signature):
        service.audit_ingest(
            db,
            org_id=source.org_id,
            source=source,
            accepted=0,
            rejected=1,
            outcome="failure",
            ip_address=client_ip,
            user_agent=request.headers.get("user-agent"),
            request_id=getattr(request.state, "request_id", "-"),
            detail={"error": "signature_invalid"},
        )
        db.commit()
        raise Unauthorized("Invalid signature")

    try:
        parsed = parse_payload(
            body,
            content_type=request.headers.get("content-type"),
            parser=source.parser,
        )
    except ParseError as exc:
        service.audit_ingest(
            db,
            org_id=source.org_id,
            source=source,
            accepted=0,
            rejected=1,
            outcome="failure",
            ip_address=client_ip,
            user_agent=request.headers.get("user-agent"),
            request_id=getattr(request.state, "request_id", "-"),
            detail={"error": exc.code},
        )
        db.commit()
        raise ValidationFailure([{"field": "body", "message": exc.message}]) from exc

    result = service.ingest_parsed_events(db, org_id=source.org_id, source=source, events=parsed)
    service.audit_ingest(
        db,
        org_id=source.org_id,
        source=source,
        accepted=len(parsed),
        rejected=0,
        ip_address=client_ip,
        user_agent=request.headers.get("user-agent"),
        request_id=getattr(request.state, "request_id", "-"),
        detail={"alerts_created": result.alerts_created},
    )
    db.commit()
    return IngestResponse(
        accepted=len(parsed),
        rejected=0,
        event_ids=result.event_ids,
        alerts_created=result.alerts_created,
    )


# ---------------------------------------------------------------------------
# Authenticated bulk ingestion
# ---------------------------------------------------------------------------


@router.post("/events/ingest", response_model=BulkIngestResponse, summary="Bulk-ingest up to 500 events")
def ingest_bulk(
    payload: BulkIngestRequest,
    ctx: RequestContext = Depends(require_permission("event:ingest")),
) -> BulkIngestResponse:
    source: IngestSource | None = None
    if payload.source_id is not None:
        source = _source_or_404(ctx.db, ctx.org.id, payload.source_id)
    parsed = [service.build_manual_event(item.model_dump()) for item in payload.events]
    result = service.ingest_parsed_events(
        ctx.db,
        org_id=ctx.org.id,
        source=source,
        events=parsed,
        run_pipeline=payload.run_detection,
    )
    ctx.audit(
        action="event.ingest.bulk",
        resource_type="ingest_source" if source else "event_batch",
        resource_id=str(source.id) if source else None,
        payload={
            "accepted": len(parsed),
            "alerts_created": result.alerts_created,
            "source_id": str(source.id) if source else None,
        },
    )
    ctx.db.commit()
    return BulkIngestResponse(
        accepted=len(parsed),
        rejected=0,
        event_ids=result.event_ids,
        alerts_created=result.alerts_created,
        errors=[],
    )


# ---------------------------------------------------------------------------
# Search, statistics, detail
# ---------------------------------------------------------------------------


@router.get("/events/stats", summary="24h event statistics (severity, class, top sources/hosts, timeline)")
def event_stats(
    ctx: RequestContext = Depends(require_permission("event:read")),
    hours: int = Query(default=24, ge=1, le=168),
) -> dict[str, Any]:
    since = utcnow() - timedelta(hours=hours)
    base = [SecurityEvent.org_id == ctx.org.id, SecurityEvent.occurred_at >= since]
    total = ctx.db.execute(select(func.count()).select_from(SecurityEvent).where(*base)).scalar_one()
    severity_rows = ctx.db.execute(
        select(SecurityEvent.severity_id, func.count())
        .where(*base)
        .group_by(SecurityEvent.severity_id)
        .order_by(SecurityEvent.severity_id)
    ).all()
    class_rows = ctx.db.execute(
        select(SecurityEvent.class_uid, SecurityEvent.class_name, func.count().label("count"))
        .where(*base)
        .group_by(SecurityEvent.class_uid, SecurityEvent.class_name)
        .order_by(func.count().desc())
        .limit(10)
    ).all()
    source_rows = ctx.db.execute(
        select(IngestSource.id, IngestSource.name, func.count(SecurityEvent.id).label("count"))
        .select_from(SecurityEvent)
        .outerjoin(IngestSource, IngestSource.id == SecurityEvent.source_id)
        .where(*base)
        .group_by(IngestSource.id, IngestSource.name)
        .order_by(func.count(SecurityEvent.id).desc())
        .limit(10)
    ).all()
    host_rows = ctx.db.execute(
        select(SecurityEvent.host_name, func.count().label("count"))
        .where(*base, SecurityEvent.host_name.isnot(None))
        .group_by(SecurityEvent.host_name)
        .order_by(func.count().desc())
        .limit(10)
    ).all()
    bucket = func.date_trunc("hour", SecurityEvent.occurred_at)
    timeline_rows = ctx.db.execute(select(bucket, func.count()).where(*base).group_by(bucket).order_by(bucket)).all()
    by_bucket = {row[0].astimezone(UTC).isoformat(): int(row[1]) for row in timeline_rows}
    timeline: list[dict[str, Any]] = []
    cursor = utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(hours=hours - 1)
    for _ in range(hours):
        timeline.append({"timestamp": cursor.isoformat(), "count": by_bucket.get(cursor.isoformat(), 0)})
        cursor += timedelta(hours=1)
    return {
        "generated_at": utcnow().isoformat(),
        "window_hours": hours,
        "total": int(total),
        "by_severity": {
            str(level): int(next((row[1] for row in severity_rows if int(row[0]) == level), 0)) for level in range(6)
        },
        "by_class": [{"class_uid": int(row[0]), "class_name": row[1], "count": int(row[2])} for row in class_rows],
        "top_sources": [
            {
                "source_id": str(row[0]) if row[0] else None,
                "name": row[1] or "deleted source",
                "count": int(row[2]),
            }
            for row in source_rows
        ],
        "top_hosts": [{"host_name": row[0], "count": int(row[1])} for row in host_rows],
        "timeline": timeline,
    }


@router.get("/events/retention", response_model=RetentionPolicyOut, summary="Read the event retention policy")
def get_retention(ctx: RequestContext = Depends(require_permission("policy:read"))) -> RetentionPolicyOut:
    policy, definition = service.get_retention_policy(ctx.db, ctx.org.id)
    return RetentionPolicyOut(**service.serialize_retention(policy, definition))


@router.put("/events/retention", response_model=RetentionPolicyOut, summary="Update the event retention policy")
def put_retention(
    payload: RetentionPolicyUpdate,
    ctx: RequestContext = Depends(require_permission("policy:write")),
) -> RetentionPolicyOut:
    policy, definition = service.save_retention_policy(
        ctx.db,
        org_id=ctx.org.id,
        definition=payload.model_dump(),
        actor_id=ctx.actor_id,
    )
    ctx.audit(
        action="policy.retention.update",
        resource_type="policy",
        resource_id=str(policy.id),
        payload={"definition": definition, "version": policy.version},
    )
    ctx.db.commit()
    ctx.db.refresh(policy)
    return RetentionPolicyOut(**service.serialize_retention(policy, definition))


@router.post(
    "/events/retention/purge",
    response_model=RetentionPurgeResult,
    summary="Purge events beyond the retention window (bounded batches)",
)
def purge_retention(ctx: RequestContext = Depends(require_permission("policy:write"))) -> RetentionPurgeResult:
    policy, definition = service.get_retention_policy(ctx.db, ctx.org.id)
    if not definition["purge_enabled"]:
        raise Conflict("Retention purge is disabled for this organization")
    cutoff = utcnow() - timedelta(days=definition["hot_days"])
    deleted, batches, truncated = service.purge_old_events(
        ctx.db,
        org_id=ctx.org.id,
        cutoff=cutoff,
        batch_size=definition["batch_size"],
    )
    ctx.audit(
        action="policy.retention.purge",
        resource_type="policy",
        resource_id=str(policy.id) if policy else None,
        payload={
            "deleted": deleted,
            "batches": batches,
            "cutoff": cutoff.isoformat(),
            "truncated": truncated,
        },
    )
    ctx.db.commit()
    return RetentionPurgeResult(deleted=deleted, cutoff=cutoff, batches=batches, truncated=truncated)


@router.get("/events", response_model=Page[EventSummary], summary="Search normalized security events")
def list_events(
    ctx: RequestContext = Depends(require_permission("event:read")),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    occurred_from: datetime | None = Query(default=None),
    occurred_to: datetime | None = Query(default=None),
    severity_id: int | None = Query(default=None, ge=0, le=5),
    class_uid: int | None = Query(default=None, ge=0, le=99999),
    source_id: UUID | None = Query(default=None),
    src_ip: str | None = Query(default=None, max_length=64),
    host_name: str | None = Query(default=None, max_length=255),
    user_name: str | None = Query(default=None, max_length=200),
    q: str | None = Query(default=None, max_length=200),
    sort: str = Query(default="occurred_at"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
) -> Page[EventSummary]:
    start, end = _utc(occurred_from), _utc(occurred_to)
    if start and end and start > end:
        raise ValidationFailure([{"field": "occurred_from", "message": "occurred_from must be before occurred_to"}])
    stmt = select(SecurityEvent).where(SecurityEvent.org_id == ctx.org.id)
    if start:
        stmt = stmt.where(SecurityEvent.occurred_at >= start)
    if end:
        stmt = stmt.where(SecurityEvent.occurred_at <= end)
    if severity_id is not None:
        stmt = stmt.where(SecurityEvent.severity_id == severity_id)
    if class_uid is not None:
        stmt = stmt.where(SecurityEvent.class_uid == class_uid)
    if source_id is not None:
        _source_or_404(ctx.db, ctx.org.id, source_id)
        stmt = stmt.where(SecurityEvent.source_id == source_id)
    if src_ip:
        stmt = stmt.where(SecurityEvent.src_ip == src_ip)
    if host_name:
        stmt = stmt.where(func.lower(SecurityEvent.host_name).like(_like(host_name), escape="\\"))
    if user_name:
        stmt = stmt.where(func.lower(SecurityEvent.user_name).like(_like(user_name), escape="\\"))
    if q:
        needle = _like(q)
        stmt = stmt.where(
            or_(
                func.lower(SecurityEvent.message).like(needle, escape="\\"),
                func.lower(SecurityEvent.src_ip).like(needle, escape="\\"),
                func.lower(SecurityEvent.host_name).like(needle, escape="\\"),
                func.lower(SecurityEvent.user_name).like(needle, escape="\\"),
                func.lower(SecurityEvent.domain).like(needle, escape="\\"),
                func.lower(SecurityEvent.url).like(needle, escape="\\"),
            )
        )
    column = SORT_COLUMNS.get(sort)
    if column is None:
        raise ValidationFailure([{"field": "sort", "message": f"Unsupported sort column: {sort}"}])
    stmt = stmt.order_by(column.asc() if order == "asc" else column.desc(), SecurityEvent.id.desc())
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[EventSummary](**paginate([EventSummary.model_validate(row) for row in rows], total, page, page_size))


@router.get("/events/{event_id}", response_model=EventDetail, summary="Read an event including its raw payload")
def get_event(
    event_id: int = Path(ge=1),
    ctx: RequestContext = Depends(require_permission("event:read")),
) -> EventDetail:
    event = ctx.db.get(SecurityEvent, event_id)
    if event is None or event.org_id != ctx.org.id:
        raise NotFound("Security event")
    return EventDetail.model_validate(event)


__all__ = ["router"]
