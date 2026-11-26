"""Threat intelligence API: indicators, actors, feeds, enrichment and ATT&CK."""

from __future__ import annotations

import json
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import func, or_, select

from app.core.db import utcnow
from app.core.deps import RequestContext, require_permission
from app.core.errors import Conflict, Forbidden, NotFound, ValidationFailure
from app.core.schemas import Page, paginate
from app.models.connectors import Connector
from app.models.ti import ThreatActor, ThreatIndicator, TIFeed
from app.modules.threat_intel import service
from app.modules.threat_intel.schemas import (
    ActorCreate,
    ActorDetail,
    ActorOut,
    ActorPatch,
    CsvImportRequest,
    DeactivateResult,
    FeedCreate,
    FeedOut,
    FeedPatch,
    FeedSyncResult,
    ImportResult,
    IndicatorCreate,
    IndicatorOut,
    IndicatorPatch,
    StixBundleImport,
)
from app.modules.threat_intel.stix import INDICATOR_TYPES, SEVERITIES

router = APIRouter(prefix="/threat-intel", tags=["Threat Intelligence"])


def _is_platform_admin(ctx: RequestContext) -> bool:
    return bool(ctx.user and ctx.user.is_platform_admin) or ctx.role == "platform_admin"


def _tenant_scope(org_id: UUID):  # type: ignore[no-untyped-def]
    return or_(ThreatIndicator.org_id == org_id, ThreatIndicator.org_id.is_(None))


def _indicator_view(indicator: ThreatIndicator) -> IndicatorOut:
    return IndicatorOut.model_validate(indicator)


def _actor_view(actor: ThreatActor) -> ActorOut:
    return ActorOut.model_validate(actor)


# --------------------------------------------------------------------------- #
# Indicators
# --------------------------------------------------------------------------- #
@router.get("/indicators", response_model=Page[IndicatorOut], summary="List indicators (tenant + global)")
def list_indicators(
    ctx: RequestContext = Depends(require_permission("ti:read")),
    indicator_type: str | None = Query(default=None, alias="type"),
    severity: str | None = Query(default=None),
    source: str | None = Query(default=None, max_length=120),
    active: bool | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
) -> Page[IndicatorOut]:
    if indicator_type is not None and indicator_type not in INDICATOR_TYPES:
        raise ValidationFailure([{"field": "type", "message": f"Type must be one of {', '.join(INDICATOR_TYPES)}"}])
    if severity is not None and severity not in SEVERITIES:
        raise ValidationFailure([{"field": "severity", "message": f"Severity must be one of {', '.join(SEVERITIES)}"}])

    stmt = select(ThreatIndicator).where(_tenant_scope(ctx.org.id)).order_by(ThreatIndicator.last_seen.desc())
    if indicator_type:
        stmt = stmt.where(ThreatIndicator.indicator_type == indicator_type)
    if severity:
        stmt = stmt.where(ThreatIndicator.severity == severity)
    if source:
        stmt = stmt.where(ThreatIndicator.source == source)
    if active is not None:
        stmt = stmt.where(ThreatIndicator.active.is_(active))
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(ThreatIndicator.value).like(needle),
                func.lower(func.coalesce(ThreatIndicator.description, "")).like(needle),
                func.lower(ThreatIndicator.source).like(needle),
            )
        )

    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[IndicatorOut](**paginate([_indicator_view(row) for row in rows], total, page, page_size))


@router.post("/indicators", response_model=IndicatorOut, status_code=201, summary="Create an indicator")
def create_indicator(
    payload: IndicatorCreate, ctx: RequestContext = Depends(require_permission("ti:write"))
) -> IndicatorOut:
    org_id: UUID | None = ctx.org.id
    if payload.global_indicator:
        if not _is_platform_admin(ctx):
            raise Forbidden("Only platform administrators can create global indicators")
        org_id = None
    duplicate = ctx.db.execute(
        select(ThreatIndicator).where(
            ThreatIndicator.org_id.is_(None) if org_id is None else ThreatIndicator.org_id == org_id,
            ThreatIndicator.indicator_type == payload.indicator_type,
            ThreatIndicator.value == payload.value,
        )
    ).scalar_one_or_none()
    if duplicate is not None:
        raise Conflict("An indicator with this type and value already exists in this scope")

    actor_id = service.resolve_actor_id(ctx.db, ctx.org.id, payload.actor_id)
    now = utcnow()
    indicator = ThreatIndicator(
        org_id=org_id,
        indicator_type=payload.indicator_type,
        value=payload.value,
        confidence=payload.confidence,
        severity=payload.severity,
        source=payload.source,
        description=payload.description,
        tags=payload.tags,
        actor_id=actor_id,
        first_seen=payload.first_seen or now,
        last_seen=payload.last_seen or now,
        expires_at=payload.expires_at,
        active=payload.active and not (payload.expires_at is not None and payload.expires_at <= now),
        stix={"imported_from": "api"},
    )
    ctx.db.add(indicator)
    ctx.db.flush()
    ctx.audit(
        action="ti.indicator.create",
        resource_type="threat_indicator",
        resource_id=str(indicator.id),
        payload={
            "indicator_type": indicator.indicator_type,
            "severity": indicator.severity,
            "confidence": indicator.confidence,
            "global": org_id is None,
        },
    )
    ctx.db.commit()
    ctx.db.refresh(indicator)
    return _indicator_view(indicator)


@router.get("/indicators/{indicator_id}", response_model=IndicatorOut, summary="Read an indicator")
def get_indicator(indicator_id: UUID, ctx: RequestContext = Depends(require_permission("ti:read"))) -> IndicatorOut:
    return _indicator_view(service.get_indicator(ctx.db, ctx.org.id, indicator_id))


@router.patch("/indicators/{indicator_id}", response_model=IndicatorOut, summary="Update an indicator")
def update_indicator(
    indicator_id: UUID,
    payload: IndicatorPatch,
    ctx: RequestContext = Depends(require_permission("ti:write")),
) -> IndicatorOut:
    indicator = service.get_indicator(ctx.db, ctx.org.id, indicator_id)
    if indicator.org_id is None and not _is_platform_admin(ctx):
        raise Forbidden("Only platform administrators can modify global indicators")

    changes = payload.model_dump(exclude_unset=True)
    if "actor_id" in changes:
        changes["actor_id"] = service.resolve_actor_id(ctx.db, ctx.org.id, changes["actor_id"])
    for field, value in changes.items():
        setattr(indicator, field, value)
    if indicator.expires_at is not None and indicator.expires_at <= utcnow():
        indicator.active = False
    ctx.audit(
        action="ti.indicator.update",
        resource_type="threat_indicator",
        resource_id=str(indicator.id),
        payload={"fields": sorted(changes.keys())},
    )
    ctx.db.commit()
    ctx.db.refresh(indicator)
    return _indicator_view(indicator)


@router.post(
    "/indicators/{indicator_id}/deactivate", response_model=DeactivateResult, summary="Deactivate an indicator"
)
def deactivate_indicator(
    indicator_id: UUID, ctx: RequestContext = Depends(require_permission("ti:write"))
) -> DeactivateResult:
    indicator = service.get_indicator(ctx.db, ctx.org.id, indicator_id)
    if indicator.org_id is None and not _is_platform_admin(ctx):
        raise Forbidden("Only platform administrators can deactivate global indicators")
    indicator.active = False
    ctx.audit(
        action="ti.indicator.deactivate",
        resource_type="threat_indicator",
        resource_id=str(indicator.id),
        payload={"value": indicator.value, "type": indicator.indicator_type},
    )
    ctx.db.commit()
    return DeactivateResult(id=indicator.id, active=False, message="Indicator deactivated")


@router.delete("/indicators/{indicator_id}", status_code=204, response_class=Response, summary="Delete an indicator")
def delete_indicator(indicator_id: UUID, ctx: RequestContext = Depends(require_permission("ti:write"))) -> Response:
    indicator = service.get_indicator(ctx.db, ctx.org.id, indicator_id)
    if indicator.org_id is None and not _is_platform_admin(ctx):
        raise Forbidden("Only platform administrators can delete global indicators")
    ctx.audit(
        action="ti.indicator.delete",
        resource_type="threat_indicator",
        resource_id=str(indicator.id),
        payload={"value": indicator.value, "type": indicator.indicator_type},
    )
    ctx.db.delete(indicator)
    ctx.db.commit()
    return Response(status_code=204)


@router.post("/indicators/import", response_model=ImportResult, summary="Import a STIX 2.1 bundle")
def import_stix(
    payload: StixBundleImport, ctx: RequestContext = Depends(require_permission("ti:write"))
) -> ImportResult:
    records = service.records_from_stix(payload.bundle, source="stix")
    summary = service.upsert_indicators(
        ctx.db,
        ctx.org.id,
        service.stix_records_to_upserts(records, source="stix"),
    )
    ctx.audit(
        action="ti.indicators.import",
        resource_type="threat_indicator",
        payload={
            "format": "stix2.1",
            "received": len(records),
            "created": summary.created,
            "updated": summary.updated,
            "skipped": summary.skipped,
        },
    )
    ctx.db.commit()
    return ImportResult(
        created=summary.created,
        updated=summary.updated,
        skipped=summary.skipped,
        errors=summary.errors[:50],
        total_received=len(records),
    )


@router.post("/indicators/import/csv", response_model=ImportResult, summary="Import indicators from CSV")
async def import_csv(request: Request, ctx: RequestContext = Depends(require_permission("ti:write"))) -> ImportResult:
    raw = await request.body()
    if not raw:
        raise ValidationFailure([{"field": "csv", "message": "Request body is empty"}])
    if len(raw) > 2_100_000:
        raise ValidationFailure([{"field": "csv", "message": "CSV payload exceeds 2 MB"}])
    content_type = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    source = "csv"
    if content_type == "application/json":
        try:
            decoded = json.loads(raw)
        except ValueError as exc:
            raise ValidationFailure([{"field": "csv", "message": "Malformed JSON body"}]) from exc
        try:
            payload = CsvImportRequest.model_validate(decoded)
        except ValueError as exc:
            raise ValidationFailure([{"field": "body", "message": "Invalid CSV import payload"}]) from exc
        csv_text = payload.csv
        source = payload.source or source
    else:
        try:
            csv_text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValidationFailure([{"field": "csv", "message": "CSV must be UTF-8 encoded"}]) from exc

    records, parse_summary = service.parse_csv_records(csv_text, default_source=source)
    summary = service.upsert_indicators(ctx.db, ctx.org.id, records)
    summary.skipped += parse_summary.skipped
    summary.errors.extend(parse_summary.errors)
    ctx.audit(
        action="ti.indicators.import",
        resource_type="threat_indicator",
        payload={
            "format": "csv",
            "received": len(records),
            "created": summary.created,
            "updated": summary.updated,
            "skipped": summary.skipped,
        },
    )
    ctx.db.commit()
    return ImportResult(
        created=summary.created,
        updated=summary.updated,
        skipped=summary.skipped,
        errors=summary.errors[:50],
        total_received=len(records) + parse_summary.skipped,
    )


# --------------------------------------------------------------------------- #
# Actors
# --------------------------------------------------------------------------- #
@router.get("/actors", response_model=Page[ActorOut], summary="List threat actors")
def list_actors(
    ctx: RequestContext = Depends(require_permission("ti:read")),
    q: str | None = Query(default=None, max_length=120),
    mitre_id: str | None = Query(default=None, pattern=r"^[GST]\d{4}$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
) -> Page[ActorOut]:
    stmt = (
        select(ThreatActor)
        .where(or_(ThreatActor.org_id == ctx.org.id, ThreatActor.org_id.is_(None)))
        .order_by(ThreatActor.name)
    )
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(ThreatActor.name).like(needle),
                func.lower(func.coalesce(ThreatActor.description, "")).like(needle),
            )
        )
    if mitre_id:
        stmt = stmt.where(ThreatActor.mitre_id == mitre_id)
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[ActorOut](**paginate([_actor_view(row) for row in rows], total, page, page_size))


@router.post("/actors", response_model=ActorOut, status_code=201, summary="Create a threat actor")
def create_actor(payload: ActorCreate, ctx: RequestContext = Depends(require_permission("ti:write"))) -> ActorOut:
    org_id: UUID | None = ctx.org.id
    if payload.global_actor:
        if not _is_platform_admin(ctx):
            raise Forbidden("Only platform administrators can create global threat actors")
        org_id = None
    actor = ThreatActor(
        org_id=org_id,
        name=payload.name,
        aliases=payload.aliases,
        mitre_id=payload.mitre_id,
        description=payload.description,
        sophistication=payload.sophistication,
        motivation=payload.motivation,
        country=payload.country,
        techniques=payload.techniques,
        stix={},
    )
    ctx.db.add(actor)
    ctx.db.flush()
    ctx.audit(
        action="ti.actor.create",
        resource_type="threat_actor",
        resource_id=str(actor.id),
        payload={"name": actor.name, "mitre_id": actor.mitre_id, "global": org_id is None},
    )
    ctx.db.commit()
    ctx.db.refresh(actor)
    return _actor_view(actor)


@router.get("/actors/{actor_id}", response_model=ActorDetail, summary="Read a threat actor")
def get_actor(actor_id: UUID, ctx: RequestContext = Depends(require_permission("ti:read"))) -> ActorDetail:
    actor = service.get_actor(ctx.db, ctx.org.id, actor_id)
    indicator_count = ctx.db.execute(
        select(func.count()).select_from(ThreatIndicator).where(ThreatIndicator.actor_id == actor.id)
    ).scalar_one()
    detail = ActorDetail.model_validate(actor)
    detail.indicator_count = int(indicator_count)
    return detail


@router.patch("/actors/{actor_id}", response_model=ActorOut, summary="Update a threat actor")
def update_actor(
    actor_id: UUID, payload: ActorPatch, ctx: RequestContext = Depends(require_permission("ti:write"))
) -> ActorOut:
    actor = service.get_actor(ctx.db, ctx.org.id, actor_id)
    if actor.org_id is None and not _is_platform_admin(ctx):
        raise Forbidden("Only platform administrators can modify global threat actors")
    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(actor, field, value)
    ctx.audit(
        action="ti.actor.update",
        resource_type="threat_actor",
        resource_id=str(actor.id),
        payload={"fields": sorted(changes.keys())},
    )
    ctx.db.commit()
    ctx.db.refresh(actor)
    return _actor_view(actor)


@router.delete("/actors/{actor_id}", status_code=204, response_class=Response, summary="Delete a threat actor")
def delete_actor(actor_id: UUID, ctx: RequestContext = Depends(require_permission("ti:write"))) -> Response:
    actor = service.get_actor(ctx.db, ctx.org.id, actor_id)
    if actor.org_id is None and not _is_platform_admin(ctx):
        raise Forbidden("Only platform administrators can delete global threat actors")
    ctx.audit(
        action="ti.actor.delete",
        resource_type="threat_actor",
        resource_id=str(actor.id),
        payload={"name": actor.name, "mitre_id": actor.mitre_id},
    )
    ctx.db.delete(actor)
    ctx.db.commit()
    return Response(status_code=204)


# --------------------------------------------------------------------------- #
# Feeds
# --------------------------------------------------------------------------- #
def _validate_connector(ctx: RequestContext, connector_id: UUID | None) -> None:
    if connector_id is None:
        return
    connector = ctx.db.get(Connector, connector_id)
    if connector is None or connector.org_id != ctx.org.id:
        raise NotFound("Connector")


@router.get("/feeds", response_model=Page[FeedOut], summary="List intelligence feeds")
def list_feeds(
    ctx: RequestContext = Depends(require_permission("ti:read")),
    enabled: bool | None = Query(default=None),
    status: str | None = Query(default=None, max_length=30),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
) -> Page[FeedOut]:
    stmt = select(TIFeed).where(TIFeed.org_id == ctx.org.id).order_by(TIFeed.name)
    if enabled is not None:
        stmt = stmt.where(TIFeed.enabled.is_(enabled))
    if status:
        stmt = stmt.where(TIFeed.status == status)
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[FeedOut](**paginate([service.serialize_feed(row) for row in rows], total, page, page_size))


@router.post("/feeds", response_model=FeedOut, status_code=201, summary="Create an intelligence feed")
def create_feed(payload: FeedCreate, ctx: RequestContext = Depends(require_permission("ti:write"))) -> FeedOut:
    _validate_connector(ctx, payload.connector_id)
    feed = TIFeed(
        org_id=ctx.org.id,
        name=payload.name,
        kind=payload.kind,
        connector_id=payload.connector_id,
        enabled=payload.enabled,
        schedule_minutes=payload.schedule_minutes,
        status="idle",
        config=payload.config,
    )
    ctx.db.add(feed)
    ctx.db.flush()
    ctx.audit(
        action="ti.feed.create",
        resource_type="ti_feed",
        resource_id=str(feed.id),
        payload={
            "name": feed.name,
            "kind": feed.kind,
            "connector_id": str(feed.connector_id) if feed.connector_id else None,
        },
    )
    ctx.db.commit()
    ctx.db.refresh(feed)
    return FeedOut.model_validate(service.serialize_feed(feed))


@router.get("/feeds/{feed_id}", response_model=FeedOut, summary="Read an intelligence feed")
def get_feed(feed_id: UUID, ctx: RequestContext = Depends(require_permission("ti:read"))) -> FeedOut:
    return FeedOut.model_validate(service.serialize_feed(service.get_feed(ctx.db, ctx.org.id, feed_id)))


@router.patch("/feeds/{feed_id}", response_model=FeedOut, summary="Update an intelligence feed")
def update_feed(
    feed_id: UUID, payload: FeedPatch, ctx: RequestContext = Depends(require_permission("ti:write"))
) -> FeedOut:
    feed = service.get_feed(ctx.db, ctx.org.id, feed_id)
    changes = payload.model_dump(exclude_unset=True)
    if "connector_id" in changes:
        _validate_connector(ctx, changes["connector_id"])
    for field, value in changes.items():
        setattr(feed, field, value)
    ctx.audit(
        action="ti.feed.update",
        resource_type="ti_feed",
        resource_id=str(feed.id),
        payload={"fields": sorted(changes.keys())},
    )
    ctx.db.commit()
    ctx.db.refresh(feed)
    return FeedOut.model_validate(service.serialize_feed(feed))


@router.delete("/feeds/{feed_id}", status_code=204, response_class=Response, summary="Delete an intelligence feed")
def delete_feed(feed_id: UUID, ctx: RequestContext = Depends(require_permission("ti:write"))) -> Response:
    feed = service.get_feed(ctx.db, ctx.org.id, feed_id)
    ctx.audit(
        action="ti.feed.delete",
        resource_type="ti_feed",
        resource_id=str(feed.id),
        payload={"name": feed.name, "kind": feed.kind},
    )
    ctx.db.delete(feed)
    ctx.db.commit()
    return Response(status_code=204)


@router.post("/feeds/{feed_id}/sync", response_model=FeedSyncResult, summary="Synchronize an intelligence feed")
def sync_feed(feed_id: UUID, ctx: RequestContext = Depends(require_permission("ti:sync"))) -> FeedSyncResult:
    feed = service.get_feed(ctx.db, ctx.org.id, feed_id)
    if not feed.enabled:
        raise Conflict("Feed is disabled")
    result = service.sync_feed(ctx.db, ctx, feed)
    return FeedSyncResult(**result)


# --------------------------------------------------------------------------- #
# Enrichment, ATT&CK and summary
# --------------------------------------------------------------------------- #
@router.get("/enrich", summary="Enrich a value with matching indicators and ATT&CK context")
def enrich(
    ctx: RequestContext = Depends(require_permission("ti:read")),
    value: str = Query(min_length=1, max_length=500),
    indicator_type: str | None = Query(default=None, alias="type"),
) -> dict[str, Any]:
    if indicator_type is not None and indicator_type not in INDICATOR_TYPES:
        raise ValidationFailure([{"field": "type", "message": f"Type must be one of {', '.join(INDICATOR_TYPES)}"}])
    return service.enrich_value(ctx.db, ctx.org.id, value, indicator_type)


@router.get("/mitre/techniques", summary="MITRE ATT&CK technique catalogue")
def list_mitre_techniques(
    ctx: RequestContext = Depends(require_permission("ti:read")),
    tactic: str | None = Query(default=None, max_length=60),
    q: str | None = Query(default=None, max_length=120),
) -> dict[str, Any]:
    catalog = service.load_mitre_techniques()
    needle = q.lower() if q else None
    items = [
        item
        for item in catalog
        if (not tactic or tactic.lower() in item["tactics"])
        and (
            not needle
            or needle in item["id"].lower()
            or needle in item["name"].lower()
            or needle in item["description"].lower()
        )
    ]
    return {
        "catalog_size": len(catalog),
        "count": len(items),
        "items": items,
        "filters": {"tactic": tactic, "q": q},
    }


@router.get("/mitre/coverage", summary="ATT&CK techniques observed in events, indicators and actors")
def mitre_coverage(ctx: RequestContext = Depends(require_permission("ti:read"))) -> dict[str, Any]:
    return service.mitre_coverage(ctx.db, ctx.org.id)


@router.get("/summary", summary="Threat intelligence posture summary")
def summary(ctx: RequestContext = Depends(require_permission("ti:read"))) -> dict[str, Any]:
    return service.tenant_summary(ctx.db, ctx.org.id)


__all__ = ["router"]
