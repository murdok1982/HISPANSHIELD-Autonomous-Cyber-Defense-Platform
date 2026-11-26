"""Zone and conduit management (IEC 62443 zoning model)."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, or_, select

from app.core.db import utcnow
from app.core.deps import RequestContext, require_permission
from app.core.errors import Conflict, NotFound, ValidationFailure
from app.core.schemas import Page, paginate
from app.models.assets import Asset, OTDevice, Zone
from app.modules.assets.schemas import AssetOut, ZoneCreate, ZoneOut, ZonePatch
from app.modules.assets.service import get_zone

zones_router = APIRouter(prefix="/zones", tags=["Zones & Conduits"])

ZONE_SORTS = {
    "name": Zone.name,
    "kind": Zone.kind,
    "purdue_level": Zone.purdue_level,
    "created_at": Zone.created_at,
}

MAX_ZONE_DEPTH = 20


def _ensure_name_available(db, org_id: UUID, name: str, *, exclude: UUID | None = None) -> None:
    stmt = select(Zone).where(Zone.org_id == org_id, func.lower(Zone.name) == name.strip().lower())
    if exclude is not None:
        stmt = stmt.where(Zone.id != exclude)
    if db.execute(stmt).scalar_one_or_none() is not None:
        raise Conflict("A zone with this name already exists")


def _validate_parent(db, org_id: UUID, zone: Zone | None, parent_id: UUID | None) -> Zone | None:
    if parent_id is None:
        return None
    if zone is not None and parent_id == zone.id:
        raise ValidationFailure([{"field": "parent_id", "message": "A zone cannot be its own parent"}])
    parent = get_zone(db, org_id, parent_id)
    cursor: Zone | None = parent
    for _ in range(MAX_ZONE_DEPTH):
        if cursor is None or cursor.parent_id is None:
            return parent
        if zone is not None and cursor.parent_id == zone.id:
            raise ValidationFailure([{"field": "parent_id", "message": "Parent assignment would create a cycle"}])
        cursor = db.get(Zone, cursor.parent_id)
        if cursor is not None and cursor.org_id != org_id:
            raise NotFound("Zone")
    raise ValidationFailure([{"field": "parent_id", "message": "Zone hierarchy is too deep or cyclic"}])


@zones_router.get("", response_model=Page[ZoneOut], summary="List zones and conduits")
def list_zones(
    ctx: RequestContext = Depends(require_permission("asset:read")),
    kind: str | None = Query(default=None, pattern="^(zone|conduit)$"),
    q: str | None = Query(default=None, max_length=120),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    sort: str = Query(default="name", pattern="^(name|kind|purdue_level|created_at)$"),
    order: str = Query(default="asc", pattern="^(asc|desc)$"),
) -> Page[ZoneOut]:
    stmt = select(Zone).where(Zone.org_id == ctx.org.id)
    if kind:
        stmt = stmt.where(Zone.kind == kind)
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(Zone.name).like(needle), func.lower(Zone.description).like(needle)))
    column = ZONE_SORTS[sort]
    stmt = stmt.order_by(column.asc() if order == "asc" else column.desc())
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[ZoneOut](**paginate([ZoneOut.model_validate(row) for row in rows], int(total), page, page_size))


@zones_router.post("", response_model=ZoneOut, status_code=201, summary="Create a zone or conduit")
def create_zone(payload: ZoneCreate, ctx: RequestContext = Depends(require_permission("asset:write"))) -> Zone:
    _ensure_name_available(ctx.db, ctx.org.id, payload.name)
    _validate_parent(ctx.db, ctx.org.id, None, payload.parent_id)
    zone = Zone(
        org_id=ctx.org.id,
        name=payload.name.strip(),
        kind=payload.kind,
        purdue_level=payload.purdue_level,
        description=payload.description,
        parent_id=payload.parent_id,
        metadata_json=payload.metadata,
    )
    ctx.db.add(zone)
    ctx.db.flush()
    ctx.audit(
        action="zone.create",
        resource_type="zone",
        resource_id=str(zone.id),
        payload={"name": zone.name, "kind": zone.kind, "purdue_level": zone.purdue_level},
    )
    ctx.db.commit()
    ctx.db.refresh(zone)
    return zone


@zones_router.get("/{zone_id}", response_model=ZoneOut, summary="Read a zone")
def read_zone(zone_id: UUID, ctx: RequestContext = Depends(require_permission("asset:read"))) -> Zone:
    return get_zone(ctx.db, ctx.org.id, zone_id)


@zones_router.patch("/{zone_id}", response_model=ZoneOut, summary="Update a zone")
def update_zone(
    zone_id: UUID, payload: ZonePatch, ctx: RequestContext = Depends(require_permission("asset:write"))
) -> Zone:
    zone = get_zone(ctx.db, ctx.org.id, zone_id)
    changes = payload.model_dump(exclude_unset=True)
    if "name" in changes and changes["name"] is not None and changes["name"].strip().lower() != zone.name.lower():
        _ensure_name_available(ctx.db, ctx.org.id, changes["name"], exclude=zone.id)
        zone.name = changes["name"].strip()
    if "parent_id" in changes:
        parent_id = changes["parent_id"]
        _validate_parent(ctx.db, ctx.org.id, zone, parent_id)
        zone.parent_id = parent_id
    if "kind" in changes and changes["kind"] is not None:
        zone.kind = changes["kind"]
    if "purdue_level" in changes:
        zone.purdue_level = changes["purdue_level"]
    if "description" in changes:
        zone.description = changes["description"]
    if "metadata" in changes and changes["metadata"] is not None:
        zone.metadata_json = changes["metadata"]
    zone.updated_at = utcnow()
    ctx.audit(
        action="zone.update",
        resource_type="zone",
        resource_id=str(zone.id),
        payload={"fields": sorted(changes.keys())},
    )
    ctx.db.commit()
    ctx.db.refresh(zone)
    return zone


@zones_router.delete(
    "/{zone_id}",
    status_code=204,
    response_class=Response,
    summary="Delete a zone; references must be reassigned explicitly",
)
def delete_zone(
    zone_id: UUID,
    reassign_to: UUID | None = Query(default=None, description="Target zone for assets/devices/children"),
    ctx: RequestContext = Depends(require_permission("asset:write")),
) -> Response:
    zone = get_zone(ctx.db, ctx.org.id, zone_id)
    assets = list(ctx.db.execute(select(Asset).where(Asset.org_id == ctx.org.id, Asset.zone_id == zone.id)).scalars())
    devices = list(
        ctx.db.execute(select(OTDevice).where(OTDevice.org_id == ctx.org.id, OTDevice.zone_id == zone.id)).scalars()
    )
    children = list(ctx.db.execute(select(Zone).where(Zone.org_id == ctx.org.id, Zone.parent_id == zone.id)).scalars())
    references = len(assets) + len(devices) + len(children)
    if references and reassign_to is None:
        raise Conflict(
            "Zone is still referenced by "
            f"{len(assets)} asset(s), {len(devices)} OT device(s) and {len(children)} child zone(s); "
            "pass ?reassign_to=<zone_id> to migrate them"
        )
    if reassign_to is not None:
        if reassign_to == zone.id:
            raise ValidationFailure([{"field": "reassign_to", "message": "Cannot reassign to the deleted zone"}])
        target = get_zone(ctx.db, ctx.org.id, reassign_to)
        for asset in assets:
            asset.zone_id = target.id
        for device in devices:
            device.zone_id = target.id
        for child in children:
            child.parent_id = target.id
    ctx.audit(
        action="zone.delete",
        resource_type="zone",
        resource_id=str(zone.id),
        payload={
            "reassigned_assets": len(assets),
            "reassigned_devices": len(devices),
            "reassigned_zones": len(children),
            "reassign_to": str(reassign_to) if reassign_to else None,
        },
    )
    ctx.db.delete(zone)
    ctx.db.commit()
    return Response(status_code=204)


@zones_router.get("/{zone_id}/assets", response_model=Page[AssetOut], summary="Assets assigned to a zone")
def zone_assets(
    zone_id: UUID,
    ctx: RequestContext = Depends(require_permission("asset:read")),
    kind: str | None = Query(default=None, pattern="^(host|network|cloud|iot|ot|identity|service)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
) -> Page[AssetOut]:
    get_zone(ctx.db, ctx.org.id, zone_id)
    stmt = select(Asset).where(Asset.org_id == ctx.org.id, Asset.zone_id == zone_id)
    if kind:
        stmt = stmt.where(Asset.kind == kind)
    stmt = stmt.order_by(Asset.criticality.desc(), Asset.name.asc())
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[AssetOut](**paginate([AssetOut.model_validate(row) for row in rows], int(total), page, page_size))


__all__ = ["zones_router"]
