"""Asset inventory, identity, relationship and graph API."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Response
from sqlalchemy import String, and_, cast, func, or_, select

from app.core.db import utcnow
from app.core.deps import RequestContext, require_permission
from app.core.errors import Conflict, NotFound, PolicyDenied, ValidationFailure
from app.core.idempotency import execute as execute_idempotent
from app.core.schemas import Page, decode_cursor, encode_cursor, paginate
from app.models.assets import Asset, AssetIdentity, AssetRelationship
from app.modules.assets import service
from app.modules.assets.schemas import (
    AssetCreate,
    AssetDetailOut,
    AssetGraphOut,
    AssetImportRequest,
    AssetOut,
    AssetPatch,
    AssetRef,
    AssetVulnerabilityOut,
    IdentityCreate,
    IdentityOut,
    ImportResult,
    RelationshipCreate,
    RelationshipView,
)
from app.modules.assets.zones import zones_router

assets_router = APIRouter(prefix="/assets", tags=["Asset Intelligence"])

ASSET_SORTS = {
    "asset_key": Asset.asset_key,
    "name": Asset.name,
    "kind": Asset.kind,
    "criticality": Asset.criticality,
    "confidence": Asset.confidence,
    "environment": Asset.environment,
    "last_seen": Asset.last_seen,
    "created_at": Asset.created_at,
    "updated_at": Asset.updated_at,
}


@assets_router.get("", response_model=Page[AssetOut], summary="List assets with filters and pagination")
def list_assets(
    ctx: RequestContext = Depends(require_permission("asset:read")),
    kind: str | None = Query(default=None, pattern="^(host|network|cloud|iot|ot|identity|service)$"),
    subtype: str | None = Query(default=None, max_length=60),
    criticality: int | None = Query(default=None, ge=1, le=5),
    environment: str | None = Query(default=None, pattern="^(production|staging|development|test)$"),
    status: str | None = Query(default=None, pattern="^(active|inactive|retired|quarantined|unknown)$"),
    zone_id: UUID | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    cursor: str | None = Query(default=None, max_length=700, description="Opaque keyset cursor from meta.next_cursor"),
    sort: str = Query(default="last_seen", pattern="^(" + "|".join(ASSET_SORTS) + ")$"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
) -> Page[AssetOut]:
    stmt = select(Asset).where(Asset.org_id == ctx.org.id, Asset.deleted_at.is_(None))
    if kind:
        stmt = stmt.where(Asset.kind == kind)
    if subtype:
        stmt = stmt.where(func.lower(Asset.subtype) == subtype.lower())
    if criticality is not None:
        stmt = stmt.where(Asset.criticality == criticality)
    if environment:
        stmt = stmt.where(Asset.environment == environment)
    if status:
        stmt = stmt.where(Asset.status == status)
    if zone_id:
        stmt = stmt.where(Asset.zone_id == zone_id)
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Asset.name).like(needle),
                func.lower(Asset.asset_key).like(needle),
                func.lower(Asset.owner).like(needle),
                func.lower(Asset.os_name).like(needle),
                cast(Asset.hostnames, String).like(needle),
                cast(Asset.ip_addresses, String).like(needle),
            )
        )
    column = ASSET_SORTS[sort]
    next_cursor: str | None = None
    if cursor:
        try:
            payload = decode_cursor(cursor)
            if payload.get("kind") != "assets" or payload.get("sort") != sort or payload.get("order") != order:
                raise ValueError("Cursor scope mismatch")
            cursor_id = UUID(str(payload["id"]))
            raw_value = payload["v"]
            if sort in {"last_seen", "created_at", "updated_at"}:
                cursor_value: Any = datetime.fromisoformat(str(raw_value))
                if cursor_value.tzinfo is None:
                    cursor_value = cursor_value.replace(tzinfo=UTC)
            elif sort in {"criticality", "confidence"}:
                cursor_value = int(raw_value)
            else:
                cursor_value = str(raw_value)
        except (ValueError, KeyError, TypeError) as exc:
            raise ValidationFailure([{"field": "cursor", "message": "Invalid or expired cursor"}]) from exc
        if order == "desc":
            stmt = stmt.where(or_(column < cursor_value, and_(column == cursor_value, Asset.id < cursor_id))).order_by(
                column.desc(), Asset.id.desc()
            )
        else:
            stmt = stmt.where(or_(column > cursor_value, and_(column == cursor_value, Asset.id > cursor_id))).order_by(
                column.asc(), Asset.id.asc()
            )
        page = 1
    else:
        stmt = stmt.order_by(
            column.asc() if order == "asc" else column.desc(), Asset.id.asc() if order == "asc" else Asset.id.desc()
        )
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    if rows and len(rows) == page_size:
        last = rows[-1]
        value = getattr(last, sort)
        encoded_value = value.astimezone(UTC).isoformat() if isinstance(value, datetime) else value
        next_cursor = encode_cursor(
            {"kind": "assets", "sort": sort, "order": order, "v": encoded_value, "id": str(last.id)}
        )
    return Page[AssetOut](
        **paginate(
            [AssetOut.model_validate(row) for row in rows],
            int(total),
            page,
            page_size,
            next_cursor=next_cursor,
        )
    )


@assets_router.post("/import", response_model=ImportResult, summary="Idempotent bulk asset import (max 500 rows)")
def import_assets(
    payload: AssetImportRequest,
    response: Response,
    ctx: RequestContext = Depends(require_permission("asset:write")),
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
) -> ImportResult:
    def run() -> ImportResult:
        result = service.import_assets(ctx.db, ctx.org.id, payload)
        ctx.audit(
            action="asset.import",
            resource_type="asset",
            payload={
                "total": result.total,
                "created": result.created,
                "updated": result.updated,
                "skipped": result.skipped,
                "errors": len(result.errors),
                "source": payload.source,
            },
        )
        ctx.db.commit()
        return result

    body, replayed = execute_idempotent(
        ctx,
        idempotency_key,
        method="POST",
        path="/api/v1/assets/import",
        payload=payload,
        fn=run,
        replay_status=200,
    )
    if replayed:
        response.headers["Idempotent-Replayed"] = "true"
    return body  # type: ignore[return-value]


@assets_router.get(
    "/{asset_id}", response_model=AssetDetailOut, summary="Asset detail with relationships and graph context"
)
def read_asset(asset_id: UUID, ctx: RequestContext = Depends(require_permission("asset:read"))) -> AssetDetailOut:
    asset = service.get_asset(ctx.db, ctx.org.id, asset_id)
    return service.asset_detail(ctx.db, asset)


@assets_router.post("", response_model=AssetOut, status_code=201, summary="Create an asset")
def create_asset(payload: AssetCreate, ctx: RequestContext = Depends(require_permission("asset:write"))) -> Asset:
    existing = service.asset_or_none_by_key(ctx.db, ctx.org.id, payload.asset_key)
    if existing is not None:
        if existing.deleted_at is not None:
            raise Conflict(
                "An asset with this asset_key is in the trash; restore it or choose another key",
                code="asset_key_in_trash",
            )
        raise Conflict("An asset with this asset_key already exists")
    service.ensure_zone_exists(ctx.db, ctx.org.id, payload.zone_id)
    asset = Asset(
        org_id=ctx.org.id,
        **payload.model_dump(exclude={"metadata"}),
        metadata_json=payload.metadata,
    )
    ctx.db.add(asset)
    ctx.db.flush()
    ctx.audit(
        action="asset.create",
        resource_type="asset",
        resource_id=str(asset.id),
        payload={"asset_key": asset.asset_key, "kind": asset.kind, "criticality": asset.criticality},
    )
    ctx.db.commit()
    ctx.db.refresh(asset)
    return asset


@assets_router.patch("/{asset_id}", response_model=AssetOut, summary="Update an asset")
def update_asset(
    asset_id: UUID, payload: AssetPatch, ctx: RequestContext = Depends(require_permission("asset:write"))
) -> Asset:
    asset = service.get_asset(ctx.db, ctx.org.id, asset_id)
    changes = payload.model_dump(exclude_unset=True)
    if "zone_id" in changes and changes["zone_id"] is not None:
        service.ensure_zone_exists(ctx.db, ctx.org.id, changes["zone_id"])
    for field, value in changes.items():
        if field == "metadata":
            if value is not None:
                asset.metadata_json = value
            continue
        setattr(asset, field, value)
    asset.last_seen = utcnow()
    ctx.audit(
        action="asset.update",
        resource_type="asset",
        resource_id=str(asset.id),
        payload={"fields": sorted(changes.keys())},
    )
    ctx.db.commit()
    ctx.db.refresh(asset)
    return asset


@assets_router.delete("/{asset_id}", status_code=204, response_class=Response, summary="Delete an asset")
def delete_asset(
    asset_id: UUID,
    confirm: bool = Query(default=False, description="Required to delete OT assets"),
    ctx: RequestContext = Depends(require_permission("asset:write")),
) -> Response:
    asset = service.get_asset(ctx.db, ctx.org.id, asset_id)
    if asset.kind == "ot" and not confirm:
        raise PolicyDenied(
            "Deleting an OT asset requires explicit confirmation: repeat the request with ?confirm=true. "
            "HISPANSHIELD never performs active OT operations implicitly.",
            details=[{"field": "confirm", "message": "OT asset deletion is a safety-sensitive operation"}],
        )
    ctx.audit(
        action="asset.delete",
        resource_type="asset",
        resource_id=str(asset.id),
        payload={"asset_key": asset.asset_key, "kind": asset.kind, "confirm": confirm, "soft": True},
    )
    # Soft delete: findings, evidence, incident references and the audit trail
    # keep pointing at a real row. Active ORM reads hide it via deleted_at.
    asset.deleted_at = utcnow()
    if asset.status != "retired":
        asset.status = "retired"
    ctx.db.commit()
    return Response(status_code=204)


@assets_router.post(
    "/{asset_id}/restore",
    response_model=AssetDetailOut,
    summary="Restore a soft-deleted asset with its relationships",
)
def restore_asset(asset_id: UUID, ctx: RequestContext = Depends(require_permission("asset:write"))) -> AssetDetailOut:
    asset = service.get_asset_including_deleted(ctx.db, ctx.org.id, asset_id)
    if asset.deleted_at is not None:
        asset.deleted_at = None
        if asset.status == "retired":
            asset.status = "active"
        asset.last_seen = utcnow()
        ctx.audit(
            action="asset.restore",
            resource_type="asset",
            resource_id=str(asset.id),
            payload={"asset_key": asset.asset_key, "kind": asset.kind},
        )
        ctx.db.commit()
        ctx.db.refresh(asset)
    return service.asset_detail(ctx.db, asset)


@assets_router.get("/{asset_id}/identities", response_model=list[IdentityOut], summary="List asset identities")
def list_identities(
    asset_id: UUID, ctx: RequestContext = Depends(require_permission("asset:read"))
) -> list[AssetIdentity]:
    asset = service.get_asset(ctx.db, ctx.org.id, asset_id)
    return list(
        ctx.db.execute(
            select(AssetIdentity)
            .where(AssetIdentity.asset_id == asset.id)
            .order_by(AssetIdentity.kind.asc(), AssetIdentity.created_at.asc())
        ).scalars()
    )


@assets_router.post(
    "/{asset_id}/identities", response_model=IdentityOut, status_code=201, summary="Attach an identity to an asset"
)
def add_identity(
    asset_id: UUID, payload: IdentityCreate, ctx: RequestContext = Depends(require_permission("asset:write"))
) -> AssetIdentity:
    asset = service.get_asset(ctx.db, ctx.org.id, asset_id)
    duplicate = ctx.db.execute(
        select(AssetIdentity).where(
            AssetIdentity.asset_id == asset.id,
            AssetIdentity.kind == payload.kind,
            AssetIdentity.value == payload.value,
        )
    ).scalar_one_or_none()
    if duplicate is not None:
        raise Conflict("This identity is already attached to the asset")
    identity = AssetIdentity(
        asset_id=asset.id,
        kind=payload.kind,
        value=payload.value,
        confidence=payload.confidence,
    )
    ctx.db.add(identity)
    ctx.db.flush()
    ctx.audit(
        action="asset.identity.add",
        resource_type="asset_identity",
        resource_id=str(identity.id),
        payload={"asset_id": str(asset.id), "kind": identity.kind},
    )
    ctx.db.commit()
    ctx.db.refresh(identity)
    return identity


@assets_router.delete(
    "/{asset_id}/identities/{identity_id}",
    status_code=204,
    response_class=Response,
    summary="Detach an identity from an asset",
)
def delete_identity(
    asset_id: UUID, identity_id: UUID, ctx: RequestContext = Depends(require_permission("asset:write"))
) -> Response:
    asset = service.get_asset(ctx.db, ctx.org.id, asset_id)
    identity = ctx.db.get(AssetIdentity, identity_id)
    if identity is None or identity.asset_id != asset.id:
        raise NotFound("Identity")
    ctx.audit(
        action="asset.identity.remove",
        resource_type="asset_identity",
        resource_id=str(identity.id),
        payload={"asset_id": str(asset.id), "kind": identity.kind},
    )
    ctx.db.delete(identity)
    ctx.db.commit()
    return Response(status_code=204)


@assets_router.get(
    "/{asset_id}/relationships", response_model=list[RelationshipView], summary="Relationships in both directions"
)
def list_relationships(
    asset_id: UUID, ctx: RequestContext = Depends(require_permission("asset:read"))
) -> list[RelationshipView]:
    asset = service.get_asset(ctx.db, ctx.org.id, asset_id)
    return service.relationship_views(ctx.db, ctx.org.id, asset)


@assets_router.post(
    "/{asset_id}/relationships",
    response_model=RelationshipView,
    status_code=201,
    summary="Create a relationship between two assets",
)
def create_relationship(
    asset_id: UUID, payload: RelationshipCreate, ctx: RequestContext = Depends(require_permission("asset:write"))
) -> RelationshipView:
    source = service.get_asset(ctx.db, ctx.org.id, asset_id)
    target = service.get_asset(ctx.db, ctx.org.id, payload.target_asset_id)
    if target.id == source.id:
        raise ValidationFailure([{"field": "target_asset_id", "message": "An asset cannot relate to itself"}])
    duplicate = ctx.db.execute(
        select(AssetRelationship).where(
            AssetRelationship.source_asset_id == source.id,
            AssetRelationship.target_asset_id == target.id,
            AssetRelationship.kind == payload.kind,
        )
    ).scalar_one_or_none()
    if duplicate is not None:
        raise Conflict("This relationship already exists")
    relationship = AssetRelationship(
        org_id=ctx.org.id,
        source_asset_id=source.id,
        target_asset_id=target.id,
        kind=payload.kind,
        confidence=payload.confidence,
        metadata_json=payload.metadata,
    )
    ctx.db.add(relationship)
    ctx.db.flush()
    ctx.audit(
        action="asset.relationship.create",
        resource_type="asset_relationship",
        resource_id=str(relationship.id),
        payload={
            "source_asset_id": str(source.id),
            "target_asset_id": str(target.id),
            "kind": relationship.kind,
        },
    )
    ctx.db.commit()
    ctx.db.refresh(relationship)
    return RelationshipView(
        id=relationship.id,
        source_asset_id=relationship.source_asset_id,
        target_asset_id=relationship.target_asset_id,
        kind=relationship.kind,
        confidence=relationship.confidence,
        first_seen=relationship.first_seen,
        last_seen=relationship.last_seen,
        metadata=relationship.metadata_json,
        direction="outbound",
        counterpart=AssetRef.model_validate(target),
    )


@assets_router.delete(
    "/relationships/{relationship_id}",
    status_code=204,
    response_class=Response,
    summary="Delete an asset relationship",
)
def delete_relationship(
    relationship_id: UUID, ctx: RequestContext = Depends(require_permission("asset:write"))
) -> Response:
    relationship = ctx.db.get(AssetRelationship, relationship_id)
    if relationship is None or relationship.org_id != ctx.org.id:
        raise NotFound("Relationship")
    ctx.audit(
        action="asset.relationship.delete",
        resource_type="asset_relationship",
        resource_id=str(relationship.id),
        payload={
            "source_asset_id": str(relationship.source_asset_id),
            "target_asset_id": str(relationship.target_asset_id),
            "kind": relationship.kind,
        },
    )
    ctx.db.delete(relationship)
    ctx.db.commit()
    return Response(status_code=204)


@assets_router.get("/{asset_id}/graph", response_model=AssetGraphOut, summary="Relationship graph (depth 1-3)")
def asset_graph(
    asset_id: UUID,
    depth: int = Query(default=1, ge=1, le=3),
    ctx: RequestContext = Depends(require_permission("asset:read")),
) -> AssetGraphOut:
    asset = service.get_asset(ctx.db, ctx.org.id, asset_id)
    return service.graph_for_asset(ctx.db, ctx.org.id, asset, depth)


@assets_router.get(
    "/{asset_id}/vulnerabilities",
    response_model=Page[AssetVulnerabilityOut],
    summary="Vulnerabilities affecting an asset",
)
def asset_vulnerabilities(
    asset_id: UUID,
    ctx: RequestContext = Depends(require_permission("asset:read")),
    status: str | None = Query(default=None, pattern="^(open|reopened|mitigated|accepted|false_positive)$"),
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low|info)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
) -> Page[AssetVulnerabilityOut]:
    service.get_asset(ctx.db, ctx.org.id, asset_id)
    items, total = service.asset_vulnerabilities(
        ctx.db,
        ctx.org.id,
        asset_id,
        status=status,
        severity=severity,
        offset=(page - 1) * page_size,
        limit=page_size,
    )
    return Page[AssetVulnerabilityOut](**paginate(items, total, page, page_size))


router = APIRouter()
router.include_router(zones_router)
router.include_router(assets_router)

__all__ = ["assets_router", "router", "zones_router"]
