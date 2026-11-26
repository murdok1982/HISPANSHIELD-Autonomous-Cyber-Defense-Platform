"""Asset intelligence business logic: details, graph traversal and imports."""

from __future__ import annotations

import ipaddress
from typing import Any
from uuid import UUID

from pydantic import ValidationError
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.core.errors import NotFound, ValidationFailure
from app.models.assets import (
    Asset,
    AssetIdentity,
    AssetRelationship,
    IoTDevice,
    OTDevice,
    Vulnerability,
    Zone,
)
from app.modules.assets.schemas import (
    AssetDetailOut,
    AssetGraphOut,
    AssetImportItem,
    AssetImportRequest,
    AssetIoTDetail,
    AssetOTDetail,
    AssetOut,
    AssetRef,
    AssetVulnerabilityOut,
    GraphEdge,
    GraphNode,
    IdentityOut,
    ImportResult,
    ImportRowError,
    RelationshipView,
    VulnerabilitySummaryOut,
)

MAX_GRAPH_DEPTH = 3
IMPORT_FIELDS = {
    "name",
    "subtype",
    "criticality",
    "environment",
    "status",
    "ip_addresses",
    "mac_addresses",
    "hostnames",
    "os_name",
    "vendor",
    "model",
    "firmware",
    "serial_number",
    "location",
    "owner",
    "zone_id",
    "tags",
    "metadata",
}


def get_asset(db: Session, org_id: UUID, asset_id: UUID) -> Asset:
    """Load an active tenant asset or raise 404 (never reveal foreign existence)."""
    asset = db.get(Asset, asset_id)
    if asset is None or asset.org_id != org_id or asset.deleted_at is not None:
        raise NotFound("Asset")
    return asset


def get_asset_including_deleted(db: Session, org_id: UUID, asset_id: UUID) -> Asset:
    """Load a tenant asset even when soft-deleted (restore/forensics only)."""
    asset = db.execute(
        select(Asset)
        .where(Asset.id == asset_id, Asset.org_id == org_id)
        .execution_options(include_soft_deleted=True)
        .with_for_update()
    ).scalar_one_or_none()
    if asset is None:
        raise NotFound("Asset")
    return asset


def get_zone(db: Session, org_id: UUID, zone_id: UUID) -> Zone:
    zone = db.get(Zone, zone_id)
    if zone is None or zone.org_id != org_id:
        raise NotFound("Zone")
    return zone


def asset_or_none_by_key(db: Session, org_id: UUID, asset_key: str) -> Asset | None:
    """Resolve a key including soft-deleted rows.

    Unique ``(org_id, asset_key)`` still applies to deleted rows, so callers
    must distinguish "active" from "in trash" instead of attempting an insert
    that would violate the constraint.
    """
    return db.execute(
        select(Asset)
        .where(Asset.org_id == org_id, Asset.asset_key == asset_key)
        .execution_options(include_soft_deleted=True)
    ).scalar_one_or_none()


def ensure_zone_exists(db: Session, org_id: UUID, zone_id: UUID | None) -> Zone | None:
    if zone_id is None:
        return None
    return get_zone(db, org_id, zone_id)


def _vulnerability_summary(db: Session, org_id: UUID, asset_id: UUID) -> VulnerabilitySummaryOut:
    rows = db.execute(
        select(Vulnerability.severity, Vulnerability.status, func.count())
        .where(Vulnerability.org_id == org_id, Vulnerability.asset_id == asset_id)
        .group_by(Vulnerability.severity, Vulnerability.status)
    ).all()
    by_severity: dict[str, int] = {}
    total = 0
    open_count = 0
    reopened = 0
    for severity, status, count in rows:
        total += count
        by_severity[severity] = by_severity.get(severity, 0) + count
        if status == "open":
            open_count += count
        elif status == "reopened":
            reopened += count
    kev = db.execute(
        select(func.count())
        .select_from(Vulnerability)
        .where(Vulnerability.org_id == org_id, Vulnerability.asset_id == asset_id, Vulnerability.kev.is_(True))
    ).scalar_one()
    return VulnerabilitySummaryOut(
        total=total,
        open=open_count,
        reopened=reopened,
        kev=int(kev),
        by_severity=by_severity,
    )


def relationship_views(db: Session, org_id: UUID, asset: Asset) -> list[RelationshipView]:
    """Return relationships in both directions with the counterpart summary."""
    relationships = list(
        db.execute(
            select(AssetRelationship)
            .where(
                AssetRelationship.org_id == org_id,
                or_(
                    AssetRelationship.source_asset_id == asset.id,
                    AssetRelationship.target_asset_id == asset.id,
                ),
            )
            .order_by(AssetRelationship.last_seen.desc())
        ).scalars()
    )
    counterpart_ids = {
        rel.target_asset_id if rel.source_asset_id == asset.id else rel.source_asset_id for rel in relationships
    }
    counterparts: dict[UUID, Asset] = {}
    if counterpart_ids:
        for row in db.execute(select(Asset).where(Asset.org_id == org_id, Asset.id.in_(counterpart_ids))).scalars():
            counterparts[row.id] = row
    views: list[RelationshipView] = []
    for rel in relationships:
        outbound = rel.source_asset_id == asset.id
        other = counterparts.get(rel.target_asset_id if outbound else rel.source_asset_id)
        views.append(
            RelationshipView(
                id=rel.id,
                source_asset_id=rel.source_asset_id,
                target_asset_id=rel.target_asset_id,
                kind=rel.kind,
                confidence=rel.confidence,
                first_seen=rel.first_seen,
                last_seen=rel.last_seen,
                metadata=rel.metadata_json,
                direction="outbound" if outbound else "inbound",
                counterpart=AssetRef.model_validate(other) if other is not None else None,
            )
        )
    return views


def asset_detail(db: Session, asset: Asset) -> AssetDetailOut:
    identities = list(
        db.execute(
            select(AssetIdentity)
            .where(AssetIdentity.asset_id == asset.id)
            .order_by(AssetIdentity.kind.asc(), AssetIdentity.created_at.asc())
        ).scalars()
    )
    iot = db.execute(
        select(IoTDevice).where(IoTDevice.asset_id == asset.id, IoTDevice.org_id == asset.org_id)
    ).scalar_one_or_none()
    ot = db.execute(
        select(OTDevice).where(OTDevice.asset_id == asset.id, OTDevice.org_id == asset.org_id)
    ).scalar_one_or_none()
    base = AssetOut.model_validate(asset)
    return AssetDetailOut(
        **base.model_dump(),
        identities=[IdentityOut.model_validate(identity) for identity in identities],
        relationships=relationship_views(db, asset.org_id, asset),
        iot=AssetIoTDetail.model_validate(iot) if iot else None,
        ot=AssetOTDetail.model_validate(ot) if ot else None,
        vulnerability_summary=_vulnerability_summary(db, asset.org_id, asset.id),
    )


def graph_for_asset(db: Session, org_id: UUID, root: Asset, depth: int) -> AssetGraphOut:
    """Breadth-first traversal of the relationship graph, depth 1..3.

    Edges are deduplicated by id and every node/edge is filtered by
    ``org_id`` on both the relationship and the asset lookup, so a graph can
    never leak a foreign tenant's inventory.
    """
    if depth < 1 or depth > MAX_GRAPH_DEPTH:
        raise ValidationFailure([{"field": "depth", "message": "depth must be between 1 and 3"}])

    node_ids: set[UUID] = {root.id}
    edges: dict[UUID, GraphEdge] = {}
    frontier: set[UUID] = {root.id}
    for _ in range(depth):
        if not frontier:
            break
        rows = list(
            db.execute(
                select(AssetRelationship).where(
                    AssetRelationship.org_id == org_id,
                    or_(
                        AssetRelationship.source_asset_id.in_(frontier),
                        AssetRelationship.target_asset_id.in_(frontier),
                    ),
                )
            ).scalars()
        )
        next_frontier: set[UUID] = set()
        for rel in rows:
            edges[rel.id] = GraphEdge(
                id=rel.id,
                source_asset_id=rel.source_asset_id,
                target_asset_id=rel.target_asset_id,
                kind=rel.kind,
                confidence=rel.confidence,
            )
            for node_id in (rel.source_asset_id, rel.target_asset_id):
                if node_id not in node_ids:
                    node_ids.add(node_id)
                    next_frontier.add(node_id)
        frontier = next_frontier

    assets = {
        row.id: row for row in db.execute(select(Asset).where(Asset.org_id == org_id, Asset.id.in_(node_ids))).scalars()
    }
    nodes = [
        GraphNode(
            id=row.id,
            asset_key=row.asset_key,
            name=row.name,
            kind=row.kind,
            criticality=row.criticality,
            environment=row.environment,
            zone_id=row.zone_id,
        )
        for row in assets.values()
    ]
    scoped_edges = [
        edge for edge in edges.values() if edge.source_asset_id in assets and edge.target_asset_id in assets
    ]
    return AssetGraphOut(root_id=root.id, depth=depth, nodes=nodes, edges=scoped_edges)


def asset_vulnerabilities(
    db: Session,
    org_id: UUID,
    asset_id: UUID,
    *,
    status: str | None,
    severity: str | None,
    offset: int,
    limit: int,
) -> tuple[list[AssetVulnerabilityOut], int]:
    stmt = select(Vulnerability).where(Vulnerability.org_id == org_id, Vulnerability.asset_id == asset_id)
    if status:
        stmt = stmt.where(Vulnerability.status == status)
    if severity:
        stmt = stmt.where(Vulnerability.severity == severity)
    stmt = stmt.order_by(Vulnerability.priority_score.desc(), Vulnerability.first_seen.desc())
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(db.execute(stmt.offset(offset).limit(limit)).scalars())
    return [AssetVulnerabilityOut.model_validate(row) for row in rows], int(total)


def _apply_row(asset: Asset, item: AssetImportItem) -> bool:
    """Apply explicitly provided row fields; return True when something changed."""
    changed = False
    explicit = item.model_fields_set
    for field in sorted(IMPORT_FIELDS & explicit):
        value = getattr(item, field)
        if value is None:
            continue
        target = "metadata_json" if field == "metadata" else field
        if getattr(asset, target) != value:
            setattr(asset, target, value)
            changed = True
    if "discovery_source" in explicit and item.discovery_source and asset.discovery_source != item.discovery_source:
        asset.discovery_source = item.discovery_source
        changed = True
    if "confidence" in explicit and item.confidence is not None and asset.confidence != item.confidence:
        asset.confidence = item.confidence
        changed = True
    if changed:
        asset.last_seen = utcnow()
    return changed


def import_assets(db: Session, org_id: UUID, payload: AssetImportRequest) -> ImportResult:
    """Idempotent bulk upsert keyed on (org_id, asset_key).

    Rows are validated individually; an invalid row is reported with its
    zero-based index and does not abort the rest of the batch. Existing assets
    are only updated with explicitly provided fields, so re-importing the same
    feed is a no-op (``skipped``) instead of overwriting curated metadata.
    """
    created = 0
    updated = 0
    skipped = 0
    errors: list[ImportRowError] = []
    seen_keys: set[str] = set()

    for index, raw in enumerate(payload.items):
        try:
            item = AssetImportItem.model_validate(raw)
        except ValidationError as exc:
            errors.append(
                ImportRowError(
                    row=index,
                    asset_key=str(raw.get("asset_key"))[:200] if isinstance(raw, dict) else None,
                    message="; ".join(
                        f"{'.'.join(str(part) for part in error['loc'])}: {error['msg']}" for error in exc.errors()
                    )[:500],
                )
            )
            continue

        if item.asset_key in seen_keys:
            errors.append(ImportRowError(row=index, asset_key=item.asset_key, message="Duplicate asset_key in batch"))
            continue
        seen_keys.add(item.asset_key)

        existing = asset_or_none_by_key(db, org_id, item.asset_key)
        if existing is not None and existing.deleted_at is not None:
            errors.append(
                ImportRowError(
                    row=index,
                    asset_key=item.asset_key,
                    message="asset_key belongs to a soft-deleted asset; restore it before importing",
                )
            )
            continue
        if existing is None:
            asset = Asset(
                org_id=org_id,
                asset_key=item.asset_key,
                name=item.name,
                kind=item.kind,
                subtype=item.subtype,
                criticality=item.criticality,
                environment=item.environment,
                status=item.status,
                ip_addresses=item.ip_addresses,
                mac_addresses=item.mac_addresses,
                hostnames=item.hostnames,
                os_name=item.os_name,
                vendor=item.vendor,
                model=item.model,
                firmware=item.firmware,
                serial_number=item.serial_number,
                location=item.location,
                owner=item.owner,
                zone_id=item.zone_id,
                tags=item.tags,
                metadata_json=item.metadata,
                discovery_source=item.discovery_source or payload.source,
                confidence=item.confidence if item.confidence is not None else payload.confidence,
                first_seen=utcnow(),
                last_seen=utcnow(),
            )
            if asset.zone_id is not None:
                ensure_zone_exists(db, org_id, asset.zone_id)
            db.add(asset)
            db.flush()
            created += 1
            continue

        if item.zone_id is not None:
            ensure_zone_exists(db, org_id, item.zone_id)
        if _apply_row(existing, item):
            updated += 1
        else:
            skipped += 1

    return ImportResult(
        total=len(payload.items),
        created=created,
        updated=updated,
        skipped=skipped,
        errors=errors,
    )


def asset_public_ip(asset: Asset) -> list[str]:
    """Return the asset's addresses that are globally routable."""
    result: list[str] = []
    for value in asset.ip_addresses or []:
        try:
            if ipaddress.ip_address(value).is_global:
                result.append(value)
        except ValueError:
            continue
    return result


def metadata_list(metadata: dict[str, Any], key: str) -> list[Any]:
    value = metadata.get(key) if isinstance(metadata, dict) else None
    if isinstance(value, list):
        return value
    return []


__all__ = [
    "MAX_GRAPH_DEPTH",
    "asset_detail",
    "asset_or_none_by_key",
    "asset_public_ip",
    "asset_vulnerabilities",
    "ensure_zone_exists",
    "get_asset",
    "get_zone",
    "graph_for_asset",
    "import_assets",
    "metadata_list",
    "relationship_views",
]
