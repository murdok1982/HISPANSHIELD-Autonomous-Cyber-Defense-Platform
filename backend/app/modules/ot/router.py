"""OT inventory, passive telemetry and IEC 62443 posture endpoints.

No endpoint performs active scanning, writes controller values, changes
firmware or reboots equipment. Telemetry is received from passive taps and is
used exclusively for baseline learning and alerting.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select

from app.core.db import utcnow
from app.core.deps import RequestContext, require_permission
from app.core.errors import Conflict, PolicyDenied, ValidationFailure
from app.core.schemas import Page, paginate
from app.models.assets import Asset, OTDevice, Zone
from app.modules.assets.service import ensure_zone_exists
from app.modules.iot.service import ensure_passive_metrics
from app.modules.ot import service
from app.modules.ot.protocols import ot_protocol_spec
from app.modules.ot.schemas import (
    OTDeviceCreate,
    OTDeviceOut,
    OTDevicePatch,
    OTPostureOut,
    OTProtocolOut,
    OTTelemetryBatch,
    OTTelemetryResult,
)

router = APIRouter(prefix="/ot", tags=["OT / ICS Security"])

OT_SORTS = {
    "name": Asset.name,
    "criticality": Asset.criticality,
    "last_seen": Asset.last_seen,
    "last_telemetry_at": OTDevice.last_telemetry_at,
}


@router.get("/devices", response_model=Page[OTDeviceOut], summary="List OT devices with zone and safety context")
def list_devices(
    ctx: RequestContext = Depends(require_permission("asset:read")),
    q: str | None = Query(default=None, max_length=200),
    zone_id: UUID | None = Query(default=None),
    safety_critical: bool | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    sort: str = Query(default="criticality", pattern="^(" + "|".join(OT_SORTS) + ")$"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
) -> Page[OTDeviceOut]:
    stmt = (
        select(OTDevice, Asset)
        .join(Asset, Asset.id == OTDevice.asset_id)
        .where(OTDevice.org_id == ctx.org.id, Asset.org_id == ctx.org.id)
    )
    if zone_id:
        stmt = stmt.where(or_(OTDevice.zone_id == zone_id, Asset.zone_id == zone_id))
    if safety_critical is not None:
        stmt = stmt.where(OTDevice.safety_critical.is_(safety_critical))
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(Asset.name).like(needle), func.lower(Asset.asset_key).like(needle)))
    column = OT_SORTS[sort]
    stmt = stmt.order_by(column.asc() if order == "asc" else column.desc(), Asset.id.asc())
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).all()

    zone_ids = {service.effective_zone_id(device, asset) for device, asset in rows}
    zones = {
        zone.id: zone
        for zone in ctx.db.execute(
            select(Zone).where(Zone.org_id == ctx.org.id, Zone.id.in_([item for item in zone_ids if item]))
        ).scalars()
    }
    items = [
        service.serialize_device(device, asset, zones.get(service.effective_zone_id(device, asset)))
        for device, asset in rows
    ]
    return Page[OTDeviceOut](**paginate(items, int(total), page, page_size))


@router.post("/devices", response_model=OTDeviceOut, status_code=201, summary="Register a passive OT device")
def create_device(
    payload: OTDeviceCreate, ctx: RequestContext = Depends(require_permission("asset:write"))
) -> OTDeviceOut:
    if not payload.passive_only:
        raise PolicyDenied(
            "passive_only must remain true for OT devices. Active control or polling of OT equipment is not supported.",
            details=[{"field": "passive_only", "message": "Only passive monitoring is permitted"}],
        )
    existing = ctx.db.execute(
        select(Asset).where(Asset.org_id == ctx.org.id, Asset.asset_key == payload.asset_key)
    ).scalar_one_or_none()
    if existing is not None:
        raise Conflict("An asset with this asset_key already exists")
    ensure_zone_exists(ctx.db, ctx.org.id, payload.zone_id)
    asset = Asset(
        org_id=ctx.org.id,
        **payload.model_dump(
            exclude={
                "metadata",
                "protocols",
                "safety_critical",
                "passive_only",
                "controller_model",
                "firmware_version",
            }
        ),
        metadata_json=payload.metadata,
    )
    ctx.db.add(asset)
    ctx.db.flush()
    device = OTDevice(
        asset_id=asset.id,
        org_id=ctx.org.id,
        protocols=payload.protocols,
        zone_id=payload.zone_id,
        safety_critical=payload.safety_critical,
        passive_only=True,
        controller_model=payload.controller_model,
        firmware_version=payload.firmware_version or payload.firmware,
        baseline={"metrics": {}, "samples": 0, "anomalies": 0},
    )
    ctx.db.add(device)
    ctx.db.flush()
    ctx.audit(
        action="ot.device.create",
        resource_type="ot_device",
        resource_id=str(asset.id),
        payload={
            "asset_key": asset.asset_key,
            "protocols": device.protocols,
            "zone_id": str(device.zone_id) if device.zone_id else None,
            "safety_critical": device.safety_critical,
        },
    )
    ctx.db.commit()
    ctx.db.refresh(device)
    ctx.db.refresh(asset)
    zone = ctx.db.get(Zone, device.zone_id) if device.zone_id else None
    return service.serialize_device(device, asset, zone)


@router.patch("/devices/{asset_id}", response_model=OTDeviceOut, summary="Update OT zone, protocols or safety flags")
def update_device(
    asset_id: UUID, payload: OTDevicePatch, ctx: RequestContext = Depends(require_permission("asset:write"))
) -> OTDeviceOut:
    asset, device = service.get_ot_device(ctx.db, ctx.org.id, asset_id)
    changes = payload.model_dump(exclude_unset=True)
    if changes.get("passive_only") is False:
        raise PolicyDenied(
            "passive_only cannot be disabled: HISPANSHIELD has no active OT control capability.",
            details=[{"field": "passive_only", "message": "Only passive monitoring is permitted"}],
        )
    if "zone_id" in changes:
        zone_id = changes["zone_id"]
        ensure_zone_exists(ctx.db, ctx.org.id, zone_id)
        device.zone_id = zone_id
        asset.zone_id = zone_id
    if "protocols" in changes and changes["protocols"] is not None:
        device.protocols = changes["protocols"]
    if "safety_critical" in changes and changes["safety_critical"] is not None:
        device.safety_critical = changes["safety_critical"]
    if "controller_model" in changes:
        device.controller_model = changes["controller_model"]
    if "firmware_version" in changes:
        device.firmware_version = changes["firmware_version"]
    asset.last_seen = utcnow()
    ctx.audit(
        action="ot.device.update",
        resource_type="ot_device",
        resource_id=str(asset.id),
        payload={"fields": sorted(changes.keys())},
    )
    ctx.db.commit()
    ctx.db.refresh(device)
    ctx.db.refresh(asset)
    zone = ctx.db.get(Zone, device.zone_id) if device.zone_id else None
    return service.serialize_device(device, asset, zone)


@router.get("/protocols", response_model=list[OTProtocolOut], summary="OT protocol registry with safety classes")
def list_protocols(ctx: RequestContext = Depends(require_permission("asset:read"))) -> list[OTProtocolOut]:
    return [OTProtocolOut(**entry) for entry in service.protocol_catalogue()]


@router.post("/telemetry", response_model=OTTelemetryResult, summary="Ingest passive OT telemetry")
def ingest_telemetry(
    payload: OTTelemetryBatch, ctx: RequestContext = Depends(require_permission("asset:write"))
) -> OTTelemetryResult:
    accepted = 0
    anomalies = 0
    alerts_created = 0
    alerts_deduplicated = 0
    unauthorized: set[str] = set()
    devices_updated: set[UUID] = set()
    now = utcnow()
    for item in payload.items:
        asset, device = service.locate_ot_asset(ctx.db, ctx.org.id, asset_id=item.asset_id, asset_key=item.asset_key)
        spec = ot_protocol_spec(item.protocol)
        if spec is None:
            raise ValidationFailure([{"field": "protocol", "message": f"Unsupported OT protocol: {item.protocol}"}])
        ensure_passive_metrics({item.metric: item.value}, context=f"ot telemetry for {asset.asset_key}")
        observed_at = item.observed_at or now
        if asset.last_seen is None or asset.last_seen < observed_at:
            asset.last_seen = observed_at
        if device.last_telemetry_at is None or device.last_telemetry_at < observed_at:
            device.last_telemetry_at = observed_at
        outcome = service.learn_and_detect(
            ctx.db,
            ctx.org.id,
            asset,
            device,
            protocol=spec["name"],
            metric=item.metric,
            value=item.value,
            observed_at=observed_at,
        )
        accepted += 1
        devices_updated.add(asset.id)
        if outcome.anomaly:
            anomalies += 1
            if outcome.reason == "unauthorized_protocol":
                unauthorized.add(spec["name"])
            if outcome.alert_created:
                alerts_created += 1
            if outcome.alert_deduplicated:
                alerts_deduplicated += 1

    ctx.audit(
        action="ot.telemetry.ingest",
        resource_type="ot_device",
        payload={
            "items": accepted,
            "devices": len(devices_updated),
            "anomalies": anomalies,
            "alerts_created": alerts_created,
            "alerts_deduplicated": alerts_deduplicated,
            "unauthorized_protocols": sorted(unauthorized),
        },
    )
    ctx.db.commit()
    return OTTelemetryResult(
        accepted=accepted,
        anomalies=anomalies,
        alerts_created=alerts_created,
        alerts_deduplicated=alerts_deduplicated,
        devices_updated=len(devices_updated),
        unauthorized_protocols=sorted(unauthorized),
    )


@router.get("/posture", response_model=OTPostureOut, summary="IEC 62443 zone/conduit posture")
def ot_posture(ctx: RequestContext = Depends(require_permission("asset:read"))) -> OTPostureOut:
    return service.posture(ctx.db, ctx.org.id)


__all__ = ["router"]
