"""IoT inventory and passive telemetry endpoints."""

from __future__ import annotations

import ipaddress
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, or_, select

from app.core.db import utcnow
from app.core.deps import RequestContext, require_permission
from app.core.errors import Conflict, NotFound, ValidationFailure
from app.core.schemas import Page, paginate
from app.models.assets import Asset, IoTDevice
from app.models.edge import EdgeGateway
from app.modules.assets.schemas import HOSTNAME_RE, MAC_RE, AssetRef
from app.modules.assets.service import ensure_zone_exists
from app.modules.iot import service
from app.modules.iot.protocols import protocol_spec
from app.modules.iot.schemas import (
    IoTDeviceCreate,
    IoTDeviceOut,
    IoTDevicePatch,
    IoTProtocolOut,
    IoTSummaryOut,
    IoTTelemetryBatch,
    IoTTelemetryResult,
)

router = APIRouter(prefix="/iot", tags=["IoT Security"])

DEVICE_SORTS = {
    "name": Asset.name,
    "criticality": Asset.criticality,
    "last_seen": Asset.last_seen,
    "last_telemetry_at": IoTDevice.last_telemetry_at,
    "connectivity": IoTDevice.connectivity,
}

IOT_FIELDS = {"protocols", "connectivity", "edge_gateway_id", "firmware_version", "security_posture"}


def _ensure_edge_gateway(db, org_id: UUID, gateway_id: UUID | None) -> None:
    if gateway_id is None:
        return
    gateway = db.get(EdgeGateway, gateway_id)
    if gateway is None or gateway.org_id != org_id:
        raise NotFound("Edge gateway")


def _observed_identity(metric: str, value: object) -> tuple[str, str] | None:
    lowered = metric.strip().lower()
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or len(candidate) > 400:
        return None
    if lowered in {"ip", "ip_address", "ipv4", "ipv6"}:
        try:
            return "ip", str(ipaddress.ip_address(candidate))
        except ValueError:
            return None
    if lowered in {"mac", "mac_address"}:
        return ("mac", candidate.upper()) if MAC_RE.match(candidate) else None
    if lowered in {"hostname", "host", "fqdn"}:
        return ("hostname", candidate.lower()) if HOSTNAME_RE.match(candidate) else None
    return None


@router.get("/devices", response_model=Page[IoTDeviceOut], summary="List IoT devices")
def list_devices(
    ctx: RequestContext = Depends(require_permission("asset:read")),
    q: str | None = Query(default=None, max_length=200),
    connectivity: str | None = Query(default=None, max_length=80),
    protocol: str | None = Query(default=None, max_length=40),
    zone_id: UUID | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    sort: str = Query(default="last_seen", pattern="^(" + "|".join(DEVICE_SORTS) + ")$"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
) -> Page[IoTDeviceOut]:
    stmt = (
        select(IoTDevice, Asset)
        .join(Asset, Asset.id == IoTDevice.asset_id)
        .where(IoTDevice.org_id == ctx.org.id, Asset.org_id == ctx.org.id)
    )
    if connectivity:
        stmt = stmt.where(IoTDevice.connectivity == connectivity)
    if protocol:
        canonical = protocol_spec(protocol)
        if canonical is None:
            raise ValidationFailure([{"field": "protocol", "message": f"Unsupported IoT protocol: {protocol}"}])
        stmt = stmt.where(IoTDevice.protocols.contains([canonical["name"]]))
    if zone_id:
        stmt = stmt.where(Asset.zone_id == zone_id)
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(Asset.name).like(needle), func.lower(Asset.asset_key).like(needle)))
    column = DEVICE_SORTS[sort]
    stmt = stmt.order_by(column.asc() if order == "asc" else column.desc(), Asset.id.asc())
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).all()
    items = []
    for device, asset in rows:
        items.append(
            IoTDeviceOut(
                asset_id=device.asset_id,
                asset=AssetRef.model_validate(asset),
                protocols=list(device.protocols or []),
                connectivity=device.connectivity,
                edge_gateway_id=device.edge_gateway_id,
                firmware_version=device.firmware_version,
                last_telemetry_at=device.last_telemetry_at,
                security_posture=dict(device.security_posture or {}),
                risk_flags=service.risk_flags(device, asset),
            )
        )
    return Page[IoTDeviceOut](**paginate(items, int(total), page, page_size))


@router.post("/devices", response_model=IoTDeviceOut, status_code=201, summary="Register an IoT device")
def create_device(
    payload: IoTDeviceCreate, ctx: RequestContext = Depends(require_permission("asset:write"))
) -> IoTDeviceOut:
    existing = ctx.db.execute(
        select(Asset).where(Asset.org_id == ctx.org.id, Asset.asset_key == payload.asset_key)
    ).scalar_one_or_none()
    if existing is not None:
        raise Conflict("An asset with this asset_key already exists")
    ensure_zone_exists(ctx.db, ctx.org.id, payload.zone_id)
    _ensure_edge_gateway(ctx.db, ctx.org.id, payload.edge_gateway_id)
    asset = Asset(
        org_id=ctx.org.id,
        **payload.model_dump(
            exclude={"metadata", "protocols", "connectivity", "edge_gateway_id", "firmware_version", "security_posture"}
        ),
        metadata_json=payload.metadata,
    )
    ctx.db.add(asset)
    ctx.db.flush()
    device = IoTDevice(
        asset_id=asset.id,
        org_id=ctx.org.id,
        protocols=payload.protocols,
        connectivity=payload.connectivity,
        edge_gateway_id=payload.edge_gateway_id,
        firmware_version=payload.firmware_version or payload.firmware,
        security_posture=payload.security_posture,
    )
    ctx.db.add(device)
    ctx.db.flush()
    ctx.audit(
        action="iot.device.create",
        resource_type="iot_device",
        resource_id=str(asset.id),
        payload={"asset_key": asset.asset_key, "protocols": device.protocols, "connectivity": device.connectivity},
    )
    ctx.db.commit()
    ctx.db.refresh(device)
    ctx.db.refresh(asset)
    return service.serialize_device(device, asset)


@router.patch("/devices/{asset_id}", response_model=IoTDeviceOut, summary="Update an IoT device")
def update_device(
    asset_id: UUID, payload: IoTDevicePatch, ctx: RequestContext = Depends(require_permission("asset:write"))
) -> IoTDeviceOut:
    asset, device = service.get_iot_device(ctx.db, ctx.org.id, asset_id)
    changes = payload.model_dump(exclude_unset=True)
    if "zone_id" in changes and changes["zone_id"] is not None:
        ensure_zone_exists(ctx.db, ctx.org.id, changes["zone_id"])
    if "edge_gateway_id" in changes:
        _ensure_edge_gateway(ctx.db, ctx.org.id, changes["edge_gateway_id"])
    for field, value in changes.items():
        if field in IOT_FIELDS:
            if field == "security_posture":
                device.security_posture = value or {}
            else:
                setattr(device, field, value)
            continue
        if field == "metadata":
            if value is not None:
                asset.metadata_json = value
            continue
        setattr(asset, field, value)
    if device.firmware_version is None:
        device.firmware_version = asset.firmware
    asset.last_seen = utcnow()
    ctx.audit(
        action="iot.device.update",
        resource_type="iot_device",
        resource_id=str(asset.id),
        payload={"fields": sorted(changes.keys())},
    )
    ctx.db.commit()
    ctx.db.refresh(device)
    ctx.db.refresh(asset)
    return service.serialize_device(device, asset)


@router.delete("/devices/{asset_id}", status_code=204, response_class=Response, summary="Delete an IoT device")
def delete_device(asset_id: UUID, ctx: RequestContext = Depends(require_permission("asset:write"))) -> Response:
    asset, _device = service.get_iot_device(ctx.db, ctx.org.id, asset_id)
    ctx.audit(
        action="iot.device.delete",
        resource_type="iot_device",
        resource_id=str(asset.id),
        payload={"asset_key": asset.asset_key},
    )
    ctx.db.delete(asset)
    ctx.db.commit()
    return Response(status_code=204)


@router.post("/telemetry", response_model=IoTTelemetryResult, summary="Ingest passive IoT telemetry")
def ingest_telemetry(
    payload: IoTTelemetryBatch, ctx: RequestContext = Depends(require_permission("asset:write"))
) -> IoTTelemetryResult:
    """Store observations only.

    The handler refuses payloads that encode actuator commands (see
    ``service.ensure_passive_metrics``). No outbound connection is ever made to
    the device and no configuration is pushed.
    """
    identities_upserted = 0
    protocols: set[str] = set()
    device_ids: set[UUID] = set()
    now = utcnow()
    for item in payload.items:
        asset, device = service.locate_iot_asset(ctx.db, ctx.org.id, asset_id=item.asset_id, asset_key=item.asset_key)
        spec = protocol_spec(item.protocol)
        if spec is None:
            raise ValidationFailure([{"field": "protocol", "message": f"Unsupported IoT protocol: {item.protocol}"}])
        service.ensure_passive_metrics(item.metrics, context=f"iot telemetry for {asset.asset_key}")
        observed_at = item.observed_at or now
        if asset.last_seen is None or asset.last_seen < observed_at:
            asset.last_seen = observed_at
        if device.last_telemetry_at is None or device.last_telemetry_at < observed_at:
            device.last_telemetry_at = observed_at
        identities_upserted += service.upsert_identity(
            ctx.db, asset, kind="telemetry_protocol", value=spec["name"], confidence=90
        )
        for metric, value in item.metrics.items():
            observed = _observed_identity(metric, value)
            if observed is not None:
                identities_upserted += service.upsert_identity(
                    ctx.db, asset, kind=observed[0], value=observed[1], confidence=85
                )
        protocols.add(spec["name"])
        device_ids.add(asset.id)

    ctx.audit(
        action="iot.telemetry.ingest",
        resource_type="iot_device",
        payload={
            "items": len(payload.items),
            "devices": len(device_ids),
            "protocols": sorted(protocols),
            "identities_upserted": identities_upserted,
        },
    )
    ctx.db.commit()
    return IoTTelemetryResult(
        accepted=len(payload.items),
        devices_updated=len(device_ids),
        identities_upserted=identities_upserted,
        protocols=sorted(protocols),
    )


@router.get("/protocols", response_model=list[IoTProtocolOut], summary="IoT protocol registry")
def list_protocols(ctx: RequestContext = Depends(require_permission("asset:read"))) -> list[IoTProtocolOut]:
    return [IoTProtocolOut(**entry) for entry in service.protocol_catalogue()]


@router.get("/summary", response_model=IoTSummaryOut, summary="IoT fleet posture summary")
def iot_summary(ctx: RequestContext = Depends(require_permission("asset:read"))) -> IoTSummaryOut:
    return IoTSummaryOut(**service.summarize_devices(ctx.db, ctx.org.id))


__all__ = ["router"]
