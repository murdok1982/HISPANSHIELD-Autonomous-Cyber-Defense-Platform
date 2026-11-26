"""IoT device helpers: passive-only enforcement, serialisation and posture."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.core.errors import NotFound, PolicyDenied, ValidationFailure
from app.models.assets import Asset, AssetIdentity, IoTDevice
from app.modules.assets.schemas import AssetRef
from app.modules.iot.protocols import IOT_PROTOCOLS, protocol_spec
from app.modules.iot.schemas import IoTDeviceOut

# Keys that would turn a telemetry write into an active control operation.
# HISPANSHIELD has no actuator path: attempting one is a policy violation, not
# a validation nuisance, because a compromised integration could otherwise be
# used to move physical equipment.
FORBIDDEN_METRIC_KEYS = {
    "command",
    "cmd",
    "actuate",
    "actuation",
    "action",
    "operation",
    "setpoint",
    "set_point",
    "setpoint_write",
    "reboot",
    "restart",
    "shutdown",
    "firmware_update",
    "firmware_write",
    "write_register",
    "write_coils",
    "write_coil",
    "write_request",
    "output_override",
    "direct_control",
    "relay_state_write",
}
FORBIDDEN_OPERATION_VALUES = {"write", "command", "cmd", "actuate", "reboot", "restart", "firmware_update"}
FORBIDDEN_KEY_PREFIXES = ("write_", "set_", "cmd_", "command_")

PLAINTEXT_CAPABLE = {"MQTT", "CoAP", "HTTP/HTTPS", "AMQP"}
STALE_AFTER = timedelta(hours=24)


def _normalized_tokens(key: str) -> set[str]:
    return {token for token in re.split(r"[^a-z0-9]+", key.lower()) if token}


def ensure_passive_metrics(metrics: dict[str, Any], *, context: str) -> None:
    """Reject telemetry that encodes an active command.

    This is the single choke-point for the passive-monitoring invariant: every
    ingestion path (IoT and OT) calls it before persisting anything.
    """
    for key, value in metrics.items():
        lowered = key.strip().lower()
        if (
            lowered in FORBIDDEN_METRIC_KEYS
            or lowered.startswith(FORBIDDEN_KEY_PREFIXES)
            or bool(_normalized_tokens(lowered) & {"command", "cmd", "actuate", "reboot", "setpoint"})
        ):
            raise PolicyDenied(
                f"Active command rejected in {context}: '{key}'. HISPANSHIELD is passive-only for IoT/OT telemetry."
            )
        if (
            isinstance(value, str)
            and lowered in {"operation", "op", "action", "mode"}
            and value.strip().lower() in FORBIDDEN_OPERATION_VALUES
        ):
            raise PolicyDenied(
                f"Active operation '{value}' rejected in {context}. Passive monitoring only; no writes are allowed."
            )


def get_iot_device(db: Session, org_id: UUID, asset_id: UUID) -> tuple[Asset, IoTDevice]:
    asset = db.get(Asset, asset_id)
    if asset is None or asset.org_id != org_id or asset.kind != "iot":
        raise NotFound("IoT device")
    device = db.execute(
        select(IoTDevice).where(IoTDevice.asset_id == asset.id, IoTDevice.org_id == org_id)
    ).scalar_one_or_none()
    if device is None:
        raise NotFound("IoT device")
    return asset, device


def locate_iot_asset(
    db: Session, org_id: UUID, *, asset_id: UUID | None, asset_key: str | None
) -> tuple[Asset, IoTDevice]:
    asset: Asset | None = None
    if asset_id is not None:
        asset = db.get(Asset, asset_id)
    elif asset_key:
        asset = db.execute(
            select(Asset).where(Asset.org_id == org_id, Asset.asset_key == asset_key)
        ).scalar_one_or_none()
    if asset is None or asset.org_id != org_id:
        raise NotFound("IoT device")
    if asset.kind != "iot":
        raise ValidationFailure([{"field": "asset_id", "message": "Asset is not of kind iot"}])
    device = db.execute(
        select(IoTDevice).where(IoTDevice.asset_id == asset.id, IoTDevice.org_id == org_id)
    ).scalar_one_or_none()
    if device is None:
        raise NotFound("IoT device profile")
    return asset, device


def upsert_identity(db: Session, asset: Asset, *, kind: str, value: str, confidence: int = 90) -> int:
    """Best-effort identity enrichment; returns 1 when a row was created/updated."""
    if not value:
        return 0
    value = value.strip()[:400]
    existing = db.execute(
        select(AssetIdentity).where(
            AssetIdentity.asset_id == asset.id, AssetIdentity.kind == kind, AssetIdentity.value == value
        )
    ).scalar_one_or_none()
    if existing is not None:
        if confidence > existing.confidence:
            existing.confidence = confidence
            return 1
        return 0
    db.add(AssetIdentity(asset_id=asset.id, kind=kind, value=value, confidence=confidence))
    db.flush()
    return 1


def risk_flags(device: IoTDevice, asset: Asset, *, now: datetime | None = None) -> list[str]:
    now = now or utcnow()
    flags: set[str] = set()
    protocols = device.protocols or []
    posture = device.security_posture or {}
    if not protocols:
        flags.add("no_protocol_declared")
    if any(protocol in PLAINTEXT_CAPABLE for protocol in protocols):
        flags.add("plaintext_capable")
    if posture.get("tls") is False:
        flags.add("tls_disabled")
    if posture.get("default_credentials") is True:
        flags.add("default_credentials")
    if posture.get("firmware_eol") is True:
        flags.add("end_of_life_firmware")
    if device.last_telemetry_at is None:
        flags.add("no_telemetry")
    else:
        last = device.last_telemetry_at
        if last.tzinfo is None:
            last = last.replace(tzinfo=UTC)
        if now - last > STALE_AFTER:
            flags.add("telemetry_stale")
    if not device.firmware_version and not asset.firmware:
        flags.add("unknown_firmware")
    return sorted(flags)


def serialize_device(device: IoTDevice, asset: Asset) -> IoTDeviceOut:
    return IoTDeviceOut(
        asset_id=device.asset_id,
        asset=AssetRef.model_validate(asset),
        protocols=list(device.protocols or []),
        connectivity=device.connectivity,
        edge_gateway_id=device.edge_gateway_id,
        firmware_version=device.firmware_version,
        last_telemetry_at=device.last_telemetry_at,
        security_posture=dict(device.security_posture or {}),
        risk_flags=risk_flags(device, asset),
    )


def protocol_catalogue() -> list[dict[str, Any]]:
    return [dict(entry) for entry in IOT_PROTOCOLS]


def summarize_devices(db: Session, org_id: UUID) -> dict[str, Any]:
    rows = db.execute(
        select(IoTDevice, Asset).join(Asset, Asset.id == IoTDevice.asset_id).where(IoTDevice.org_id == org_id)
    ).all()
    stale = 0
    without_protocols = 0
    by_connectivity: dict[str, int] = {}
    by_protocol: dict[str, int] = {}
    by_support: dict[str, int] = {}
    flag_counts: dict[str, int] = {}
    now = utcnow()
    for device, asset in rows:
        flags = risk_flags(device, asset, now=now)
        for flag in flags:
            flag_counts[flag] = flag_counts.get(flag, 0) + 1
        if "telemetry_stale" in flags or "no_telemetry" in flags:
            stale += 1
        protocols = list(device.protocols or [])
        if not protocols:
            without_protocols += 1
        for protocol in protocols:
            by_protocol[protocol] = by_protocol.get(protocol, 0) + 1
            spec = protocol_spec(protocol)
            level = spec["support_level"] if spec else "unknown"
            by_support[level] = by_support.get(level, 0) + 1
        connectivity = device.connectivity or "unknown"
        by_connectivity[connectivity] = by_connectivity.get(connectivity, 0) + 1
    return {
        "total_devices": len(rows),
        "stale_devices": stale,
        "without_protocols": without_protocols,
        "by_connectivity": by_connectivity,
        "by_protocol": by_protocol,
        "by_support_level": by_support,
        "risk_flag_counts": flag_counts,
    }


__all__ = [
    "FORBIDDEN_METRIC_KEYS",
    "STALE_AFTER",
    "ensure_passive_metrics",
    "get_iot_device",
    "locate_iot_asset",
    "protocol_catalogue",
    "risk_flags",
    "serialize_device",
    "summarize_devices",
    "upsert_identity",
]
