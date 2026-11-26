"""Pydantic contracts for OT devices, passive telemetry and IEC 62443 posture."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.core.schemas import StrictModel
from app.modules.assets.schemas import AssetCreate, AssetRef
from app.modules.ot.protocols import canonical_ot_protocol_list

OT_METRIC_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,80}$")
MAX_OT_TELEMETRY_ITEMS = 200


def _protocols(values: list[str]) -> list[str]:
    if len(values) > 20:
        raise ValueError("protocols supports at most 20 entries")
    try:
        return canonical_ot_protocol_list(values)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc


class OTDeviceCreate(AssetCreate):
    """Create an OT asset; passive-only and safety-critical default to true."""

    kind: str = Field(default="ot", pattern="^ot$")
    protocols: list[str] = Field(default_factory=list, max_length=20)
    safety_critical: bool = True
    passive_only: bool = True
    controller_model: str | None = Field(default=None, max_length=160)
    firmware_version: str | None = Field(default=None, max_length=120)

    @field_validator("protocols")
    @classmethod
    def _validate_protocols(cls, value: list[str]) -> list[str]:
        return _protocols(value)


class OTDevicePatch(StrictModel):
    zone_id: UUID | None = None
    protocols: list[str] | None = Field(default=None, max_length=20)
    safety_critical: bool | None = None
    passive_only: bool | None = None
    controller_model: str | None = Field(default=None, max_length=160)
    firmware_version: str | None = Field(default=None, max_length=120)

    @field_validator("protocols")
    @classmethod
    def _validate_protocols(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _protocols(value)


class OTDeviceOut(StrictModel):
    asset_id: UUID
    asset: AssetRef
    zone_id: UUID | None
    zone_name: str | None
    protocols: list[str]
    safety_critical: bool
    passive_only: bool
    controller_model: str | None
    firmware_version: str | None
    last_telemetry_at: datetime | None
    baseline: dict[str, Any]
    risk_flags: list[str]


class OTProtocolOut(StrictModel):
    name: str
    family: str
    default_ports: list[int]
    safety_class: str
    support_level: str
    passive_only_default: bool
    security_notes: str
    active_operations_denied: list[str]


class OTTelemetryItem(StrictModel):
    asset_id: UUID | None = None
    asset_key: str | None = Field(default=None, min_length=1, max_length=200)
    protocol: str = Field(min_length=1, max_length=40)
    metric: str = Field(min_length=1, max_length=80)
    value: float | str
    observed_at: datetime | None = None

    @field_validator("metric")
    @classmethod
    def _metric(cls, value: str) -> str:
        if not OT_METRIC_RE.match(value):
            raise ValueError("Invalid metric name")
        return value

    @field_validator("value")
    @classmethod
    def _value(cls, value: float | str) -> float | str:
        if isinstance(value, str) and len(value) > 400:
            raise ValueError("String values are limited to 400 characters")
        if isinstance(value, float) and (value != value or value in (float("inf"), float("-inf"))):
            raise ValueError("Numeric telemetry must be finite")
        return value

    @field_validator("observed_at")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    @model_validator(mode="after")
    def _asset_reference(self) -> OTTelemetryItem:
        if self.asset_id is None and not self.asset_key:
            raise ValueError("Provide asset_id or asset_key")
        return self


class OTTelemetryBatch(StrictModel):
    items: list[OTTelemetryItem] = Field(min_length=1, max_length=MAX_OT_TELEMETRY_ITEMS)


class OTTelemetryResult(StrictModel):
    accepted: int
    anomalies: int
    alerts_created: int
    alerts_deduplicated: int
    devices_updated: int
    unauthorized_protocols: list[str]


class OTZonePostureOut(StrictModel):
    zone_id: UUID
    name: str
    kind: str
    purdue_level: int | None
    devices: int
    safety_critical: int


class OTPostureOut(StrictModel):
    ot_devices_total: int
    ot_devices_zoned: int
    unzoned_devices: int
    safety_critical_devices: int
    monitored_devices: int
    unmonitored_devices: int
    zones_total: int
    conduits_total: int
    purdue_documented_zones: int
    zone_coverage_pct: float
    conduit_coverage_pct: float
    posture_level: str
    iec62443: dict[str, Any]
    zone_breakdown: list[OTZonePostureOut]


__all__ = [
    "MAX_OT_TELEMETRY_ITEMS",
    "OTDeviceCreate",
    "OTDeviceOut",
    "OTDevicePatch",
    "OTPostureOut",
    "OTProtocolOut",
    "OTTelemetryBatch",
    "OTTelemetryItem",
    "OTTelemetryResult",
    "OTZonePostureOut",
]
