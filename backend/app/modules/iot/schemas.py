"""Pydantic contracts for IoT devices and passive telemetry."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.core.schemas import StrictModel
from app.modules.assets.schemas import AssetCreate, AssetPatch, AssetRef, _clean_metadata
from app.modules.iot.protocols import canonical_protocol_list

METRIC_KEY_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
MAX_METRICS = 50
MAX_TELEMETRY_ITEMS = 200


def _validate_protocols(values: list[str]) -> list[str]:
    if len(values) > 16:
        raise ValueError("protocols supports at most 16 entries")
    try:
        return canonical_protocol_list(values)
    except ValueError as exc:
        raise ValueError(str(exc)) from exc


def _validate_posture(value: dict[str, Any]) -> dict[str, Any]:
    return _clean_metadata(value)


class IoTDeviceCreate(AssetCreate):
    """Create the Asset (kind=iot) and its IoT profile in one transaction."""

    kind: str = Field(default="iot", pattern="^iot$")
    protocols: list[str] = Field(default_factory=list, max_length=16)
    connectivity: str | None = Field(default=None, max_length=80)
    edge_gateway_id: UUID | None = None
    firmware_version: str | None = Field(default=None, max_length=120)
    security_posture: dict[str, Any] = Field(default_factory=dict)

    @field_validator("protocols")
    @classmethod
    def _protocols(cls, value: list[str]) -> list[str]:
        return _validate_protocols(value)

    @field_validator("security_posture")
    @classmethod
    def _posture(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_posture(value)


class IoTDevicePatch(AssetPatch):
    protocols: list[str] | None = Field(default=None, max_length=16)
    connectivity: str | None = Field(default=None, max_length=80)
    edge_gateway_id: UUID | None = None
    firmware_version: str | None = Field(default=None, max_length=120)
    security_posture: dict[str, Any] | None = None

    @field_validator("protocols")
    @classmethod
    def _protocols(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _validate_protocols(value)

    @field_validator("security_posture")
    @classmethod
    def _posture(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return None if value is None else _validate_posture(value)


class IoTDeviceOut(StrictModel):
    asset_id: UUID
    asset: AssetRef
    protocols: list[str]
    connectivity: str | None
    edge_gateway_id: UUID | None
    firmware_version: str | None
    last_telemetry_at: datetime | None
    security_posture: dict[str, Any]
    risk_flags: list[str]


class IoTProtocolOut(StrictModel):
    name: str
    family: str
    default_ports: list[int]
    read_only_default: bool
    security_notes: str
    support_level: str


class IoTTelemetryItem(StrictModel):
    asset_id: UUID | None = None
    asset_key: str | None = Field(default=None, min_length=1, max_length=200)
    protocol: str = Field(min_length=1, max_length=40)
    observed_at: datetime | None = None
    metrics: dict[str, Any] = Field(min_length=1)

    @field_validator("metrics")
    @classmethod
    def _metrics(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > MAX_METRICS:
            raise ValueError(f"metrics supports at most {MAX_METRICS} entries")
        for key, item in value.items():
            if not METRIC_KEY_RE.match(key):
                raise ValueError(f"Invalid metric name: {key}")
            if isinstance(item, dict | list | tuple | set):
                raise ValueError(f"Metric {key} must be a scalar value")
            if isinstance(item, str) and len(item) > 400:
                raise ValueError(f"Metric {key} exceeds 400 characters")
        return value

    @field_validator("observed_at")
    @classmethod
    def _aware(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    @model_validator(mode="after")
    def _asset_reference(self) -> IoTTelemetryItem:
        if self.asset_id is None and not self.asset_key:
            raise ValueError("Provide asset_id or asset_key")
        return self


class IoTTelemetryBatch(StrictModel):
    items: list[IoTTelemetryItem] = Field(min_length=1, max_length=MAX_TELEMETRY_ITEMS)


class IoTTelemetryResult(StrictModel):
    accepted: int
    devices_updated: int
    identities_upserted: int
    protocols: list[str]


class IoTSummaryOut(StrictModel):
    total_devices: int
    stale_devices: int
    without_protocols: int
    by_connectivity: dict[str, int]
    by_protocol: dict[str, int]
    by_support_level: dict[str, int]
    risk_flag_counts: dict[str, int]


__all__ = [
    "IoTDeviceCreate",
    "IoTDeviceOut",
    "IoTDevicePatch",
    "IoTProtocolOut",
    "IoTSummaryOut",
    "IoTTelemetryBatch",
    "IoTTelemetryItem",
    "IoTTelemetryResult",
    "MAX_TELEMETRY_ITEMS",
]
