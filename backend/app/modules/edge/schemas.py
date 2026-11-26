"""Pydantic contracts for edge gateway enrollment, telemetry and configuration."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, field_validator

from app.core.schemas import ORMModel, StrictModel

GatewayEventKind = Literal["network", "ot", "iot", "json"]
LogLevel = Literal["debug", "info", "warning", "error"]

FINGERPRINT_PATTERN = r"^[A-Za-z0-9:._-]{8,128}$"


class EnrollmentTokenOut(StrictModel):
    gateway_id: UUID
    token: str
    expires_at: datetime
    expires_in_seconds: int


class GatewayRegisterRequest(StrictModel):
    enrollment_token: str = Field(min_length=16, max_length=2048)
    fingerprint: str = Field(pattern=FINGERPRINT_PATTERN)
    name: str = Field(min_length=1, max_length=160)
    version: str | None = Field(default=None, max_length=40)
    certificate_serial: str | None = Field(default=None, max_length=120)


class SignedConfigBundle(StrictModel):
    bundle: dict[str, Any]
    signature: str
    algorithm: str = "HMAC-SHA256"


class GatewayRegisterResponse(StrictModel):
    gateway_id: UUID
    org_id: UUID
    fingerprint: str
    status: str
    enrolled_at: datetime
    shared_key: str
    config_bundle: SignedConfigBundle


class HeartbeatRequest(StrictModel):
    version: str | None = Field(default=None, max_length=40)
    buffer_stats: dict[str, Any] = Field(default_factory=dict)
    status: str | None = Field(default=None, max_length=20)

    @field_validator("buffer_stats")
    @classmethod
    def _bound_stats(cls, value: dict[str, Any]) -> dict[str, Any]:
        if len(value) > 32:
            raise ValueError("buffer_stats accepts at most 32 keys")
        for key, item in value.items():
            if len(str(key)) > 60:
                raise ValueError("buffer_stats keys must be at most 60 characters")
            if isinstance(item, str) and len(item) > 500:
                raise ValueError("buffer_stats string values must be at most 500 characters")
        return value


class HeartbeatResponse(StrictModel):
    ok: bool
    server_time: datetime
    cursor: int
    next_heartbeat_seconds: int
    config_version: str


class GatewayEventEnvelope(StrictModel):
    sequence: int = Field(ge=0, le=9_223_372_036_854_775_807)
    kind: GatewayEventKind = "json"
    events: list[dict[str, Any]] = Field(min_length=1, max_length=500)
    batch_id: str | None = Field(default=None, max_length=80)

    @field_validator("events")
    @classmethod
    def _bound_events(cls, value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for item in value:
            if not isinstance(item, dict):
                raise ValueError("Each event must be a JSON object")
        return value


class GatewayEventIngestResult(StrictModel):
    accepted: bool
    sequence: int
    processed: int
    duplicates: int
    cursor: int


class GatewayConfigPatch(StrictModel):
    """Server-side allow-list: unknown keys are rejected, so a gateway cannot
    alter central policy, autonomy or permissions through configuration."""

    buffer_max_events: int | None = Field(default=None, ge=100, le=1_000_000)
    batch_size: int | None = Field(default=None, ge=1, le=1000)
    flush_interval_seconds: int | None = Field(default=None, ge=5, le=3600)
    heartbeat_interval_seconds: int | None = Field(default=None, ge=15, le=3600)
    log_level: LogLevel | None = None
    collectors: list[str] | None = Field(default=None, max_length=20)
    store_forward: bool | None = None
    allow_remote_config: bool | None = None
    tags: list[str] | None = Field(default=None, max_length=20)

    @field_validator("collectors", "tags")
    @classmethod
    def _validate_list(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        cleaned: list[str] = []
        for item in value:
            token = item.strip().lower()
            if not token:
                continue
            if len(token) > 40 or not token.replace("-", "").replace("_", "").isalnum():
                raise ValueError("Collector and tag values must be short alphanumeric identifiers")
            if token not in cleaned:
                cleaned.append(token)
        return cleaned


class GatewayOut(ORMModel):
    id: UUID
    org_id: UUID
    name: str
    fingerprint: str
    status: str
    version: str | None
    last_seen_at: datetime | None
    enrolled_at: datetime | None
    revoked_at: datetime | None
    certificate_serial: str | None
    config: dict[str, Any]
    buffer_stats: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class GatewayRotateKeyResult(StrictModel):
    gateway_id: UUID
    shared_key: str
    key_id: str
    rotated_at: datetime


class GatewayIngestEventOut(ORMModel):
    id: UUID
    gateway_id: UUID
    kind: str
    sequence: int
    signature_valid: bool
    accepted: bool
    rejection_reason: str | None
    processed_count: int
    payload: dict[str, Any]
    received_at: datetime


__all__ = [
    "EnrollmentTokenOut",
    "GatewayConfigPatch",
    "GatewayEventEnvelope",
    "GatewayEventIngestResult",
    "GatewayIngestEventOut",
    "GatewayOut",
    "GatewayRegisterRequest",
    "GatewayRegisterResponse",
    "GatewayRotateKeyResult",
    "HeartbeatRequest",
    "HeartbeatResponse",
    "SignedConfigBundle",
]
