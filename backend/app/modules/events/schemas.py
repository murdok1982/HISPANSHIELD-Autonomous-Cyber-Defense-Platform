"""Event fabric and ingestion API contracts."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.core.schemas import ORMModel, StrictModel
from app.services.normalization.ocsf import identify_domain, identify_ip

_SEVERITY_WORDS = {
    "unknown",
    "info",
    "informational",
    "information",
    "debug",
    "trace",
    "low",
    "minor",
    "notice",
    "medium",
    "moderate",
    "warn",
    "warning",
    "high",
    "major",
    "error",
    "critical",
    "crit",
    "fatal",
    "emergency",
    "emerg",
    "alert",
}


def _bounded_json(value: dict[str, Any] | None, *, max_bytes: int, field_name: str) -> dict[str, Any] | None:
    if value is None:
        return None
    try:
        encoded = json.dumps(value, default=str)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be JSON serialisable") from exc
    if len(encoded.encode("utf-8")) > max_bytes:
        raise ValueError(f"{field_name} exceeds {max_bytes} bytes")
    return value


class IngestSourceCreate(StrictModel):
    name: str = Field(min_length=2, max_length=160)
    kind: Literal["api", "webhook", "syslog"] = "api"
    parser: Literal["auto", "json", "cef", "leef", "syslog", "otel"] = "auto"
    enabled: bool = True
    connector_id: UUID | None = None
    config: dict[str, Any] = Field(default_factory=dict)
    generate_hmac_secret: bool = False
    hmac_secret: str | None = Field(default=None, min_length=16, max_length=256)

    @field_validator("config")
    @classmethod
    def _config_bounded(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _bounded_json(value, max_bytes=8192, field_name="config") or {}

    @field_validator("hmac_secret")
    @classmethod
    def _secret_clean(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if any(ord(char) < 32 for char in value):
            raise ValueError("hmac_secret contains control characters")
        return value

    @model_validator(mode="after")
    def _secret_mode(self) -> IngestSourceCreate:
        if self.generate_hmac_secret and self.hmac_secret:
            raise ValueError("Provide either hmac_secret or generate_hmac_secret, not both")
        return self


class IngestSourcePatch(StrictModel):
    name: str | None = Field(default=None, min_length=2, max_length=160)
    parser: Literal["auto", "json", "cef", "leef", "syslog", "otel"] | None = None
    enabled: bool | None = None
    config: dict[str, Any] | None = None

    @field_validator("config")
    @classmethod
    def _config_bounded(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return _bounded_json(value, max_bytes=8192, field_name="config")


class IngestSourceOut(StrictModel):
    id: UUID
    org_id: UUID
    name: str
    kind: str
    parser: str
    enabled: bool
    connector_id: UUID | None = None
    config: dict[str, Any] = Field(default_factory=dict)
    last_event_at: datetime | None = None
    event_count: int = 0
    created_by: str | None = None
    created_at: datetime
    updated_at: datetime
    has_token: bool
    has_hmac_secret: bool


class IngestSourceCreated(IngestSourceOut):
    token: str = Field(description="Raw ingestion token. Returned exactly once.")
    hmac_secret: str | None = Field(default=None, description="Raw HMAC secret. Returned exactly once.")


class IngestSourceTokenRotated(StrictModel):
    id: UUID
    token: str
    rotated_at: datetime


class EventIngestItem(StrictModel):
    occurred_at: datetime | None = None
    severity: int | str | None = None
    class_uid: int | None = Field(default=None, ge=0, le=99999)
    class_name: str | None = Field(default=None, max_length=80)
    category_uid: int | None = Field(default=None, ge=0, le=99)
    activity_id: int | None = Field(default=None, ge=0, le=999)
    status_id: int | None = Field(default=None, ge=0, le=2)
    message: str = Field(min_length=1, max_length=20000)
    src_ip: str | None = Field(default=None, max_length=64)
    dst_ip: str | None = Field(default=None, max_length=64)
    src_port: int | None = Field(default=None, ge=0, le=65535)
    dst_port: int | None = Field(default=None, ge=0, le=65535)
    protocol: str | None = Field(default=None, max_length=30)
    user_name: str | None = Field(default=None, max_length=200)
    host_name: str | None = Field(default=None, max_length=255)
    process_name: str | None = Field(default=None, max_length=255)
    file_hash_sha256: str | None = Field(default=None, max_length=64)
    url: str | None = Field(default=None, max_length=2048)
    domain: str | None = Field(default=None, max_length=255)
    action: str | None = Field(default=None, max_length=200)
    outcome: str | None = Field(default=None, max_length=80)
    category: str | None = Field(default=None, max_length=120)
    bytes_in: int | None = Field(default=None, ge=0)
    bytes_out: int | None = Field(default=None, ge=0)
    raw: dict[str, Any] | None = None
    normalized: dict[str, Any] | None = None

    @field_validator("severity")
    @classmethod
    def _severity_valid(cls, value: int | str | None) -> int | str | None:
        if value is None:
            return None
        if isinstance(value, bool):
            raise ValueError("severity must be an integer 0..5 or a label")
        if isinstance(value, int):
            if not 0 <= value <= 5:
                raise ValueError("severity must be between 0 and 5")
            return value
        if value.strip().lower() not in _SEVERITY_WORDS:
            raise ValueError("Unknown severity label")
        return value.strip().lower()

    @field_validator("src_ip", "dst_ip")
    @classmethod
    def _ip_valid(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        normalized = identify_ip(value)
        if normalized is None:
            raise ValueError("Invalid IP address")
        return normalized

    @field_validator("domain")
    @classmethod
    def _domain_valid(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        normalized = identify_domain(value)
        if normalized is None:
            raise ValueError("Invalid domain name")
        return normalized

    @field_validator("file_hash_sha256")
    @classmethod
    def _hash_valid(cls, value: str | None) -> str | None:
        if value is None or value == "":
            return None
        candidate = value.strip().lower()
        if len(candidate) != 64 or any(char not in "0123456789abcdef" for char in candidate):
            raise ValueError("file_hash_sha256 must be 64 hexadecimal characters")
        return candidate

    @field_validator("occurred_at")
    @classmethod
    def _timezone_aware(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)

    @field_validator("raw")
    @classmethod
    def _raw_bounded(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return _bounded_json(value, max_bytes=65536, field_name="raw")

    @field_validator("normalized")
    @classmethod
    def _normalized_bounded(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return _bounded_json(value, max_bytes=32768, field_name="normalized")


class BulkIngestRequest(StrictModel):
    source_id: UUID | None = None
    events: list[EventIngestItem] = Field(min_length=1, max_length=500)
    run_detection: bool = True


class IngestError(StrictModel):
    index: int
    field: str | None = None
    message: str


class IngestResponse(StrictModel):
    accepted: int
    rejected: int
    event_ids: list[int] = Field(default_factory=list)
    alerts_created: int = 0


class BulkIngestResponse(IngestResponse):
    errors: list[IngestError] = Field(default_factory=list)


class EventSummary(ORMModel):
    id: int
    event_uid: str
    org_id: UUID
    source_id: UUID | None = None
    occurred_at: datetime
    received_at: datetime
    class_uid: int
    class_name: str
    category_uid: int
    activity_id: int | None = None
    severity_id: int
    status_id: int | None = None
    message: str
    raw_format: str
    schema_version: str
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    user_name: str | None = None
    host_name: str | None = None
    process_name: str | None = None
    file_hash_sha256: str | None = None
    url: str | None = None
    domain: str | None = None
    ioc_matches: list[dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: list[str] = Field(default_factory=list)
    is_demo: bool = False


class EventDetail(EventSummary):
    raw: dict[str, Any] = Field(default_factory=dict)
    normalized: dict[str, Any] = Field(default_factory=dict)
    dedupe_key: str | None = None
    source_connector: str | None = None


class RetentionPolicyUpdate(StrictModel):
    hot_days: int = Field(default=90, ge=1, le=3650)
    cold_days: int = Field(default=400, ge=1, le=4000)
    batch_size: int = Field(default=5000, ge=100, le=50000)
    purge_enabled: bool = True

    @model_validator(mode="after")
    def _cold_after_hot(self) -> RetentionPolicyUpdate:
        if self.cold_days < self.hot_days:
            raise ValueError("cold_days must be greater than or equal to hot_days")
        return self


class RetentionPolicyOut(StrictModel):
    policy_id: UUID | None = None
    name: str
    kind: str
    version: int
    enabled: bool
    definition: dict[str, Any]
    effective_cutoff: datetime
    source: Literal["default", "policy"]
    updated_at: datetime | None = None


class RetentionPurgeResult(StrictModel):
    deleted: int
    cutoff: datetime
    batches: int
    truncated: bool


__all__ = [
    "BulkIngestRequest",
    "BulkIngestResponse",
    "EventDetail",
    "EventIngestItem",
    "EventSummary",
    "IngestError",
    "IngestResponse",
    "IngestSourceCreate",
    "IngestSourceCreated",
    "IngestSourceOut",
    "IngestSourcePatch",
    "IngestSourceTokenRotated",
    "RetentionPolicyOut",
    "RetentionPolicyUpdate",
    "RetentionPurgeResult",
]
