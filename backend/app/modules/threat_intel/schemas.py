"""Pydantic contracts for the threat intelligence module."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, field_validator

from app.core.schemas import ORMModel, StrictModel
from app.modules.threat_intel.stix import StixError, normalize_value

IndicatorType = Literal["ip", "domain", "url", "sha256", "sha1", "md5", "email"]
Severity = Literal["low", "medium", "high", "critical"]
FeedKind = Literal["misp", "opencti", "taxii", "csv", "stix"]

FEED_CONFIG_KEYS = {
    "url",
    "base_url",
    "collection_id",
    "api_root",
    "api_key",
    "token",
    "username",
    "password",
    "auth_type",
    "headers",
    "default_severity",
    "limit",
    "added_after",
    "verify_tls",
}
FINDING_SEVERITIES = ("low", "medium", "high", "critical")


def _clean_tags(values: list[str] | None) -> list[str]:
    if not values:
        return []
    cleaned: list[str] = []
    for item in values:
        if not isinstance(item, str):
            raise ValueError("Tags must be strings")
        tag = item.strip()
        if not tag:
            continue
        if len(tag) > 40:
            raise ValueError("Each tag must be at most 40 characters")
        if "\x00" in tag:
            raise ValueError("Tags must not contain null bytes")
        if tag not in cleaned:
            cleaned.append(tag)
    if len(cleaned) > 20:
        raise ValueError("At most 20 tags are allowed")
    return cleaned


def _ensure_aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _validate_feed_config(value: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("Feed config must be an object")
    unknown = set(value) - FEED_CONFIG_KEYS
    if unknown:
        raise ValueError(f"Unsupported feed config keys: {', '.join(sorted(unknown))}")
    encoded = json.dumps(value, default=str)
    if len(encoded) > 16_384:
        raise ValueError("Feed config exceeds 16 KB")
    for key, item in value.items():
        if isinstance(item, str) and len(item) > 2000:
            raise ValueError(f"Feed config value for {key} is too long")
    return value


class IndicatorCreate(StrictModel):
    indicator_type: IndicatorType
    value: str = Field(min_length=1, max_length=500)
    confidence: int = Field(default=50, ge=0, le=100)
    severity: Severity = "medium"
    source: str = Field(default="manual", min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    tags: list[str] = Field(default_factory=list, max_length=20)
    actor_id: UUID | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    expires_at: datetime | None = None
    active: bool = True
    global_indicator: bool = False

    @field_validator("value")
    @classmethod
    def _validate_value(cls, value: str, info) -> str:  # type: ignore[no-untyped-def]
        indicator_type = info.data.get("indicator_type")
        if indicator_type is None:
            return value
        try:
            return normalize_value(indicator_type, value)
        except StixError as exc:
            raise ValueError(str(exc)) from exc

    @field_validator("tags")
    @classmethod
    def _validate_tags(cls, value: list[str]) -> list[str]:
        return _clean_tags(value)

    @field_validator("first_seen", "last_seen", "expires_at")
    @classmethod
    def _normalize_datetimes(cls, value: datetime | None) -> datetime | None:
        return _ensure_aware(value)


class IndicatorPatch(StrictModel):
    confidence: int | None = Field(default=None, ge=0, le=100)
    severity: Severity | None = None
    source: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    tags: list[str] | None = Field(default=None, max_length=20)
    actor_id: UUID | None = None
    last_seen: datetime | None = None
    expires_at: datetime | None = None
    active: bool | None = None

    @field_validator("tags")
    @classmethod
    def _validate_tags(cls, value: list[str] | None) -> list[str] | None:
        return _clean_tags(value) if value is not None else None

    @field_validator("last_seen", "expires_at")
    @classmethod
    def _normalize_datetimes(cls, value: datetime | None) -> datetime | None:
        return _ensure_aware(value)


class IndicatorOut(ORMModel):
    id: UUID
    org_id: UUID | None
    indicator_type: str
    value: str
    confidence: int
    severity: str
    source: str
    description: str | None
    tags: list[str]
    actor_id: UUID | None
    first_seen: datetime
    last_seen: datetime
    expires_at: datetime | None
    active: bool
    created_at: datetime
    updated_at: datetime


class ActorCreate(StrictModel):
    name: str = Field(min_length=1, max_length=200)
    aliases: list[str] = Field(default_factory=list, max_length=20)
    mitre_id: str | None = Field(default=None, pattern=r"^[GST]\d{4}$")
    description: str | None = Field(default=None, max_length=4000)
    sophistication: str = Field(default="unknown", max_length=40)
    motivation: str = Field(default="unknown", max_length=80)
    country: str | None = Field(default=None, max_length=80)
    techniques: list[str] = Field(default_factory=list, max_length=100)
    global_actor: bool = False

    @field_validator("aliases")
    @classmethod
    def _validate_aliases(cls, value: list[str]) -> list[str]:
        return _clean_tags(value)

    @field_validator("techniques")
    @classmethod
    def _validate_techniques(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for item in value:
            candidate = item.strip().upper()
            if not candidate:
                continue
            if not _is_technique_id(candidate):
                raise ValueError(f"Invalid MITRE technique identifier: {item}")
            if candidate not in cleaned:
                cleaned.append(candidate)
        return cleaned


class ActorPatch(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    aliases: list[str] | None = Field(default=None, max_length=20)
    mitre_id: str | None = Field(default=None, pattern=r"^[GST]\d{4}$")
    description: str | None = Field(default=None, max_length=4000)
    sophistication: str | None = Field(default=None, max_length=40)
    motivation: str | None = Field(default=None, max_length=80)
    country: str | None = Field(default=None, max_length=80)
    techniques: list[str] | None = Field(default=None, max_length=100)

    @field_validator("aliases")
    @classmethod
    def _validate_aliases(cls, value: list[str] | None) -> list[str] | None:
        return _clean_tags(value) if value is not None else None

    @field_validator("techniques")
    @classmethod
    def _validate_techniques(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        cleaned: list[str] = []
        for item in value:
            candidate = item.strip().upper()
            if not candidate:
                continue
            if not _is_technique_id(candidate):
                raise ValueError(f"Invalid MITRE technique identifier: {item}")
            if candidate not in cleaned:
                cleaned.append(candidate)
        return cleaned


def _is_technique_id(value: str) -> bool:
    import re

    return bool(re.match(r"^T\d{4}(?:\.\d{3})?$", value))


class ActorOut(ORMModel):
    id: UUID
    org_id: UUID | None
    name: str
    aliases: list[str]
    mitre_id: str | None
    description: str | None
    sophistication: str
    motivation: str
    country: str | None
    techniques: list[str]
    created_at: datetime
    updated_at: datetime


class ActorDetail(ActorOut):
    indicator_count: int = 0


class FeedCreate(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    kind: FeedKind
    connector_id: UUID | None = None
    enabled: bool = True
    schedule_minutes: int = Field(default=60, ge=5, le=1440)
    config: dict[str, Any] = Field(default_factory=dict)

    @field_validator("config")
    @classmethod
    def _validate_config(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_feed_config(value)


class FeedPatch(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=160)
    kind: FeedKind | None = None
    connector_id: UUID | None = None
    enabled: bool | None = None
    schedule_minutes: int | None = Field(default=None, ge=5, le=1440)
    config: dict[str, Any] | None = None

    @field_validator("config")
    @classmethod
    def _validate_config(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return _validate_feed_config(value) if value is not None else None


class FeedOut(ORMModel):
    id: UUID
    org_id: UUID
    name: str
    kind: str
    connector_id: UUID | None
    enabled: bool
    schedule_minutes: int
    last_sync_at: datetime | None
    status: str
    last_error: str | None
    config: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class StixBundleImport(StrictModel):
    bundle: dict[str, Any]


class CsvImportRequest(StrictModel):
    csv: str = Field(min_length=1, max_length=2_000_000)
    source: str | None = Field(default=None, max_length=120)


class ImportErrorItem(StrictModel):
    row: int | None = None
    field: str | None = None
    message: str


class ImportResult(StrictModel):
    created: int
    updated: int
    skipped: int
    errors: list[ImportErrorItem]
    total_received: int


class DeactivateResult(StrictModel):
    id: UUID
    active: bool
    message: str


class FeedSyncResult(StrictModel):
    feed_id: UUID
    status: str
    objects_read: int
    created: int
    updated: int
    skipped: int
    errors: list[ImportErrorItem]
    last_sync_at: datetime | None


__all__ = [
    "ActorCreate",
    "ActorDetail",
    "ActorOut",
    "ActorPatch",
    "CsvImportRequest",
    "DeactivateResult",
    "FeedCreate",
    "FeedOut",
    "FeedPatch",
    "FeedSyncResult",
    "ImportErrorItem",
    "ImportResult",
    "IndicatorCreate",
    "IndicatorOut",
    "IndicatorPatch",
    "StixBundleImport",
]
