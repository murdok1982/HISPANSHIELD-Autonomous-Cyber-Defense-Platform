"""Pydantic contracts for the asset intelligence domain.

All inputs inherit :class:`StrictModel` (``extra="forbid"``) so misspelled or
unexpected fields are rejected with 422 instead of silently persisted.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field, field_validator

from app.core.schemas import ORMModel, StrictModel

ASSET_KINDS = ("host", "network", "cloud", "iot", "ot", "identity", "service")
ASSET_ENVIRONMENTS = ("production", "staging", "development", "test")
ASSET_STATUSES = ("active", "inactive", "retired", "quarantined", "unknown")
IDENTITY_KINDS = (
    "ip",
    "mac",
    "hostname",
    "domain",
    "serial",
    "cert_cn",
    "cert_sha256",
    "email",
    "username",
    "uid",
    "uri",
    "telemetry_protocol",
)
ZONE_KINDS = ("zone", "conduit")
RELATIONSHIP_KINDS_PATTERN = r"^[a-z0-9][a-z0-9_:.-]{1,59}$"

KIND_PATTERN = "^(host|network|cloud|iot|ot|identity|service)$"
ENVIRONMENT_PATTERN = "^(production|staging|development|test)$"
STATUS_PATTERN = "^(active|inactive|retired|quarantined|unknown)$"
IDENTITY_KIND_PATTERN = "^(" + "|".join(IDENTITY_KINDS) + ")$"

MAX_METADATA_BYTES = 16_384
MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}$")
HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _clean_metadata(value: dict[str, Any] | None) -> dict[str, Any]:
    """Bound metadata size and strip control characters from keys/values."""
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("metadata must be an object")
    if len(value) > 80:
        raise ValueError("metadata supports at most 80 keys")
    serialized = json.dumps(value, default=str, ensure_ascii=False)
    if len(serialized.encode("utf-8")) > MAX_METADATA_BYTES:
        raise ValueError("metadata exceeds 16 KiB")
    if CONTROL_CHARS_RE.search(serialized):
        raise ValueError("metadata contains control characters")
    return value


def _clean_string_list(values: list[str], *, label: str, max_items: int, max_length: int) -> list[str]:
    if len(values) > max_items:
        raise ValueError(f"{label} supports at most {max_items} entries")
    cleaned: list[str] = []
    seen: set[str] = set()
    for raw in values:
        item = str(raw).strip()
        if not item:
            raise ValueError(f"{label} entries must not be empty")
        if len(item) > max_length:
            raise ValueError(f"{label} entries must be at most {max_length} characters")
        lowered = item.lower()
        if lowered not in seen:
            seen.add(lowered)
            cleaned.append(item)
    return cleaned


class _AssetInputBase(StrictModel):
    name: str = Field(min_length=1, max_length=240)
    subtype: str | None = Field(default=None, max_length=60)
    criticality: int = Field(default=3, ge=1, le=5)
    environment: str = Field(default="production", pattern=ENVIRONMENT_PATTERN)
    status: str = Field(default="active", pattern=STATUS_PATTERN)
    ip_addresses: list[str] = Field(default_factory=list, max_length=64)
    mac_addresses: list[str] = Field(default_factory=list, max_length=64)
    hostnames: list[str] = Field(default_factory=list, max_length=64)
    os_name: str | None = Field(default=None, max_length=160)
    vendor: str | None = Field(default=None, max_length=160)
    model: str | None = Field(default=None, max_length=160)
    firmware: str | None = Field(default=None, max_length=120)
    serial_number: str | None = Field(default=None, max_length=160)
    location: str | None = Field(default=None, max_length=200)
    owner: str | None = Field(default=None, max_length=200)
    zone_id: UUID | None = None
    tags: list[str] = Field(default_factory=list, max_length=40)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ip_addresses")
    @classmethod
    def _validate_ips(cls, value: list[str]) -> list[str]:
        cleaned = _clean_string_list(value, label="ip_addresses", max_items=64, max_length=64)
        for item in cleaned:
            try:
                ipaddress.ip_address(item)
            except ValueError as exc:
                raise ValueError(f"Invalid IP address: {item}") from exc
        return cleaned

    @field_validator("mac_addresses")
    @classmethod
    def _validate_macs(cls, value: list[str]) -> list[str]:
        cleaned = _clean_string_list(value, label="mac_addresses", max_items=64, max_length=17)
        for item in cleaned:
            if not MAC_RE.match(item):
                raise ValueError(f"Invalid MAC address: {item}")
        return [item.upper() for item in cleaned]

    @field_validator("hostnames")
    @classmethod
    def _validate_hostnames(cls, value: list[str]) -> list[str]:
        cleaned = _clean_string_list(value, label="hostnames", max_items=64, max_length=253)
        for item in cleaned:
            if not HOSTNAME_RE.match(item):
                raise ValueError(f"Invalid hostname: {item}")
        return [item.lower() for item in cleaned]

    @field_validator("tags")
    @classmethod
    def _validate_tags(cls, value: list[str]) -> list[str]:
        return _clean_string_list(value, label="tags", max_items=40, max_length=60)

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _clean_metadata(value)

    @field_validator("subtype", "os_name", "vendor", "model", "firmware", "serial_number", "location", "owner")
    @classmethod
    def _no_control_chars(cls, value: str | None) -> str | None:
        if value is not None and CONTROL_CHARS_RE.search(value):
            raise ValueError("Field contains control characters")
        return value


class AssetCreate(_AssetInputBase):
    asset_key: str = Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
    kind: str = Field(pattern=KIND_PATTERN)
    discovery_source: str = Field(default="manual", min_length=1, max_length=80)
    confidence: int = Field(default=100, ge=0, le=100)


class AssetPatch(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=240)
    subtype: str | None = Field(default=None, max_length=60)
    criticality: int | None = Field(default=None, ge=1, le=5)
    environment: str | None = Field(default=None, pattern=ENVIRONMENT_PATTERN)
    status: str | None = Field(default=None, pattern=STATUS_PATTERN)
    ip_addresses: list[str] | None = Field(default=None, max_length=64)
    mac_addresses: list[str] | None = Field(default=None, max_length=64)
    hostnames: list[str] | None = Field(default=None, max_length=64)
    os_name: str | None = Field(default=None, max_length=160)
    vendor: str | None = Field(default=None, max_length=160)
    model: str | None = Field(default=None, max_length=160)
    firmware: str | None = Field(default=None, max_length=120)
    serial_number: str | None = Field(default=None, max_length=160)
    location: str | None = Field(default=None, max_length=200)
    owner: str | None = Field(default=None, max_length=200)
    zone_id: UUID | None = None
    tags: list[str] | None = Field(default=None, max_length=40)
    metadata: dict[str, Any] | None = None
    discovery_source: str | None = Field(default=None, min_length=1, max_length=80)
    confidence: int | None = Field(default=None, ge=0, le=100)

    @field_validator("ip_addresses")
    @classmethod
    def _validate_ips(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _AssetInputBase._validate_ips(value)

    @field_validator("mac_addresses")
    @classmethod
    def _validate_macs(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _AssetInputBase._validate_macs(value)

    @field_validator("hostnames")
    @classmethod
    def _validate_hostnames(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _AssetInputBase._validate_hostnames(value)

    @field_validator("tags")
    @classmethod
    def _validate_tags(cls, value: list[str] | None) -> list[str] | None:
        return None if value is None else _AssetInputBase._validate_tags(value)

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return None if value is None else _clean_metadata(value)

    @field_validator("subtype", "os_name", "vendor", "model", "firmware", "serial_number", "location", "owner")
    @classmethod
    def _no_control_chars(cls, value: str | None) -> str | None:
        if value is not None and CONTROL_CHARS_RE.search(value):
            raise ValueError("Field contains control characters")
        return value


class AssetImportItem(AssetCreate):
    """One row of a bulk import: creation defaults plus per-row provenance."""

    discovery_source: str | None = Field(default=None, min_length=1, max_length=80)
    confidence: int | None = Field(default=None, ge=0, le=100)


class ImportRowError(StrictModel):
    row: int
    asset_key: str | None = None
    message: str


class AssetImportRequest(StrictModel):
    # Rows are validated individually inside the service so a single bad row
    # produces a per-row error instead of rejecting the whole batch.
    items: list[dict[str, Any]] = Field(min_length=1, max_length=500)
    source: str = Field(default="import", min_length=1, max_length=80)
    confidence: int = Field(default=60, ge=0, le=100)


class ImportResult(StrictModel):
    total: int
    created: int
    updated: int
    skipped: int
    errors: list[ImportRowError]


class AssetOut(ORMModel):
    id: UUID
    asset_key: str
    name: str
    kind: str
    subtype: str | None
    criticality: int
    environment: str
    status: str
    ip_addresses: list[str]
    mac_addresses: list[str]
    hostnames: list[str]
    os_name: str | None
    vendor: str | None
    model: str | None
    firmware: str | None
    serial_number: str | None
    location: str | None
    owner: str | None
    discovery_source: str
    confidence: int
    first_seen: datetime
    last_seen: datetime
    last_scanned_at: datetime | None
    zone_id: UUID | None
    tags: list[str]
    metadata: dict[str, Any] = Field(default_factory=dict, validation_alias="metadata_json")
    is_demo: bool
    created_at: datetime
    updated_at: datetime


class AssetRef(ORMModel):
    id: UUID
    asset_key: str
    name: str
    kind: str
    criticality: int
    environment: str
    zone_id: UUID | None


class IdentityOut(ORMModel):
    id: UUID
    asset_id: UUID
    kind: str
    value: str
    confidence: int
    created_at: datetime


class IdentityCreate(StrictModel):
    kind: str = Field(pattern=IDENTITY_KIND_PATTERN)
    value: str = Field(min_length=1, max_length=400)
    confidence: int = Field(default=100, ge=0, le=100)

    @field_validator("value")
    @classmethod
    def _no_control_chars(cls, value: str) -> str:
        if CONTROL_CHARS_RE.search(value):
            raise ValueError("Identity value contains control characters")
        return value.strip()

    @field_validator("kind")
    @classmethod
    def _known_kind(cls, value: str) -> str:
        if value not in IDENTITY_KINDS:
            raise ValueError(f"Unsupported identity kind: {value}")
        return value


class RelationshipCreate(StrictModel):
    target_asset_id: UUID
    kind: str = Field(pattern=RELATIONSHIP_KINDS_PATTERN)
    confidence: int = Field(default=100, ge=0, le=100)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _clean_metadata(value)


class RelationshipView(StrictModel):
    id: UUID
    source_asset_id: UUID
    target_asset_id: UUID
    kind: str
    confidence: int
    first_seen: datetime
    last_seen: datetime
    metadata: dict[str, Any]
    direction: str
    counterpart: AssetRef | None = None


class GraphNode(StrictModel):
    id: UUID
    asset_key: str
    name: str
    kind: str
    criticality: int
    environment: str
    zone_id: UUID | None


class GraphEdge(StrictModel):
    id: UUID
    source_asset_id: UUID
    target_asset_id: UUID
    kind: str
    confidence: int


class AssetGraphOut(StrictModel):
    root_id: UUID
    depth: int
    nodes: list[GraphNode]
    edges: list[GraphEdge]


class AssetIoTDetail(ORMModel):
    protocols: list[str]
    connectivity: str | None
    edge_gateway_id: UUID | None
    firmware_version: str | None
    last_telemetry_at: datetime | None
    security_posture: dict[str, Any]


class AssetOTDetail(ORMModel):
    protocols: list[str]
    zone_id: UUID | None
    safety_critical: bool
    passive_only: bool
    controller_model: str | None
    firmware_version: str | None
    last_telemetry_at: datetime | None
    baseline: dict[str, Any]


class VulnerabilitySummaryOut(StrictModel):
    total: int
    open: int
    reopened: int
    kev: int
    by_severity: dict[str, int]


class AssetDetailOut(AssetOut):
    identities: list[IdentityOut]
    relationships: list[RelationshipView]
    iot: AssetIoTDetail | None
    ot: AssetOTDetail | None
    vulnerability_summary: VulnerabilitySummaryOut


class ZoneCreate(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    kind: str = Field(default="zone", pattern="^(zone|conduit)$")
    purdue_level: int | None = Field(default=None, ge=0, le=5)
    description: str | None = Field(default=None, max_length=2000)
    parent_id: UUID | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _clean_metadata(value)


class ZonePatch(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    kind: str | None = Field(default=None, pattern="^(zone|conduit)$")
    purdue_level: int | None = Field(default=None, ge=0, le=5)
    description: str | None = Field(default=None, max_length=2000)
    parent_id: UUID | None = None
    metadata: dict[str, Any] | None = None

    @field_validator("metadata")
    @classmethod
    def _validate_metadata(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return None if value is None else _clean_metadata(value)


class ZoneOut(ORMModel):
    id: UUID
    name: str
    kind: str
    purdue_level: int | None
    description: str | None
    parent_id: UUID | None
    metadata: dict[str, Any] = Field(default_factory=dict, validation_alias="metadata_json")
    created_at: datetime
    updated_at: datetime


class AssetVulnerabilityOut(ORMModel):
    id: UUID
    asset_id: UUID | None
    cve_id: str | None
    title: str
    severity: str
    status: str
    cvss_score: float | None
    epss_score: float | None
    kev: bool
    exploitable: bool
    exposure: str
    priority_score: float
    priority_reason: str | None
    source: str
    first_seen: datetime
    last_seen: datetime
    due_at: datetime | None
    remediation: str | None


__all__ = [
    "ASSET_ENVIRONMENTS",
    "ASSET_KINDS",
    "ASSET_STATUSES",
    "IDENTITY_KINDS",
    "ZONE_KINDS",
    "AssetCreate",
    "AssetDetailOut",
    "AssetGraphOut",
    "AssetImportItem",
    "AssetImportRequest",
    "AssetIoTDetail",
    "AssetOTDetail",
    "AssetOut",
    "AssetPatch",
    "AssetRef",
    "AssetVulnerabilityOut",
    "GraphEdge",
    "GraphNode",
    "IdentityCreate",
    "IdentityOut",
    "ImportResult",
    "ImportRowError",
    "RelationshipCreate",
    "RelationshipView",
    "VulnerabilitySummaryOut",
    "ZoneCreate",
    "ZoneOut",
    "ZonePatch",
]
