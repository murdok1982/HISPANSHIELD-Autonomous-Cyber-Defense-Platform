"""Pydantic contracts for attack-surface findings and discovery jobs."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.core.db import utcnow
from app.core.schemas import ORMModel, StrictModel

FINDING_SEVERITIES = ("critical", "high", "medium", "low", "info")
FINDING_STATUSES = ("open", "triaged", "accepted", "resolved", "false_positive")
DISCOVERY_MODES = ("passive", "active")
DISCOVERY_STATUSES = ("pending", "running", "completed", "failed")

MAX_SCOPE_CIDRS = 16


def _clean_metadata(value: dict[str, Any] | None) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("metadata must be an object")
    if len(value) > 80:
        raise ValueError("metadata supports at most 80 keys")
    return value


class FindingOut(ORMModel):
    id: UUID
    asset_id: UUID | None
    kind: str
    title: str
    severity: str
    status: str
    evidence: str | None
    source: str
    first_seen: datetime
    last_seen: datetime
    metadata: dict[str, Any] = Field(default_factory=dict, validation_alias="metadata_json")
    created_at: datetime
    updated_at: datetime


class FindingCreate(StrictModel):
    asset_id: UUID | None = None
    kind: str = Field(min_length=2, max_length=60, pattern=r"^[a-z0-9][a-z0-9_]*$")
    title: str = Field(min_length=1, max_length=300)
    severity: str = Field(default="medium", pattern="^(critical|high|medium|low|info)$")
    status: str = Field(default="open", pattern="^(open|triaged|accepted|resolved|false_positive)$")
    evidence: str | None = Field(default=None, max_length=8000)
    source: str = Field(default="manual", min_length=1, max_length=80)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def _metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _clean_metadata(value)


class FindingPatch(StrictModel):
    status: str | None = Field(default=None, pattern="^(open|triaged|accepted|resolved|false_positive)$")
    severity: str | None = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    evidence: str | None = Field(default=None, max_length=8000)
    metadata: dict[str, Any] | None = None

    @field_validator("metadata")
    @classmethod
    def _metadata(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return None if value is None else _clean_metadata(value)


class AnalyzeResult(StrictModel):
    scanned_assets: int
    created: int
    updated: int
    by_kind: dict[str, int]


class FindingSummaryOut(StrictModel):
    total: int
    by_severity: dict[str, int]
    by_kind: dict[str, int]
    by_status: dict[str, int]


class DiscoveryJobOut(ORMModel):
    id: UUID
    name: str
    mode: str
    scope_cidrs: list[str]
    authorization_id: UUID | None = None
    status: str
    authorized_by: str | None
    authorization_reference: str | None
    authorized_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    summary: dict[str, Any]
    created_by: str | None
    created_at: datetime
    updated_at: datetime


AUTHORIZATION_STATUSES = ("pending", "approved", "expired", "revoked")


class DiscoveryAuthorizationCreate(StrictModel):
    name: str = Field(min_length=2, max_length=160)
    cidrs: list[str] = Field(min_length=1, max_length=MAX_SCOPE_CIDRS)
    ports: list[int] = Field(min_length=1, max_length=32)
    max_hosts: int = Field(default=256, ge=1, le=256)
    expires_at: datetime

    @field_validator("cidrs")
    @classmethod
    def _cidrs(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw in value:
            token = raw.strip()
            if not token or len(token) > 64:
                raise ValueError("cidrs entries must be 1-64 characters")
            if token not in cleaned:
                cleaned.append(token)
        return cleaned

    @field_validator("ports")
    @classmethod
    def _ports(cls, value: list[int]) -> list[int]:
        for port in value:
            if port < 1 or port > 65535:
                raise ValueError("Ports must be within 1-65535")
        return sorted(set(value))

    @field_validator("expires_at")
    @classmethod
    def _expiry(cls, value: datetime) -> datetime:
        aware = value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)
        if aware <= utcnow():
            raise ValueError("expires_at must be in the future")
        if aware - utcnow() > timedelta(days=90):
            raise ValueError("expires_at cannot be more than 90 days in the future")
        return aware


class DiscoveryAuthorizationOut(StrictModel):
    id: UUID
    org_id: UUID
    name: str
    cidrs: list[str]
    ports: list[int]
    max_hosts: int
    status: str
    approved_by: UUID | None = None
    approved_at: datetime | None = None
    expires_at: datetime
    revoked_at: datetime | None = None
    revoked_by: UUID | None = None
    created_by: UUID | None = None
    created_at: datetime


class _ScopeMixin(StrictModel):
    scope_cidrs: list[str] = Field(default_factory=list, max_length=MAX_SCOPE_CIDRS)

    @field_validator("scope_cidrs")
    @classmethod
    def _validate_cidrs(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for raw in value:
            token = raw.strip()
            if not token or len(token) > 64:
                raise ValueError("scope_cidrs entries must be 1-64 characters")
            if token not in cleaned:
                cleaned.append(token)
        return cleaned


class DiscoveryJobCreate(_ScopeMixin):
    name: str = Field(min_length=1, max_length=200)
    mode: str = Field(default="passive", pattern="^(passive|active)$")
    authorization_id: UUID
    authorized_by: str | None = Field(default=None, max_length=120)
    authorization_reference: str | None = Field(default=None, max_length=200)

    @model_validator(mode="after")
    def _active_requires_scope(self) -> DiscoveryJobCreate:
        if self.mode == "active" and not self.scope_cidrs:
            raise ValueError("Active discovery requires at least one scope_cidrs entry")
        return self


class DiscoveryJobPatch(_ScopeMixin):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    mode: str | None = Field(default=None, pattern="^(passive|active)$")
    # PATCH semantics make the inherited scope optional; pydantic re-declares the
    # field at runtime while mypy treats the narrowed override as a type error.
    scope_cidrs: list[str] | None = Field(default=None, max_length=MAX_SCOPE_CIDRS)  # type: ignore[assignment]
    authorization_id: UUID | None = None
    authorized_by: str | None = Field(default=None, max_length=120)
    authorization_reference: str | None = Field(default=None, max_length=200)


class DiscoveryRunRequest(StrictModel):
    ports: list[int] = Field(default_factory=list, max_length=32)

    @field_validator("ports")
    @classmethod
    def _ports(cls, value: list[int]) -> list[int]:
        for port in value:
            if port < 1 or port > 65535:
                raise ValueError("Ports must be within 1-65535")
        return sorted(set(value))


class DiscoveryRunResult(StrictModel):
    job: DiscoveryJobOut
    summary: dict[str, Any]


__all__ = [
    "AUTHORIZATION_STATUSES",
    "AnalyzeResult",
    "DISCOVERY_MODES",
    "DISCOVERY_STATUSES",
    "DiscoveryAuthorizationCreate",
    "DiscoveryAuthorizationOut",
    "DiscoveryJobCreate",
    "DiscoveryJobOut",
    "DiscoveryJobPatch",
    "DiscoveryRunRequest",
    "DiscoveryRunResult",
    "FINDING_SEVERITIES",
    "FINDING_STATUSES",
    "FindingCreate",
    "FindingOut",
    "FindingPatch",
    "FindingSummaryOut",
]
