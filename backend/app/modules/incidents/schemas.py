"""Pydantic contracts for incidents, timeline, evidence and metrics."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field, field_validator

from app.core.schemas import ORMModel, StrictModel

_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_STATUS_PATTERN = "^(new|triage|investigating|contained|eradicated|recovered|closed)$"
_SEVERITY_PATTERN = "^(info|low|medium|high|critical|P[1-5]|p[1-5])$"


def _clean_text(value: str | None, *, allow_newlines: bool = True) -> str | None:
    if value is None:
        return None
    if _CONTROL_RE.search(value):
        raise ValueError("Text contains unsupported control characters")
    if not allow_newlines and ("\n" in value or "\r" in value):
        raise ValueError("Line breaks are not allowed in this field")
    return value


class TimelineOut(ORMModel):
    id: UUID
    incident_id: UUID
    at: datetime
    kind: str
    actor: str | None
    summary: str
    detail: dict[str, Any]


class EvidenceOut(ORMModel):
    id: UUID
    incident_id: UUID | None
    kind: str
    title: str
    description: str | None
    sha256: str
    content_type: str
    size_bytes: int
    collected_by: str | None
    collected_at: datetime
    sealed: bool
    chain_of_custody: list[dict[str, Any]]


class AlertLink(ORMModel):
    id: UUID
    title: str
    severity: str
    status: str
    count: int
    first_seen: datetime
    last_seen: datetime
    mitre: list[str]


class RemediationLink(ORMModel):
    id: UUID
    action_type: str
    target_type: str
    target_id: str
    status: str
    risk_level: str
    execution_id: UUID | None
    executed_at: datetime | None
    verified_at: datetime | None
    rollback_status: str | None


class AssetSummary(ORMModel):
    id: UUID
    name: str
    kind: str
    criticality: int
    environment: str
    status: str
    ip_addresses: list[str]


class IncidentOut(ORMModel):
    id: UUID
    ref: str
    title: str
    description: str | None
    severity: str
    status: str
    priority: int
    assignee_id: UUID | None
    commander_id: UUID | None
    detected_at: datetime
    contained_at: datetime | None
    resolved_at: datetime | None
    closed_at: datetime | None
    sla_due_at: datetime | None
    mitre: list[str]
    affected_asset_ids: list[str]
    root_cause: str | None
    lessons_learned: str | None
    is_demo: bool
    created_by: str | None
    created_at: datetime
    updated_at: datetime


class IncidentDetail(IncidentOut):
    timeline: list[TimelineOut] = Field(default_factory=list)
    evidence: list[EvidenceOut] = Field(default_factory=list)
    alerts: list[AlertLink] = Field(default_factory=list)
    remediations: list[RemediationLink] = Field(default_factory=list)
    assets: list[AssetSummary] = Field(default_factory=list)


class IncidentCreate(StrictModel):
    title: str = Field(min_length=3, max_length=300)
    description: str | None = Field(default=None, max_length=20000)
    severity: str = Field(default="medium", pattern=_SEVERITY_PATTERN)
    priority: int | None = Field(default=None, ge=1, le=5)
    assignee_id: UUID | None = None
    commander_id: UUID | None = None
    detected_at: datetime | None = None
    mitre: list[str] = Field(default_factory=list, max_length=20)
    affected_asset_ids: list[str] = Field(default_factory=list, max_length=100)
    sla_due_at: datetime | None = None

    @field_validator("title", "description")
    @classmethod
    def _text(cls, value: str | None) -> str | None:
        return _clean_text(value)

    @field_validator("mitre")
    @classmethod
    def _mitre(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            item = item.strip()
            if not item or len(item) > 40:
                raise ValueError("MITRE technique identifiers must be 1-40 characters")
            cleaned.append(item)
        return cleaned

    @field_validator("affected_asset_ids")
    @classmethod
    def _asset_ids(cls, value: list[str]) -> list[str]:
        for item in value:
            try:
                UUID(str(item))
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Invalid asset id: {item}") from exc
        return value


class IncidentPatch(StrictModel):
    title: str | None = Field(default=None, min_length=3, max_length=300)
    description: str | None = Field(default=None, max_length=20000)
    severity: str | None = Field(default=None, pattern=_SEVERITY_PATTERN)
    priority: int | None = Field(default=None, ge=1, le=5)
    assignee_id: UUID | None = None
    commander_id: UUID | None = None
    detected_at: datetime | None = None
    sla_due_at: datetime | None = None
    mitre: list[str] | None = Field(default=None, max_length=20)
    affected_asset_ids: list[str] | None = Field(default=None, max_length=100)

    @field_validator("title", "description")
    @classmethod
    def _text(cls, value: str | None) -> str | None:
        return _clean_text(value)

    @field_validator("mitre")
    @classmethod
    def _mitre(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        for item in value:
            if not item.strip() or len(item) > 40:
                raise ValueError("MITRE technique identifiers must be 1-40 characters")
        return value

    @field_validator("affected_asset_ids")
    @classmethod
    def _asset_ids(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        for item in value:
            try:
                UUID(str(item))
            except (ValueError, TypeError) as exc:
                raise ValueError(f"Invalid asset id: {item}") from exc
        return value


class StatusChange(StrictModel):
    status: str = Field(pattern=_STATUS_PATTERN)
    root_cause: str | None = Field(default=None, max_length=20000)
    lessons_learned: str | None = Field(default=None, max_length=20000)
    note: str | None = Field(default=None, max_length=500)

    @field_validator("root_cause", "lessons_learned", "note")
    @classmethod
    def _text(cls, value: str | None) -> str | None:
        return _clean_text(value)


class TimelineCreate(StrictModel):
    kind: str = Field(default="note", pattern=r"^[a-z][a-z0-9_]{1,29}$")
    summary: str = Field(min_length=3, max_length=500)
    detail: dict[str, Any] = Field(default_factory=dict)

    @field_validator("summary")
    @classmethod
    def _text(cls, value: str) -> str:
        return _clean_text(value, allow_newlines=False) or ""

    @field_validator("detail")
    @classmethod
    def _detail_size(cls, value: dict[str, Any]) -> dict[str, Any]:
        import json

        if len(json.dumps(value, default=str)) > 16_000:
            raise ValueError("Timeline detail exceeds the 16KB limit")
        return value


class IncidentMetricsOut(StrictModel):
    open_total: int
    open_by_severity: dict[str, int]
    closed_total: int
    total: int
    mttd_seconds: float | None
    mttr_seconds: float | None
    computed_at: datetime
