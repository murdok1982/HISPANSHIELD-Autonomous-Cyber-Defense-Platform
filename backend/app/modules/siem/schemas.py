"""SIEM API contracts: detection rules, Sigma import, alerts and promotion."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import AliasChoices, Field, field_validator, model_validator

from app.core.schemas import ORMModel, StrictModel

RuleSeverity = Literal["informational", "low", "medium", "high", "critical"]
RuleStatus = Literal["production", "experimental", "draft", "deprecated"]
AlertStatus = Literal["new", "triaged", "investigating", "closed", "benign"]

_MITRE_RE = r"^T\d{4}(?:\.\d{3})?$"


def _json_size(value: dict[str, Any] | None, *, max_bytes: int, field_name: str) -> dict[str, Any] | None:
    if value is None:
        return None
    try:
        encoded = json.dumps(value, default=str)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be JSON serialisable") from exc
    if len(encoded.encode("utf-8")) > max_bytes:
        raise ValueError(f"{field_name} exceeds {max_bytes} bytes")
    return value


class RuleCreate(StrictModel):
    name: str = Field(min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    severity: RuleSeverity = "medium"
    status: RuleStatus = "production"
    enabled: bool = True
    definition: dict[str, Any]
    logsource: dict[str, Any] = Field(default_factory=dict)
    mitre: list[str] = Field(default_factory=list, max_length=20)
    tags: list[str] = Field(default_factory=list, max_length=20)
    is_global: bool = False

    @field_validator("definition")
    @classmethod
    def _definition_bounded(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _json_size(value, max_bytes=65536, field_name="definition") or {}

    @field_validator("logsource")
    @classmethod
    def _logsource_bounded(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _json_size(value, max_bytes=8192, field_name="logsource") or {}

    @field_validator("mitre")
    @classmethod
    def _mitre_valid(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            candidate = item.strip().upper()
            if not re.match(_MITRE_RE, candidate):
                raise ValueError(f"Invalid MITRE technique: {item}")
            cleaned.append(candidate)
        return cleaned

    @field_validator("tags")
    @classmethod
    def _tags_valid(cls, value: list[str]) -> list[str]:
        for item in value:
            if len(item) > 60 or any(ord(char) < 32 for char in item):
                raise ValueError("Invalid tag")
        return [item.strip() for item in value if item.strip()]


class RulePatch(StrictModel):
    name: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    severity: RuleSeverity | None = None
    status: RuleStatus | None = None
    enabled: bool | None = None
    definition: dict[str, Any] | None = None
    logsource: dict[str, Any] | None = None
    mitre: list[str] | None = Field(default=None, max_length=20)
    tags: list[str] | None = Field(default=None, max_length=20)

    @field_validator("definition")
    @classmethod
    def _definition_bounded(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return _json_size(value, max_bytes=65536, field_name="definition")

    @field_validator("logsource")
    @classmethod
    def _logsource_bounded(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return _json_size(value, max_bytes=8192, field_name="logsource")

    @field_validator("mitre")
    @classmethod
    def _mitre_valid(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        cleaned = []
        for item in value:
            candidate = item.strip().upper()
            if not re.match(_MITRE_RE, candidate):
                raise ValueError(f"Invalid MITRE technique: {item}")
            cleaned.append(candidate)
        return cleaned

    @model_validator(mode="after")
    def _at_least_one(self) -> RulePatch:
        if not self.model_fields_set:
            raise ValueError("At least one field must be provided")
        return self


class RuleOut(StrictModel):
    id: UUID
    org_id: UUID | None
    name: str
    description: str | None = None
    severity: str
    status: str
    enabled: bool
    version: int
    logsource: dict[str, Any] = Field(default_factory=dict)
    definition: dict[str, Any] = Field(default_factory=dict)
    mitre: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    false_positive_count: int = 0
    true_positive_count: int = 0
    created_by: str | None = None
    created_at: datetime
    updated_at: datetime
    scope: Literal["global", "organization"]


class RuleTestRequest(StrictModel):
    events: list[dict[str, Any]] | None = Field(
        default=None, max_length=50, validation_alias=AliasChoices("events", "sample_events")
    )
    event_ids: list[int] | None = Field(default=None, max_length=50)
    apply_threshold: bool = True

    @field_validator("events")
    @classmethod
    def _events_bounded(cls, value: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        if value is None:
            return None
        if not value:
            raise ValueError("events must not be empty")
        for item in value:
            _json_size(item, max_bytes=32768, field_name="events[]")
        return value

    @field_validator("event_ids")
    @classmethod
    def _event_ids_valid(cls, value: list[int] | None) -> list[int] | None:
        if value is None:
            return None
        if not value:
            raise ValueError("event_ids must not be empty")
        if any(identifier <= 0 for identifier in value):
            raise ValueError("event_ids must be positive integers")
        return value

    @model_validator(mode="after")
    def _one_source(self) -> RuleTestRequest:
        if self.events is None and self.event_ids is None:
            raise ValueError("Provide events or event_ids")
        if self.events is not None and self.event_ids is not None:
            raise ValueError("Provide either events or event_ids, not both")
        return self


class SigmaRule(StrictModel):
    title: str = Field(min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    logsource: dict[str, Any] = Field(default_factory=dict)
    detection: dict[str, Any]
    tags: list[str] = Field(default_factory=list, max_length=50)
    level: str | None = Field(default=None, pattern="^(informational|low|medium|high|critical)$")

    @field_validator("logsource")
    @classmethod
    def _logsource_bounded(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _json_size(value, max_bytes=8192, field_name="logsource") or {}

    @field_validator("detection")
    @classmethod
    def _detection_bounded(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _json_size(value, max_bytes=32768, field_name="detection") or {}

    @field_validator("tags")
    @classmethod
    def _tags_valid(cls, value: list[str]) -> list[str]:
        for item in value:
            if len(item) > 80:
                raise ValueError("Sigma tag is too long")
        return value


class SigmaImportRequest(StrictModel):
    rules: list[SigmaRule] = Field(min_length=1, max_length=100)


class SigmaImportSkipped(StrictModel):
    title: str
    reason: str


class SigmaImportResponse(StrictModel):
    imported: list[RuleOut] = Field(default_factory=list)
    skipped: list[SigmaImportSkipped] = Field(default_factory=list)


class AlertSummary(ORMModel):
    id: UUID
    org_id: UUID
    rule_id: UUID | None = None
    rule_name: str | None = None
    title: str
    description: str | None = None
    severity: str
    status: str
    dedupe_key: str | None = None
    event_ids: list[int] = Field(default_factory=list)
    first_seen: datetime
    last_seen: datetime
    count: int
    assignee_id: UUID | None = None
    incident_id: UUID | None = None
    mitre: list[str] = Field(default_factory=list)
    risk_score: float
    is_demo: bool = False
    created_at: datetime
    updated_at: datetime


class AlertDetail(AlertSummary):
    evidence: dict[str, Any] = Field(default_factory=dict)


class AlertPatch(StrictModel):
    status: AlertStatus | None = None
    assignee_id: UUID | None = None
    note: str | None = Field(default=None, max_length=4000)

    @model_validator(mode="after")
    def _not_empty(self) -> AlertPatch:
        if not self.model_fields_set:
            raise ValueError("At least one field must be provided")
        return self


class AlertBulkRequest(StrictModel):
    ids: list[UUID] = Field(min_length=1, max_length=100)
    status: AlertStatus | None = None
    assignee_id: UUID | None = None
    note: str | None = Field(default=None, max_length=4000)

    @field_validator("ids")
    @classmethod
    def _unique(cls, value: list[UUID]) -> list[UUID]:
        if len(set(value)) != len(value):
            raise ValueError("ids must be unique")
        return value

    @model_validator(mode="after")
    def _any_change(self) -> AlertBulkRequest:
        if self.status is None and "assignee_id" not in self.model_fields_set and self.note is None:
            raise ValueError("Provide status, assignee_id or note")
        return self


class AlertBulkResponse(StrictModel):
    updated: int
    skipped: int
    ids: list[UUID] = Field(default_factory=list)


class PromoteRequest(StrictModel):
    title: str | None = Field(default=None, min_length=3, max_length=300)
    description: str | None = Field(default=None, max_length=4000)


class IncidentSummary(StrictModel):
    id: UUID
    ref: str
    title: str
    severity: str
    status: str
    priority: int
    detected_at: datetime


class PromoteResponse(StrictModel):
    incident: IncidentSummary
    alert_id: UUID
    incident_id: UUID


__all__ = [
    "AlertBulkRequest",
    "AlertBulkResponse",
    "AlertDetail",
    "AlertPatch",
    "AlertStatus",
    "AlertSummary",
    "IncidentSummary",
    "PromoteRequest",
    "PromoteResponse",
    "RuleCreate",
    "RuleOut",
    "RulePatch",
    "RuleSeverity",
    "RuleTestRequest",
    "SigmaImportRequest",
    "SigmaImportResponse",
    "SigmaImportSkipped",
    "SigmaRule",
]
