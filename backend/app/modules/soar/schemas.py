"""Pydantic contracts for SOAR playbooks, executions and validation."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field, field_validator

from app.core.schemas import ORMModel, StrictModel

_LEVEL = "^(A[0-4])$"


class PlaybookCreate(StrictModel):
    name: str = Field(min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    definition: dict[str, Any]
    min_autonomy_level: str = Field(default="A2", pattern=_LEVEL)
    triggers: dict[str, Any] | None = None


class PlaybookPatch(StrictModel):
    name: str | None = Field(default=None, min_length=3, max_length=200)
    description: str | None = Field(default=None, max_length=5000)
    definition: dict[str, Any] | None = None
    min_autonomy_level: str | None = Field(default=None, pattern=_LEVEL)
    triggers: dict[str, Any] | None = None


class PlaybookOut(ORMModel):
    id: UUID
    org_id: UUID | None
    name: str
    description: str | None
    version: int
    status: str
    trigger: dict[str, Any]
    definition: dict[str, Any]
    min_autonomy_level: str
    created_by: str | None
    published_at: datetime | None
    created_at: datetime
    updated_at: datetime


class ValidateRequest(StrictModel):
    definition: dict[str, Any]
    min_autonomy_level: str = Field(default="A2", pattern=_LEVEL)
    triggers: dict[str, Any] | None = None


class ValidationIssue(StrictModel):
    field: str
    message: str


class ValidationResult(StrictModel):
    valid: bool
    errors: list[ValidationIssue] = Field(default_factory=list)
    normalized: dict[str, Any] | None = None


class SimulateRequest(StrictModel):
    context: dict[str, Any] = Field(default_factory=dict)
    incident_id: UUID | None = None


class ExecutionCreate(StrictModel):
    playbook_id: UUID
    incident_id: UUID | None = None
    alert_id: UUID | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False
    requested_level: str | None = Field(default=None, pattern=_LEVEL)

    @field_validator("context")
    @classmethod
    def _bounded_context(cls, value: dict[str, Any]) -> dict[str, Any]:
        from app.modules.soar.validation import validate_context

        return validate_context(value)


class ExecutionStart(StrictModel):
    incident_id: UUID | None = None
    alert_id: UUID | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False
    requested_level: str | None = Field(default=None, pattern=_LEVEL)

    @field_validator("context")
    @classmethod
    def _bounded_context(cls, value: dict[str, Any]) -> dict[str, Any]:
        from app.modules.soar.validation import validate_context

        return validate_context(value)


class StepOut(ORMModel):
    id: UUID
    step_key: str
    name: str
    status: str
    attempts: int
    input: dict[str, Any]
    output: dict[str, Any]
    error: str | None
    started_at: datetime | None
    finished_at: datetime | None
    compensation_status: str | None
    compensation_output: dict[str, Any]


class ExecutionOut(ORMModel):
    id: UUID
    org_id: UUID
    playbook_id: UUID
    incident_id: UUID | None
    status: str
    trigger: str
    context: dict[str, Any]
    autonomy_level: str
    dry_run: bool
    started_at: datetime
    finished_at: datetime | None
    error: str | None
    requested_by: str | None
    approval_id: UUID | None


class ExecutionDetail(ExecutionOut):
    steps: list[StepOut] = Field(default_factory=list)
    approval_status: str | None = None


class ResumeOut(StrictModel):
    execution: ExecutionDetail
    resumed: bool
    reason: str | None = None
