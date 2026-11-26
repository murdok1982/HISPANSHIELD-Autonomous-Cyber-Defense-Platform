"""Pydantic contracts for the defence / autonomous remediation API."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field, field_validator

from app.core.schemas import ORMModel, StrictModel

_LEVEL = "^(A[0-4])$"
_TARGET = "^(endpoint|ip|identity|session|incident|asset|organization|integration)$"


def _validate_parameters(value: dict[str, Any]) -> dict[str, Any]:
    if len(json.dumps(value, default=str)) > 20_000:
        raise ValueError("Parameters exceed the 20KB limit")
    return value


class EvaluateRequest(StrictModel):
    action_type: str = Field(min_length=1, max_length=80)
    target_type: str | None = Field(default=None, pattern=_TARGET)
    target_id: str | None = Field(default=None, max_length=300)
    requested_level: str | None = Field(default=None, pattern=_LEVEL)
    incident_id: UUID | None = None


class ExecuteRequest(EvaluateRequest):
    target_type: str = Field(pattern=_TARGET)
    target_id: str = Field(min_length=1, max_length=300)
    parameters: dict[str, Any] = Field(default_factory=dict)
    approval_id: UUID | None = None
    connector_id: UUID | None = None
    dry_run: bool = False

    @field_validator("parameters")
    @classmethod
    def _params(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_parameters(value)


class SimulateRequest(StrictModel):
    action_type: str = Field(min_length=1, max_length=80)
    target_type: str = Field(pattern=_TARGET)
    target_id: str = Field(min_length=1, max_length=300)
    parameters: dict[str, Any] = Field(default_factory=dict)
    requested_level: str | None = Field(default=None, pattern=_LEVEL)
    incident_id: UUID | None = None

    @field_validator("parameters")
    @classmethod
    def _params(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _validate_parameters(value)


class ActionCatalogueItem(StrictModel):
    key: str
    label: str
    description: str
    min_level: str
    risk: str
    reversible: bool
    target_type: str
    capability: str | None
    internal: bool
    approval_required: bool
    ot_allowed: bool
    decision: dict[str, Any]


class ForbiddenActionItem(StrictModel):
    key: str
    reason: str


class ActionCatalogueOut(StrictModel):
    actions: list[ActionCatalogueItem]
    forbidden: list[ForbiddenActionItem]
    org_max_level: str
    policy: dict[str, Any]


class RemediationOut(ORMModel):
    id: UUID
    incident_id: UUID | None
    execution_id: UUID | None
    action_type: str
    target_type: str
    target_id: str
    parameters: dict[str, Any]
    status: str
    risk_level: str
    autonomy_level: str
    authorization_id: UUID | None
    executed_by: str | None
    executed_at: datetime | None
    verified_at: datetime | None
    verification: dict[str, Any]
    rollback_status: str | None
    rollback_output: dict[str, Any]
    evidence_id: UUID | None


class DefenceExecuteResult(StrictModel):
    status: str
    approval_required: bool = False
    approval_id: UUID | None = None
    remediation_id: UUID | None = None
    decision: dict[str, Any] = Field(default_factory=dict)
    remediation: RemediationOut | None = None
    result: dict[str, Any] | None = None


class VerifyRequest(StrictModel):
    recheck: bool = False


class VerifyResult(StrictModel):
    remediation_id: UUID
    recorded: dict[str, Any]
    verified: bool
    rechecked: bool
    checked_at: datetime


class KillSwitchEntry(StrictModel):
    id: UUID
    scope: str
    target_id: str | None
    target_name: str | None
    reason: str
    engaged_at: datetime


class EffectiveKillSwitchesOut(StrictModel):
    org_id: UUID
    global_engaged: bool
    organization_engaged: bool
    autonomy_engaged: bool
    autonomy_halted: bool
    connectors: list[KillSwitchEntry]
    switches: list[KillSwitchEntry]


class PolicySnapshotOut(StrictModel):
    org_id: UUID
    autonomy_level: str
    approval_threshold: str
    policy_id: str | None
    policy_version: int | None
    definition: dict[str, Any]
    evaluated_at: datetime
    kill_switches: EffectiveKillSwitchesOut
