"""Organization, membership, policy, kill-switch, approval and audit API."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import Field

from app.core.schemas import ORMModel, StrictModel


class OrganizationOut(ORMModel):
    id: UUID
    slug: str
    name: str
    kind: str
    country: str
    sector: str
    tier: str
    autonomy_level: str
    status: str
    settings: dict
    is_demo: bool
    created_at: datetime


class OrganizationCreate(StrictModel):
    name: str = Field(min_length=2, max_length=200)
    slug: str = Field(min_length=2, max_length=80, pattern=r"^[a-z0-9](?:[a-z0-9-]{1,78}[a-z0-9])?$")
    kind: str = Field(default="private", pattern="^(private|public|critical_infrastructure|alliance)$")
    country: str = Field(default="ES", min_length=2, max_length=2)
    sector: str = Field(default="general", max_length=80)
    tier: str = Field(default="standard", pattern="^(standard|high|critical)$")
    autonomy_level: str = Field(default="A1", pattern="^A[0-4]$")


class OrganizationPatch(StrictModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    kind: str | None = Field(default=None, pattern="^(private|public|critical_infrastructure|alliance)$")
    country: str | None = Field(default=None, min_length=2, max_length=2)
    sector: str | None = Field(default=None, max_length=80)
    tier: str | None = Field(default=None, pattern="^(standard|high|critical)$")
    autonomy_level: str | None = Field(default=None, pattern="^A[0-4]$")
    settings: dict | None = None


class MemberOut(ORMModel):
    id: UUID
    user_id: UUID
    email: str
    full_name: str
    role: str
    status: str
    mfa_enabled: bool
    last_login_at: datetime | None
    created_at: datetime


class MemberCreate(StrictModel):
    email: str = Field(min_length=5, max_length=255)
    full_name: str = Field(min_length=2, max_length=200)
    role: str = Field(
        pattern="^(org_admin|soc_manager|soc_analyst|incident_responder|threat_analyst|vulnerability_manager|compliance_officer|auditor|viewer)$"
    )
    password: str | None = Field(default=None, min_length=12, max_length=128)


class MemberPatch(StrictModel):
    role: str | None = Field(
        default=None,
        pattern="^(org_admin|soc_manager|soc_analyst|incident_responder|threat_analyst|vulnerability_manager|compliance_officer|auditor|viewer)$",
    )
    status: str | None = Field(default=None, pattern="^(active|suspended)$")


class PolicyOut(ORMModel):
    id: UUID
    org_id: UUID | None
    name: str
    kind: str
    version: int
    enabled: bool
    definition: dict
    description: str | None
    created_at: datetime
    updated_at: datetime


class PolicyCreate(StrictModel):
    name: str = Field(min_length=2, max_length=120)
    kind: str = Field(default="autonomy", pattern="^(autonomy|access|retention|notification)$")
    definition: dict = Field(default_factory=dict)
    description: str | None = Field(default=None, max_length=2000)
    enabled: bool = True


class PolicyPatch(StrictModel):
    definition: dict | None = None
    description: str | None = Field(default=None, max_length=2000)
    enabled: bool | None = None


class KillSwitchOut(ORMModel):
    id: UUID
    org_id: UUID | None
    scope: str
    target_id: str | None
    engaged: bool
    reason: str
    engaged_by: str | None
    engaged_at: datetime
    released_by: str | None
    released_at: datetime | None


class KillSwitchCreate(StrictModel):
    scope: str = Field(pattern="^(global|organization|connector|autonomy)$")
    target_id: str | None = Field(default=None, max_length=80)
    reason: str = Field(min_length=5, max_length=500)


class ApprovalOut(ORMModel):
    id: UUID
    org_id: UUID
    request_type: str
    resource_type: str
    resource_id: str | None
    payload: dict
    status: str
    requested_by: str | None
    decided_by: UUID | None
    decided_at: datetime | None
    consumed_at: datetime | None = None
    reason: str | None
    expires_at: datetime | None
    created_at: datetime


class ApprovalDecision(StrictModel):
    decision: str = Field(pattern="^(approved|rejected)$")
    reason: str = Field(min_length=3, max_length=1000)


class AuditOut(ORMModel):
    id: UUID
    org_id: UUID | None
    actor_type: str
    actor_id: str | None
    actor_email: str | None
    action: str
    resource_type: str
    resource_id: str | None
    outcome: str
    request_id: str | None
    ip_address: str | None
    payload: dict
    hash: str
    prev_hash: str | None
    created_at: datetime
