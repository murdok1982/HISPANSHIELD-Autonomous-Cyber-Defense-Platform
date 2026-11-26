"""Authentication schemas."""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import EmailStr, Field

from app.core.schemas import ORMModel, StrictModel


class LoginRequest(StrictModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)
    org_slug: str | None = Field(default=None, max_length=80)


class MfaRequiredResponse(StrictModel):
    mfa_required: bool = True
    challenge_token: str
    expires_in: int


class MfaVerifyRequest(StrictModel):
    challenge_token: str = Field(min_length=20, max_length=2000)
    code: str = Field(min_length=6, max_length=8, pattern=r"^\d{6,8}$")


class ChangePasswordRequest(StrictModel):
    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=12, max_length=128)


class MfaActivateRequest(StrictModel):
    code: str = Field(min_length=6, max_length=8, pattern=r"^\d{6,8}$")


class MfaDisableRequest(StrictModel):
    password: str = Field(min_length=1, max_length=128)
    code: str = Field(min_length=6, max_length=8, pattern=r"^\d{6,8}$")


class OrgSummary(ORMModel):
    id: UUID
    slug: str
    name: str
    kind: str
    is_demo: bool = False
    role: str | None = None


class UserProfile(ORMModel):
    id: UUID
    email: str
    full_name: str
    status: str
    is_platform_admin: bool
    mfa_enabled: bool
    locale: str
    timezone: str
    last_login_at: datetime | None
    created_at: datetime


class SessionInfo(StrictModel):
    user: UserProfile
    organization: OrgSummary
    role: str
    permissions: list[str]
    organizations: list[OrgSummary]
    csrf_token: str
    autonomy_level: str
    expires_at: datetime


class SwitchOrgRequest(StrictModel):
    org_id: UUID
    reason: str | None = Field(default=None, max_length=1000)
    ticket: str | None = Field(default=None, max_length=80)


class BreakGlassRequest(StrictModel):
    org_id: UUID
    reason: str = Field(min_length=10, max_length=1000)
    ticket: str = Field(min_length=3, max_length=80)


class BreakGlassResponse(StrictModel):
    grant_id: UUID
    org_id: UUID
    expires_at: datetime
    reason: str
    ticket: str


class ApiTokenCreate(StrictModel):
    name: str = Field(min_length=2, max_length=120)
    scopes: list[str] = Field(default_factory=list, max_length=100)
    expires_days: int | None = Field(default=None, ge=1, le=365)


class ApiTokenCreated(StrictModel):
    id: UUID
    name: str
    token: str
    prefix: str
    scopes: list[str]
    expires_at: datetime | None


class ApiTokenInfo(ORMModel):
    id: UUID
    name: str
    prefix: str
    scopes: list[str]
    created_at: datetime
    expires_at: datetime | None
    last_used_at: datetime | None


class MfaEnrollment(StrictModel):
    secret: str
    otpauth_uri: str
    issuer: str


class PermissionsCatalogue(StrictModel):
    permissions: list[dict[str, str]]
    roles: dict[str, list[str]]
