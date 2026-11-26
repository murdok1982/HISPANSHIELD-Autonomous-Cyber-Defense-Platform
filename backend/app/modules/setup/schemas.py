"""First-run setup schemas."""

from __future__ import annotations

from uuid import UUID

from pydantic import EmailStr, Field

from app.core.schemas import StrictModel


class SetupRequest(StrictModel):
    org_name: str = Field(min_length=2, max_length=200)
    org_slug: str | None = Field(
        default=None, min_length=2, max_length=80, pattern=r"^[a-z0-9](?:[a-z0-9-]{1,78}[a-z0-9])?$"
    )
    full_name: str = Field(default="Platform Administrator", min_length=2, max_length=200)
    email: EmailStr
    password: str = Field(min_length=12, max_length=128)


class SetupResponse(StrictModel):
    organization_id: UUID
    organization_slug: str
    autonomy_level: str
    user_id: UUID
    email: str
    created: bool
