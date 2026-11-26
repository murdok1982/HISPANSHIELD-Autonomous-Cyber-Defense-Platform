"""First-run platform setup.

``POST /api/v1/setup`` is intentionally public because a fresh installation has
no accounts. It is safe only while the platform has zero organizations; after
that it returns ``409 setup_completed``. A transaction-scoped advisory lock
makes the zero-check race-free across API replicas.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.crypto import constant_time_equals
from app.core.db import get_db
from app.core.errors import Conflict, Forbidden, ValidationFailure
from app.core.rate_limit import enforce
from app.models.core import Organization
from app.modules.compliance.service import seed_builtin_frameworks
from app.modules.setup.schemas import SetupRequest, SetupResponse
from app.services.bootstrap import BootstrapError, bootstrap_admin

router = APIRouter(prefix="/setup", tags=["Setup"])


def _client_ip(request: Request) -> str:
    return (request.client.host if request.client else "unknown")[:64]


@router.post(
    "", response_model=SetupResponse, status_code=201, summary="Create the first organization and platform owner"
)
def setup(
    payload: SetupRequest,
    request: Request,
    db: Session = Depends(get_db),
    setup_token: str | None = Header(default=None, alias="X-Setup-Token"),
) -> SetupResponse:
    enforce(f"setup:ip:{_client_ip(request)}", 5, 3600)
    if settings.setup_token:
        provided = setup_token or ""
        if not constant_time_equals(provided, settings.setup_token):
            raise Forbidden("A valid X-Setup-Token is required for first-run setup")

    # The lock is released by bootstrap_admin's commit; a concurrent setup
    # request blocks here until it can observe the first organization.
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext('platform:setup'))"))
    existing = db.execute(select(func.count()).select_from(Organization)).scalar_one()
    if int(existing) > 0:
        raise Conflict("Setup has already been completed", code="setup_completed")

    try:
        user, org, created = bootstrap_admin(
            db,
            email=str(payload.email),
            password=payload.password,
            full_name=payload.full_name,
            org_name=payload.org_name,
            org_slug=payload.org_slug,
        )
    except BootstrapError as exc:
        raise ValidationFailure([{"field": "password", "message": str(exc)}]) from exc

    # New organizations start at A0 (observation only). Autonomy is raised
    # explicitly by an administrator after reviewing policy and guardrails.
    org.autonomy_level = "A0"
    db.commit()

    # A fresh installation must expose the built-in compliance catalogue
    # without requiring an out-of-band script. The seed is idempotent and
    # keyed by (code, version), so retries and upgrades are safe.
    seed_builtin_frameworks(db)

    return SetupResponse(
        organization_id=org.id,
        organization_slug=org.slug,
        autonomy_level=org.autonomy_level,
        user_id=user.id,
        email=user.email,
        created=created,
    )


__all__ = ["router"]
