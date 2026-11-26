"""Idempotent initial provisioning of the platform administrator."""

from __future__ import annotations

import re

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import append_audit
from app.core.crypto import hash_password
from app.core.schemas import PasswordPolicyError, validate_password_strength
from app.models.core import Membership, Organization, Policy, User


class BootstrapError(RuntimeError):
    pass


def _slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return (slug or "organization")[:72]


def bootstrap_admin(
    db: Session,
    *,
    email: str,
    password: str,
    full_name: str = "Platform Administrator",
    org_name: str = "HISPANSHIELD",
    org_slug: str | None = None,
    org_kind: str = "private",
) -> tuple[User, Organization, bool]:
    """Create the platform admin and organization if missing.

    Returns (user, organization, created). Existing accounts are never modified,
    so running the script twice cannot reset a production password.
    """
    normalized = email.strip().lower()
    try:
        validate_password_strength(password, email=normalized)
    except PasswordPolicyError as exc:
        raise BootstrapError("Weak bootstrap password: " + "; ".join(exc.violations)) from exc

    existing = db.execute(select(User).where(User.email == normalized)).scalar_one_or_none()
    created = existing is None
    if existing is None:
        user = User(
            email=normalized,
            full_name=full_name,
            password_hash=hash_password(password),
            is_platform_admin=True,
            status="active",
        )
        db.add(user)
        db.flush()
    else:
        user = existing
        user.is_platform_admin = True

    slug = org_slug or _slugify(org_name)
    org = db.execute(select(Organization).where(Organization.slug == slug)).scalar_one_or_none()
    if org is None:
        org = Organization(
            slug=slug,
            name=org_name,
            kind=org_kind,
            country="ES",
            sector="general",
            tier="standard",
            autonomy_level="A1",
            settings={"reporting_timezone": "UTC", "session_notice": "Authorized use only"},
        )
        db.add(org)
        db.flush()

    membership = db.execute(
        select(Membership).where(Membership.org_id == org.id, Membership.user_id == user.id)
    ).scalar_one_or_none()
    if membership is None:
        db.add(
            Membership(
                org_id=org.id,
                user_id=user.id,
                role="org_admin",
                status="active",
            )
        )

    if not db.execute(
        select(Policy).where(Policy.org_id == org.id, Policy.name == "default-autonomy")
    ).scalar_one_or_none():
        db.add(
            Policy(
                org_id=org.id,
                name="default-autonomy",
                kind="autonomy",
                version=1,
                enabled=True,
                description="Baseline defensive autonomy policy",
                definition={
                    "default_level": "A1",
                    "max_level": "A4",
                    "require_approval_from": "A3",
                    "allow_autonomous_actions": ["A0", "A1", "A2"],
                    "denied_asset_kinds_for_automation": ["ot"],
                    "quiet_hours_restrict_to": "A1",
                },
                created_by=str(user.id),
            )
        )

    append_audit(
        db,
        org_id=org.id,
        action="platform.bootstrap",
        resource_type="organization",
        resource_id=str(org.id),
        actor_type="system",
        actor_id=str(user.id),
        actor_email=user.email,
        payload={"created_user": created, "org_slug": org.slug},
    )
    db.commit()
    return user, org, created
