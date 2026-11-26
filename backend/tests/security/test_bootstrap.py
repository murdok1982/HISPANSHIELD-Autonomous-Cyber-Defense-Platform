"""Bootstrap provisioning must never silently elevate an existing account."""

from __future__ import annotations

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.crypto import hash_password
from app.models.core import User
from app.services.bootstrap import BootstrapError, bootstrap_admin


def _existing_user(db: Session, email: str) -> User:
    user = User(
        email=email,
        full_name="Regular Operator",
        password_hash=hash_password("Regular-Passw0rd!2026"),
        is_platform_admin=False,
        status="active",
    )
    db.add(user)
    db.commit()
    return user


def test_bootstrap_refuses_to_promote_existing_non_admin(db: Session) -> None:
    email = "existing.operator@example.eu"
    _existing_user(db, email)

    with pytest.raises(BootstrapError, match="refusing to elevate"):
        bootstrap_admin(
            db,
            email=email,
            password="N3w-Bootstrap-Pass!2026",
            org_name="Bootstrap Org",
            org_slug="bootstrap-org",
        )

    db.rollback()
    user = db.execute(select(User).where(User.email == email)).scalar_one()
    assert user.is_platform_admin is False


def test_bootstrap_explicit_promotion_is_audited(db: Session) -> None:
    email = "reviewed.operator@example.eu"
    _existing_user(db, email)

    user, org, created = bootstrap_admin(
        db,
        email=email,
        password="N3w-Bootstrap-Pass!2026",
        org_name="Bootstrap Org 2",
        org_slug="bootstrap-org-2",
        promote_existing=True,
    )
    assert created is False
    assert user.is_platform_admin is True
    assert org.slug == "bootstrap-org-2"

    from app.models.core import AuditRecord

    actions = db.execute(select(AuditRecord.action).where(AuditRecord.org_id == org.id)).scalars().all()
    assert "platform.bootstrap" in actions
