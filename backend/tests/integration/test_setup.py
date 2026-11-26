"""First-run setup endpoint (AC-09)."""

from __future__ import annotations

from sqlalchemy import select

from app.models.compliance import ComplianceFramework
from app.models.core import Membership, Organization, User


def test_setup_creates_first_org_at_a0_and_refuses_replay(client, db) -> None:
    payload = {
        "org_name": "Nova Iberia",
        "org_slug": "nova-iberia",
        "full_name": "Nova Owner",
        "email": "owner@nova-iberia.eu",
        "password": "Str0ng-Setup-Passw0rd!2026",
    }
    response = client.post("/api/v1/setup", json=payload)
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["organization_slug"] == "nova-iberia"
    assert body["autonomy_level"] == "A0"
    assert body["created"] is True

    org = db.execute(select(Organization).where(Organization.slug == "nova-iberia")).scalar_one()
    user = db.execute(select(User).where(User.email == "owner@nova-iberia.eu")).scalar_one()
    assert org.autonomy_level == "A0"
    assert user.is_platform_admin is True
    membership = db.execute(
        select(Membership).where(Membership.org_id == org.id, Membership.user_id == user.id)
    ).scalar_one()
    assert membership.role == "org_admin"

    # A fresh installation must expose the built-in compliance catalogue
    # without a manual seed step (AC-88).
    frameworks = db.execute(select(ComplianceFramework.code).distinct()).scalars().all()
    assert len(frameworks) >= 10
    assert "NIS2" in frameworks

    replay = client.post("/api/v1/setup", json=payload)
    assert replay.status_code == 409
    assert replay.json()["error"]["code"] == "setup_completed"


def test_setup_rejects_weak_password(client) -> None:
    response = client.post(
        "/api/v1/setup",
        json={
            "org_name": "Weak Org",
            "org_slug": "weak-org",
            "email": "weak@example.eu",
            "password": "aaaaaaaaaaaa",
        },
    )
    assert response.status_code == 422
    assert response.json()["error"]["details"][0]["field"] == "password"


def test_setup_token_can_gate_first_run(client, monkeypatch) -> None:
    from app.core.config import settings

    monkeypatch.setattr(settings, "setup_token", "setup-only-token-0123456789", raising=False)
    payload = {
        "org_name": "Token Org",
        "org_slug": "token-org",
        "email": "owner@token-org.eu",
        "password": "Str0ng-Setup-Passw0rd!2026",
    }
    denied = client.post("/api/v1/setup", json=payload)
    assert denied.status_code == 403
    allowed = client.post("/api/v1/setup", json=payload, headers={"X-Setup-Token": "setup-only-token-0123456789"})
    assert allowed.status_code == 201, allowed.text
