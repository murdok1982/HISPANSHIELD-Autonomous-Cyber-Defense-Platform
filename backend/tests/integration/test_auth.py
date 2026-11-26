"""Authentication, session and tenancy regression tests."""

from __future__ import annotations

from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.core.crypto import hash_password
from app.core.db import utcnow
from app.core.errors import Unauthorized
from app.models.core import Membership, Organization, User
from app.models.core import Session as AuthSession
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, login


def test_health_endpoints(client: TestClient) -> None:
    assert client.get("/healthz").json()["status"] == "ok"
    ready = client.get("/readyz")
    assert ready.status_code == 200
    assert ready.json()["status"] == "ready"


def test_login_me_and_logout(seeded, client: TestClient) -> None:
    response = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["user"]["email"] == ADMIN_EMAIL
    assert body["organization"]["slug"] == "test-org"
    assert "audit:read" in body["permissions"]
    assert client.cookies.get("hs_session")
    csrf = client.cookies.get("hs_csrf")

    client.headers.update({"X-CSRF-Token": csrf})
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["user"]["id"] == str(seeded["user"].id)

    logout = client.post("/api/v1/auth/logout")
    assert logout.status_code == 200
    assert client.get("/api/v1/auth/me").status_code == 401


def test_login_rejects_bad_credentials(seeded, client: TestClient) -> None:
    response = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": "wrong-password"})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "unauthorized"
    assert "request_id" in response.json()["error"]


def test_login_unknown_email_is_generic(client: TestClient) -> None:
    response = client.post("/api/v1/auth/login", json={"email": "nobody@example.eu", "password": "irrelevant"})
    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Invalid email or password"


def test_csrf_required_for_session_mutations(seeded, client: TestClient) -> None:
    login(client)
    client.headers.pop("X-CSRF-Token", None)
    response = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": ADMIN_PASSWORD, "new_password": "An0ther-Strong-Pass!"},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "forbidden"


def test_tenant_isolation_hides_foreign_organization(seeded, client: TestClient, db) -> None:
    other_org = Organization(slug="other-org", name="Other Organisation", kind="public")
    db.add(other_org)
    db.flush()
    stranger = User(
        email="stranger@other.eu",
        full_name="Stranger",
        password_hash=hash_password("Str0ng-Stranger-Pass!1"),
        status="active",
    )
    db.add(stranger)
    db.flush()
    db.add(Membership(org_id=other_org.id, user_id=stranger.id, role="org_admin", status="active"))
    db.commit()

    member = User(
        email="member@hispanshield.eu",
        full_name="Member",
        password_hash=hash_password("Member-Str0ng-Pass!1"),
        status="active",
    )
    db.add(member)
    db.flush()
    db.add(Membership(org_id=seeded["org"].id, user_id=member.id, role="org_admin", status="active"))
    db.commit()

    login(client, email="member@hispanshield.eu", password="Member-Str0ng-Pass!1")
    response = client.get("/api/v1/auth/me", headers={"X-Organization-Id": str(other_org.id)})
    assert response.status_code == 404


def test_break_glass_requires_a_second_approver_when_one_exists(seeded, auth_client: TestClient, db) -> None:
    from app.main import app

    other_org = Organization(slug="dual-control-org", name="Dual Control Org", kind="public")
    db.add(other_org)
    approver = User(
        email="second.admin@example.eu",
        full_name="Second Platform Admin",
        password_hash=hash_password("S3cond-Admin-Pass!2026"),
        is_platform_admin=True,
        status="active",
    )
    db.add(approver)
    db.flush()
    db.add(Membership(org_id=seeded["org"].id, user_id=approver.id, role="org_admin", status="active"))
    db.commit()

    requested = auth_client.post(
        "/api/v1/auth/break-glass",
        json={
            "org_id": str(other_org.id),
            "reason": "Incident response requires access to the public body tenant",
            "ticket": "INC-2026-0042",
        },
    )
    assert requested.status_code == 200, requested.text
    grant = requested.json()
    assert grant["status"] == "pending"

    self_approval = auth_client.post(f"/api/v1/auth/break-glass/{grant['grant_id']}/approve")
    assert self_approval.status_code == 403

    with TestClient(app) as approver_client:
        login(approver_client, "second.admin@example.eu", "S3cond-Admin-Pass!2026")
        approved = approver_client.post(f"/api/v1/auth/break-glass/{grant['grant_id']}/approve")
        assert approved.status_code == 200, approved.text
        assert approved.json()["status"] == "approved"
        assert approved.json()["approved_by"] == str(approver.id)

    access = auth_client.get("/api/v1/auth/me", headers={"X-Organization-Id": str(other_org.id)})
    assert access.status_code == 200
    assert access.json()["organization"]["id"] == str(other_org.id)


def test_break_glass_is_not_created_implicitly_by_switch_org(seeded, auth_client: TestClient, db) -> None:
    other_org = Organization(slug="implicit-org", name="Implicit Org", kind="public")
    db.add(other_org)
    db.commit()

    switched = auth_client.post(
        "/api/v1/auth/switch-org",
        json={
            "org_id": str(other_org.id),
            "reason": "Trying to bypass an explicit grant",
            "ticket": "CHG-2026-9999",
        },
    )
    assert switched.status_code == 403
    assert switched.json()["error"]["message"].startswith("break_glass_required")


def test_platform_admin_can_select_organization(seeded, client: TestClient, db) -> None:
    other_org = Organization(slug="public-body", name="Public Body", kind="public")
    db.add(other_org)
    db.commit()
    login(client)
    denied = client.get("/api/v1/auth/me", headers={"X-Organization-Id": str(other_org.id)})
    assert denied.status_code == 404
    assert denied.json()["error"]["code"] == "not_found"

    grant = client.post(
        "/api/v1/auth/break-glass",
        json={
            "org_id": str(other_org.id),
            "reason": "Incident response for public body",
            "ticket": "INC-2026-0001",
        },
    )
    assert grant.status_code == 200, grant.text
    response = client.get("/api/v1/auth/me", headers={"X-Organization-Id": str(other_org.id)})
    assert response.status_code == 200
    assert response.json()["organization"]["id"] == str(other_org.id)
    assert response.json()["role"] == "platform_admin"


def test_expired_session_is_rejected(seeded, client: TestClient, db) -> None:
    login(client)
    session = db.execute(select(AuthSession)).scalars().first()
    session.expires_at = utcnow() - timedelta(minutes=1)
    db.commit()
    assert client.get("/api/v1/auth/me").status_code == 401


def test_of_org_header_requires_membership(seeded, client: TestClient, db) -> None:
    login(client)
    response = client.get("/api/v1/auth/me", headers={"X-Organization-Id": "00000000-0000-0000-0000-000000000000"})
    assert response.status_code == 404


def test_api_token_authentication_and_scope(seeded, client: TestClient) -> None:
    login(client)
    created = client.post(
        "/api/v1/auth/api-tokens",
        json={"name": "ci", "scopes": ["incident:read"], "expires_days": 1},
    )
    assert created.status_code == 201, created.text
    token = created.json()["token"]
    assert token.startswith("hs_")

    client.cookies.clear()
    client.headers.clear()
    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json()["role"] == "api_token"


def test_api_token_cannot_escalate_scopes(seeded, client: TestClient, db) -> None:
    analyst = User(
        email="analyst@test-org.eu",
        full_name="Analyst",
        password_hash=hash_password("Analyst-Str0ng-Pass!1"),
        status="active",
    )
    db.add(analyst)
    db.flush()
    db.add(Membership(org_id=seeded["org"].id, user_id=analyst.id, role="soc_analyst", status="active"))
    db.commit()

    login(client, email="analyst@test-org.eu", password="Analyst-Str0ng-Pass!1")
    response = client.post(
        "/api/v1/auth/api-tokens",
        json={"name": "escalate", "scopes": ["user:manage"]},
    )
    assert response.status_code == 403


def test_weak_password_rejected_on_change(seeded, client: TestClient) -> None:
    login(client)
    response = client.post(
        "/api/v1/auth/change-password",
        json={"current_password": ADMIN_PASSWORD, "new_password": "short"},
    )
    assert response.status_code == 422


def test_session_cookie_flags(seeded, client: TestClient) -> None:
    response = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    cookie = response.headers["set-cookie"].lower()
    assert "httponly" in cookie
    assert "samesite=strict" in cookie
    assert settings.cookie_name in cookie


def test_api_token_defaults_to_concrete_permissions_for_platform_admin(seeded, client: TestClient) -> None:
    login(client)
    created = client.post("/api/v1/auth/api-tokens", json={"name": "default-scopes"})
    assert created.status_code == 201, created.text
    scopes = created.json()["scopes"]
    assert scopes and "*" not in scopes
    assert "asset:read" in scopes
    token = created.json()["token"]
    client.cookies.clear()
    client.headers.clear()
    response = client.get("/api/v1/assets", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_login_never_returns_password_or_mfa_material(seeded, client: TestClient) -> None:
    response = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert response.status_code == 200
    raw = response.text
    assert "password_hash" not in raw
    assert "mfa_secret_encrypted" not in raw
    assert "$argon2" not in raw
    for forbidden in ("password", "mfa_secret", "failed_login_count", "locked_until"):
        assert forbidden not in response.json()["user"]


def test_api_token_scopes_are_enforced_on_overview(seeded, client: TestClient) -> None:
    login(client)
    created = client.post("/api/v1/auth/api-tokens", json={"name": "report-only", "scopes": ["report:read"]})
    assert created.status_code == 201
    token = created.json()["token"]
    client.cookies.clear()
    client.headers.clear()
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/v1/overview/executive", headers=headers).status_code == 403
    assert client.get("/api/v1/overview/soc", headers=headers).status_code == 403
    assert client.get("/api/v1/events", headers=headers).status_code == 403
    assert client.get("/api/v1/reports", headers=headers).status_code == 200


def test_idle_session_is_rejected(seeded, client: TestClient, db) -> None:
    login(client)
    session = db.execute(select(AuthSession)).scalars().first()
    session.last_seen_at = utcnow() - timedelta(minutes=90)
    db.commit()
    assert client.get("/api/v1/auth/me").status_code == 401


def test_single_source_cannot_lock_account_for_its_owner(seeded, client: TestClient, db) -> None:
    from app.modules.auth.service import authenticate_password

    for _ in range(6):
        with pytest.raises(Unauthorized):
            authenticate_password(db, email=ADMIN_EMAIL, password="wrong-password", ip="203.0.113.7")
        db.rollback()

    user = db.execute(select(User).where(User.email == ADMIN_EMAIL)).scalar_one()
    assert user.locked_until is None
    response = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert response.status_code == 200, response.text


def test_distributed_failures_still_trigger_a_global_lock(seeded, db) -> None:
    from app.modules.auth.service import authenticate_password

    for index in range(5):
        with pytest.raises(Unauthorized):
            authenticate_password(db, email=ADMIN_EMAIL, password="wrong-password", ip=f"198.51.100.{index}")
        db.rollback()

    user = db.execute(select(User).where(User.email == ADMIN_EMAIL)).scalar_one()
    assert user.locked_until is not None
    with pytest.raises(Unauthorized):
        authenticate_password(db, email=ADMIN_EMAIL, password=ADMIN_PASSWORD, ip="192.0.2.50")
    db.rollback()


def test_user_can_list_and_revoke_other_sessions(seeded, auth_client: TestClient) -> None:
    from app.main import app

    with TestClient(app) as second_client:
        login(second_client)

        listing = auth_client.get("/api/v1/auth/sessions")
        assert listing.status_code == 200, listing.text
        sessions = listing.json()
        assert len(sessions) == 2
        current = [row for row in sessions if row["is_current"]]
        other = [row for row in sessions if not row["is_current"]]
        assert len(current) == 1 and len(other) == 1

        revoked = auth_client.delete(f"/api/v1/auth/sessions/{other[0]['id']}")
        assert revoked.status_code == 204

        # The revoked browser session must be rejected on its next request.
        assert second_client.get("/api/v1/auth/me").status_code == 401

        remaining = auth_client.get("/api/v1/auth/sessions").json()
        assert len(remaining) == 1 and remaining[0]["is_current"] is True

        # A user cannot revoke the session currently in use through this endpoint.
        assert auth_client.delete(f"/api/v1/auth/sessions/{current[0]['id']}").status_code == 403
