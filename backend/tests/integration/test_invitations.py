"""Organization invitations: single use, TTL, role binding and tenant scope."""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select

from app.core.crypto import hash_password
from app.core.db import utcnow
from app.models.core import Invitation, Membership, User
from tests.conftest import login


def _invite(auth_client, email: str = "new-analyst@example.eu", role: str = "soc_analyst"):
    response = auth_client.post(
        "/api/v1/organizations/current/invitations",
        json={"email": email, "role": role},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_invitation_accept_creates_membership_once(auth_client, client, db) -> None:
    invitation = _invite(auth_client)
    assert invitation["token"]
    assert invitation["status"] == "pending"

    # The token is a bearer secret; accepting with a weak password fails.
    weak = client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": invitation["token"], "password": "aaaaaaaaaaaa"},
    )
    assert weak.status_code == 422

    accepted = client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": invitation["token"], "password": "Analyst-Str0ng-Pass!7", "full_name": "New Analyst"},
    )
    assert accepted.status_code == 200, accepted.text
    body = accepted.json()
    assert body["role"] == "soc_analyst"
    assert body["email"] == "new-analyst@example.eu"

    user = db.execute(select(User).where(User.email == "new-analyst@example.eu")).scalar_one()
    membership = db.execute(select(Membership).where(Membership.user_id == user.id)).scalar_one()
    assert membership.role == "soc_analyst"
    stored = db.execute(select(Invitation).where(Invitation.id == invitation["id"])).scalar_one()
    assert stored.status == "consumed"
    assert stored.consumed_at is not None

    replay = client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": invitation["token"], "password": "Analyst-Str0ng-Pass!7"},
    )
    assert replay.status_code == 410
    assert replay.json()["error"]["code"] == "invite_consumed"

    client.cookies.clear()
    login(client, email="new-analyst@example.eu", password="Analyst-Str0ng-Pass!7")
    me = client.get("/api/v1/auth/me")
    assert me.status_code == 200
    assert me.json()["role"] == "soc_analyst"


def test_existing_account_requires_its_password(auth_client, client, db) -> None:
    db.add(
        User(
            email="existing@example.eu",
            full_name="Existing Account",
            password_hash=hash_password("Existing-Str0ng-Pass!7"),
            status="active",
        )
    )
    db.commit()
    invitation = _invite(auth_client, email="existing@example.eu", role="soc_analyst")
    # A token alone must never grant access to an existing account.
    wrong = client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": invitation["token"], "password": "Wrong-Str0ng-Pass!7"},
    )
    assert wrong.status_code == 401
    right = client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": invitation["token"], "password": "Existing-Str0ng-Pass!7"},
    )
    assert right.status_code == 200, right.text
    assert right.json()["already_member"] is False
    user = db.execute(select(User).where(User.email == "existing@example.eu")).scalar_one()
    membership = db.execute(select(Membership).where(Membership.user_id == user.id)).scalar_one()
    assert membership.role == "soc_analyst"


def test_revoked_and_expired_invitations_are_rejected(auth_client, client, db) -> None:
    first = _invite(auth_client, email="revoked@example.eu")
    revoked = auth_client.delete(f"/api/v1/organizations/current/invitations/{first['id']}")
    assert revoked.status_code == 204
    response = client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": first["token"], "password": "Analyst-Str0ng-Pass!7"},
    )
    assert response.status_code == 410
    assert response.json()["error"]["code"] == "invite_revoked"

    second = _invite(auth_client, email="expired@example.eu")
    row = db.execute(select(Invitation).where(Invitation.id == second["id"])).scalar_one()
    row.expires_at = utcnow() - timedelta(minutes=1)
    db.commit()
    response = client.post(
        "/api/v1/auth/invitations/accept",
        json={"token": second["token"], "password": "Analyst-Str0ng-Pass!7"},
    )
    assert response.status_code == 410
    assert response.json()["error"]["code"] == "invite_expired"


def test_pending_invitation_is_unique_per_email(auth_client) -> None:
    _invite(auth_client, email="dup@example.eu")
    duplicate = auth_client.post(
        "/api/v1/organizations/current/invitations",
        json={"email": "dup@example.eu", "role": "viewer"},
    )
    assert duplicate.status_code == 409
    bad_role = auth_client.post(
        "/api/v1/organizations/current/invitations",
        json={"email": "role@example.eu", "role": "platform_admin"},
    )
    assert bad_role.status_code == 422
