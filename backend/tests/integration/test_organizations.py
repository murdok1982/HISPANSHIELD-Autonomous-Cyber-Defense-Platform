"""Organization governance, policy, kill switch and audit-chain tests."""

from __future__ import annotations

from datetime import timedelta

from fastapi.testclient import TestClient
from sqlalchemy import select, text

from app.core.db import utcnow
from app.models.core import Approval, AuditRecord, Membership, Organization, Policy, User
from tests.conftest import login


def test_organization_profile_and_update(seeded, auth_client: TestClient) -> None:
    current = auth_client.get("/api/v1/organizations/current")
    assert current.status_code == 200
    assert current.json()["slug"] == "test-org"

    updated = auth_client.patch("/api/v1/organizations/current", json={"autonomy_level": "A2", "sector": "energy"})
    assert updated.status_code == 200
    assert updated.json()["autonomy_level"] == "A2"
    assert updated.json()["sector"] == "energy"


def test_member_lifecycle_and_last_admin_guard(seeded, auth_client: TestClient, db) -> None:
    created = auth_client.post(
        "/api/v1/organizations/current/members",
        json={
            "email": "new.analyst@hispanshield.eu",
            "full_name": "New Analyst",
            "role": "soc_analyst",
            "password": "Analyst-Str0ng-Pass!9",
        },
    )
    assert created.status_code == 201, created.text
    membership_id = created.json()["id"]

    duplicate = auth_client.post(
        "/api/v1/organizations/current/members",
        json={"email": "new.analyst@hispanshield.eu", "full_name": "Dup", "role": "viewer"},
    )
    assert duplicate.status_code == 409

    promoted = auth_client.patch(
        f"/api/v1/organizations/current/members/{membership_id}", json={"role": "org_admin"}
    )
    assert promoted.status_code == 200
    assert promoted.json()["role"] == "org_admin"

    admin_membership = db.execute(
        select(Membership).where(Membership.user_id == seeded["user"].id, Membership.org_id == seeded["org"].id)
    ).scalar_one()
    self_change = auth_client.patch(
        f"/api/v1/organizations/current/members/{admin_membership.id}", json={"status": "suspended"}
    )
    assert self_change.status_code == 409

    removed = auth_client.delete(f"/api/v1/organizations/current/members/{membership_id}")
    assert removed.status_code == 204


def test_policy_versioning(seeded, auth_client: TestClient) -> None:
    created = auth_client.post(
        "/api/v1/organizations/current/policies",
        json={
            "name": "retention-365",
            "kind": "retention",
            "definition": {"security_events_days": 365},
            "description": "One year retention",
        },
    )
    assert created.status_code == 201, created.text
    policy_id = created.json()["id"]
    assert created.json()["version"] == 1

    patched = auth_client.patch(
        f"/api/v1/organizations/current/policies/{policy_id}",
        json={"definition": {"security_events_days": 400}},
    )
    assert patched.status_code == 200
    assert patched.json()["version"] == 2
    assert patched.json()["definition"]["security_events_days"] == 400


def test_kill_switch_lifecycle(seeded, auth_client: TestClient) -> None:
    engaged = auth_client.post(
        "/api/v1/organizations/current/kill-switches",
        json={"scope": "organization", "reason": "Suspicious autonomous activity drill"},
    )
    assert engaged.status_code == 201, engaged.text
    assert engaged.json()["engaged"] is True

    duplicate = auth_client.post(
        "/api/v1/organizations/current/kill-switches",
        json={"scope": "organization", "reason": "Duplicate"},
    )
    assert duplicate.status_code == 409

    released = auth_client.post(f"/api/v1/organizations/current/kill-switches/{engaged.json()['id']}/release")
    assert released.status_code == 200
    assert released.json()["engaged"] is False


def test_audit_chain_detects_tampering(seeded, auth_client: TestClient, db) -> None:
    for index in range(3):
        auth_client.patch("/api/v1/organizations/current", json={"sector": f"sector-{index}"})
    verified = auth_client.get("/api/v1/organizations/current/audit/verify")
    assert verified.status_code == 200
    assert verified.json()["organization"]["valid"] is True
    assert verified.json()["organization"]["checked"] >= 3

    record = db.execute(select(AuditRecord).where(AuditRecord.org_id == seeded["org"].id).limit(1)).scalar_one()
    # Simulate a privileged insider who can disable the append-only trigger.
    db.execute(text("ALTER TABLE audit_records DISABLE TRIGGER audit_records_append_only"))
    db.execute(
        text("UPDATE audit_records SET payload = payload || '{\"tampered\": true}'::jsonb WHERE id = :id"),
        {"id": record.id},
    )
    db.commit()
    db.execute(text("ALTER TABLE audit_records ENABLE TRIGGER audit_records_append_only"))
    db.commit()
    broken = auth_client.get("/api/v1/organizations/current/audit/verify")
    assert broken.status_code == 200
    assert broken.json()["organization"]["valid"] is False


def test_approval_separation_of_duties(seeded, auth_client: TestClient, db) -> None:
    approval = Approval(
        org_id=seeded["org"].id,
        request_type="defensive_action",
        resource_type="incident",
        resource_id="incident-1",
        payload={"action": "isolate_endpoint"},
        status="pending",
        requested_by=str(seeded["user"].id),
        requested_by_user_id=seeded["user"].id,
        expires_at=utcnow() + timedelta(hours=1),
    )
    db.add(approval)
    db.commit()

    own = auth_client.post(
        f"/api/v1/organizations/current/approvals/{approval.id}/decision",
        json={"decision": "approved", "reason": "self approval attempt"},
    )
    assert own.status_code == 403


def test_tenant_cannot_read_other_org(seeded, auth_client: TestClient, db) -> None:
    other = Organization(slug="foreign-org", name="Foreign Org")
    db.add(other)
    db.commit()
    response = auth_client.get(f"/api/v1/organizations/{other.id}")
    assert response.status_code == 200  # platform admin can inspect any org
    member = User(
        email="regular@hispanshield.eu",
        full_name="Regular",
        password_hash=__import__("app.core.crypto", fromlist=["hash_password"]).hash_password("Regular-Str0ng!1"),
        status="active",
    )
    db.add(member)
    db.flush()
    db.add(Membership(org_id=seeded["org"].id, user_id=member.id, role="org_admin", status="active"))
    db.commit()
    auth_client.cookies.clear()
    login(auth_client, email="regular@hispanshield.eu", password="Regular-Str0ng!1")
    denied = auth_client.get(f"/api/v1/organizations/{other.id}")
    assert denied.status_code == 404
