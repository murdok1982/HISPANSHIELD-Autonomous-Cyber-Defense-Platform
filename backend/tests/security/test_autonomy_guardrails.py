"""Autonomy guardrails: ceilings, approvals, kill switches, OT and separation of duties."""

from __future__ import annotations

import hashlib
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.models.assets import Asset
from app.models.core import Approval, AuditRecord, Organization, Policy
from app.models.incidents import Remediation
from app.services.connectors.base import (
    WRITE,
    AdapterResult,
    CapabilitySpec,
    ConnectorAdapter,
    register_adapter,
)
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, login

DEFENCE = "/api/v1/defence"
SOAR = "/api/v1/soar"
INCIDENTS = "/api/v1/incidents"


@pytest.fixture(scope="session", autouse=True)
def _disable_audit_truncate_guard(migrate_database):
    """Allow the shared TRUNCATE cleanup to reset the test database.

    Migration 0003 installs a production guard that blocks TRUNCATE on the
    append-only audit trail; the platform test cleanup still truncates every
    table. Tests never mutate audit rows, so user triggers are disabled for this
    test database only (the guard stays active in production).
    """
    from sqlalchemy import text

    from app.core.db import engine

    with engine.begin() as connection:
        connection.execute(text("ALTER TABLE audit_records DISABLE TRIGGER USER"))
    yield


class GuardTestAdapter(ConnectorAdapter):
    connector_type = "fake_guard_local"
    display_name = "Fake guardrail connector"
    vendor = "HISPANSHIELD Tests"
    product = "Guard stub"
    capabilities = (
        CapabilitySpec("revoke_sessions", WRITE, "Revoke sessions", risk="medium"),
        CapabilitySpec("block_ip", WRITE, "Block IP", risk="medium"),
        CapabilitySpec("unblock_ip", WRITE, "Unblock IP", risk="medium"),
    )
    CALLS: list[tuple[str, dict]] = []

    def health_check(self) -> AdapterResult:
        return AdapterResult(ok=True, data={"healthy": True})

    def invoke(self, capability: str, params: dict) -> AdapterResult:
        type(self).CALLS.append((capability, dict(params)))
        return AdapterResult(ok=True, data={"capability": capability})

    def verify(self, capability: str, params: dict, result: AdapterResult) -> AdapterResult:
        return AdapterResult(ok=True, data={"verified": True})


register_adapter(GuardTestAdapter)


def _reset() -> None:
    GuardTestAdapter.CALLS.clear()


def _set_autonomy(db, org, level: str) -> None:
    organization = db.get(Organization, org.id)
    organization.autonomy_level = level
    db.commit()


def _connector(db, org_id) -> None:
    from app.models.connectors import Connector

    db.add(
        Connector(
            org_id=org_id,
            name="guard-connector",
            connector_type=GuardTestAdapter.connector_type,
            status="healthy",
            enabled=True,
            config={},
        )
    )
    db.commit()


def _add_member(client: TestClient, email: str, role: str) -> None:
    response = client.post(
        "/api/v1/organizations/current/members",
        json={
            "email": email,
            "full_name": "Guardrail Member",
            "role": role,
            "password": "Guardian-Str0ng-Pass!9",
        },
    )
    assert response.status_code == 201, response.text


def _switch(client: TestClient, email: str, password: str = "Guardian-Str0ng-Pass!9") -> None:
    client.cookies.clear()
    login(client, email=email, password=password)


def _execute(client: TestClient, payload: dict):
    return client.post(f"{DEFENCE}/execute", json=payload)


def test_a1_org_cannot_execute_a2_action(auth_client: TestClient, seeded, db) -> None:
    _reset()
    _connector(db, seeded["org"].id)
    response = _execute(
        auth_client,
        {"action_type": "session.revoke", "target_type": "identity", "target_id": "user-1"},
    )
    assert response.status_code == 403
    assert "ceiling" in response.json()["error"]["message"]
    assert GuardTestAdapter.CALLS == []
    assert db.execute(select(func.count()).select_from(Remediation)).scalar_one() == 0


def test_a2_org_cannot_execute_a3_action(auth_client: TestClient, seeded, db) -> None:
    _reset()
    _set_autonomy(db, seeded["org"], "A2")
    _connector(db, seeded["org"].id)
    response = _execute(
        auth_client,
        {"action_type": "ip.block", "target_type": "ip", "target_id": "203.0.113.50"},
    )
    assert response.status_code == 403
    assert "ceiling" in response.json()["error"]["message"]
    # A ceiling denial must not generate an approval request.
    assert db.execute(select(func.count()).select_from(Approval)).scalar_one() == 0
    assert GuardTestAdapter.CALLS == []


def test_approval_gate_pauses_instead_of_executing(auth_client: TestClient, seeded, db) -> None:
    _reset()
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id)
    response = _execute(
        auth_client,
        {"action_type": "ip.block", "target_type": "ip", "target_id": "203.0.113.51"},
    )
    assert response.status_code == 202
    assert response.json()["status"] == "pending_approval"
    assert GuardTestAdapter.CALLS == []
    approval = db.execute(select(Approval)).scalar_one()
    assert approval.status == "pending"
    assert approval.requested_by_user_id is not None


def test_kill_switch_halts_autonomy(auth_client: TestClient, seeded, db) -> None:
    _reset()
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id)
    engaged = auth_client.post(
        "/api/v1/organizations/current/kill-switches",
        json={
            "scope": "autonomy",
            "target_id": str(seeded["org"].id),
            "reason": "Containment drill",
        },
    )
    assert engaged.status_code == 201
    response = _execute(
        auth_client,
        {"action_type": "session.revoke", "target_type": "identity", "target_id": "user-2"},
    )
    assert response.status_code == 403
    assert "kill switch" in response.json()["error"]["message"].lower()
    assert GuardTestAdapter.CALLS == []


def test_ot_asset_denied_even_with_approval_capable_org(auth_client: TestClient, seeded, db) -> None:
    _reset()
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id)
    asset = Asset(
        org_id=seeded["org"].id,
        asset_key="plc-guard",
        name="Safety PLC",
        kind="ot",
        criticality=5,
        environment="production",
    )
    db.add(asset)
    db.commit()
    response = _execute(
        auth_client,
        {
            "action_type": "configuration.restore",
            "target_type": "asset",
            "target_id": str(asset.id),
        },
    )
    assert response.status_code == 403
    assert "OT" in response.json()["error"]["message"]
    assert GuardTestAdapter.CALLS == []
    assert db.execute(select(func.count()).select_from(Approval)).scalar_one() == 0


def test_forbidden_action_classes_never_execute(auth_client: TestClient, seeded, db) -> None:
    _reset()
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id)
    for action_type, target_type, target_id in (
        ("ot.write_register", "asset", "plc-1"),
        ("ot.firmware_update", "asset", "plc-1"),
        ("attack.exploit", "ip", "203.0.113.1"),
        ("not.a.real.action", "ip", "203.0.113.1"),
    ):
        response = _execute(
            auth_client,
            {"action_type": action_type, "target_type": target_type, "target_id": target_id},
        )
        assert response.status_code == 403, action_type
    assert GuardTestAdapter.CALLS == []
    denials = db.execute(select(AuditRecord).where(AuditRecord.action == "defence.action.denied")).scalars()
    assert len(list(denials)) == 4


def test_playbook_rejects_forbidden_ot_action(auth_client: TestClient) -> None:
    definition = {
        "steps": [
            {
                "key": "firmware",
                "name": "Flash firmware",
                "action": "defence.execute",
                "params": {
                    "action_type": "ot.firmware_update",
                    "target_type": "asset",
                    "target_id": "plc-1",
                },
            }
        ]
    }
    response = auth_client.post(f"{SOAR}/playbooks", json={"name": "OT firmware", "definition": definition})
    assert response.status_code == 422


def test_playbook_high_risk_defence_requires_approval_step(auth_client: TestClient) -> None:
    definition = {
        "steps": [
            {
                "key": "isolate",
                "name": "Isolate",
                "action": "defence.execute",
                "params": {
                    "action_type": "endpoint.isolate",
                    "target_type": "endpoint",
                    "target_id": "host-1",
                },
            }
        ]
    }
    response = auth_client.post(f"{SOAR}/playbooks", json={"name": "Unapproved isolate", "definition": definition})
    assert response.status_code == 422
    assert "internal.request_approval" in response.text


def test_separation_of_duties_requester_cannot_approve(auth_client: TestClient, seeded, db) -> None:
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id)
    started = _execute(
        auth_client,
        {"action_type": "ip.block", "target_type": "ip", "target_id": "203.0.113.52"},
    )
    assert started.status_code == 202
    approval_id = started.json()["approval_id"]
    own = auth_client.post(
        f"/api/v1/organizations/current/approvals/{approval_id}/decision",
        json={"decision": "approved", "reason": "self approval"},
    )
    assert own.status_code == 403
    assert db.get(Approval, UUID(approval_id)).status == "pending"


def test_approval_is_bound_to_action_and_target(auth_client: TestClient, seeded, db) -> None:
    _reset()
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id)
    started = _execute(
        auth_client,
        {"action_type": "ip.block", "target_type": "ip", "target_id": "203.0.113.53"},
    )
    assert started.status_code == 202
    approval_id = started.json()["approval_id"]

    _add_member(auth_client, "guard-approver@hispanshield.eu", "org_admin")
    _switch(auth_client, "guard-approver@hispanshield.eu")
    approved = auth_client.post(
        f"/api/v1/organizations/current/approvals/{approval_id}/decision",
        json={"decision": "approved", "reason": "validated"},
    )
    assert approved.status_code == 200
    _switch(auth_client, ADMIN_EMAIL, ADMIN_PASSWORD)

    mismatched = _execute(
        auth_client,
        {
            "action_type": "ip.block",
            "target_type": "ip",
            "target_id": "198.51.100.99",
            "approval_id": approval_id,
        },
    )
    assert mismatched.status_code == 403
    assert GuardTestAdapter.CALLS == []


def test_rollback_requires_reversible_catalogue_action(auth_client: TestClient, seeded, db) -> None:
    _set_autonomy(db, seeded["org"], "A3")
    remediation = Remediation(
        org_id=seeded["org"].id,
        action_type="configuration.restore",
        target_type="asset",
        target_id="router-1",
        parameters={},
        status="executed",
        risk_level="high",
        autonomy_level="A3",
    )
    db.add(remediation)
    db.commit()
    response = auth_client.post(f"{DEFENCE}/remediations/{remediation.id}/rollback")
    assert response.status_code == 409


def test_playbook_dry_run_never_calls_connector(auth_client: TestClient, seeded, db) -> None:
    _reset()
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id)
    definition = {
        "steps": [
            {
                "key": "approval",
                "name": "Request approval",
                "action": "internal.request_approval",
                "params": {
                    "action_type": "ip.block",
                    "target_type": "ip",
                    "target_id": "203.0.113.54",
                },
            },
            {
                "key": "block",
                "name": "Block",
                "action": "defence.execute",
                "params": {
                    "action_type": "ip.block",
                    "target_type": "ip",
                    "target_id": "203.0.113.54",
                },
            },
        ]
    }
    created = auth_client.post(f"{SOAR}/playbooks", json={"name": "Dry guard", "definition": definition})
    assert created.status_code == 201, created.text
    published = auth_client.post(f"{SOAR}/playbooks/{created.json()['id']}/publish")
    assert published.status_code == 200
    execution = auth_client.post(f"{SOAR}/executions", json={"playbook_id": created.json()["id"], "dry_run": True})
    assert execution.status_code == 201, execution.text
    assert execution.json()["status"] == "simulated"
    assert GuardTestAdapter.CALLS == []
    assert db.execute(select(func.count()).select_from(Approval)).scalar_one() == 0


def test_evidence_viewer_denied_and_audited(auth_client: TestClient, db, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HS_EVIDENCE_DIR", str(tmp_path / "evidence"))
    incident = auth_client.post(f"{INCIDENTS}", json={"title": "Evidence access test", "severity": "medium"}).json()
    uploaded = auth_client.post(
        f"{INCIDENTS}/{incident['id']}/evidence",
        files={"file": ("audit.log", b"restricted forensic data", "text/plain")},
        data={"title": "Restricted log"},
    )
    assert uploaded.status_code == 201
    evidence_id = uploaded.json()["id"]
    _add_member(auth_client, "guard-viewer@hispanshield.eu", "viewer")
    _switch(auth_client, "guard-viewer@hispanshield.eu")
    denied = auth_client.get(f"{INCIDENTS}/evidence/{evidence_id}/download")
    assert denied.status_code == 403
    failures = list(
        db.execute(
            select(AuditRecord).where(
                AuditRecord.action == "incident.evidence.download", AuditRecord.outcome == "failure"
            )
        ).scalars()
    )
    assert failures
    assert "audit.log" not in (failures[0].payload or {}).get("reason", "")


def test_evidence_magic_byte_cannot_be_spoofed(auth_client: TestClient, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HS_EVIDENCE_DIR", str(tmp_path / "evidence"))
    incident = auth_client.post(f"{INCIDENTS}", json={"title": "Magic bytes", "severity": "low"}).json()
    spoof = auth_client.post(
        f"{INCIDENTS}/{incident['id']}/evidence",
        files={"file": ("report.pdf", b"#!/bin/sh\nrm -rf /", "application/pdf")},
    )
    assert spoof.status_code == 422
    valid_pdf = auth_client.post(
        f"{INCIDENTS}/{incident['id']}/evidence",
        files={"file": ("report.pdf", b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n", "application/pdf")},
        data={"title": "Real PDF"},
    )
    assert valid_pdf.status_code == 201, valid_pdf.text
    assert valid_pdf.json()["content_type"] == "application/pdf"


def test_policy_is_deny_by_default_for_unknown_levels(auth_client: TestClient, seeded, db) -> None:
    _set_autonomy(db, seeded["org"], "A3")
    response = _execute(
        auth_client,
        {
            "action_type": "session.revoke",
            "target_type": "identity",
            "target_id": "user-1",
            "requested_level": "A9",
        },
    )
    assert response.status_code == 422


def test_policy_versions_cannot_lower_catalogue_floor(auth_client: TestClient, seeded, db) -> None:
    _set_autonomy(db, seeded["org"], "A3")
    db.add(
        Policy(
            org_id=seeded["org"].id,
            name="lower-floor",
            kind="autonomy",
            version=3,
            enabled=True,
            definition={"action_levels": {"ip.block": "A1"}},
        )
    )
    db.commit()
    decision = auth_client.post(
        f"{DEFENCE}/evaluate",
        json={"action_type": "ip.block", "target_type": "ip", "target_id": "203.0.113.55"},
    )
    assert decision.status_code == 200
    assert decision.json()["effective_level"] == "A3"
    assert decision.json()["requires_approval"] is True


def test_playbook_simulation_has_no_side_effects(auth_client: TestClient, seeded, db) -> None:
    _reset()
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id)
    definition = {
        "steps": [
            {
                "key": "approval",
                "name": "Approval",
                "action": "internal.request_approval",
                "params": {"action_type": "ip.block", "target_type": "ip", "target_id": "203.0.113.56"},
            },
            {
                "key": "block",
                "name": "Block",
                "action": "defence.execute",
                "params": {"action_type": "ip.block", "target_type": "ip", "target_id": "203.0.113.56"},
            },
        ]
    }
    created = auth_client.post(f"{SOAR}/playbooks", json={"name": "Simulation guard", "definition": definition}).json()
    auth_client.post(f"{SOAR}/playbooks/{created['id']}/publish")
    response = auth_client.post(
        f"{SOAR}/playbooks/{created['id']}/simulate", json={"context": {"alert": {"severity": "critical"}}}
    )
    assert response.status_code == 200
    assert response.json()["steps"][1]["approval_required"] is True
    assert GuardTestAdapter.CALLS == []
    assert db.execute(select(func.count()).select_from(Approval)).scalar_one() == 0
    assert db.execute(select(func.count()).select_from(Remediation)).scalar_one() == 0


def test_ot_asset_cannot_be_targeted_via_endpoint_type(auth_client: TestClient, seeded, db) -> None:
    _reset()
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id)
    asset = Asset(
        org_id=seeded["org"].id,
        asset_key="ot-endpoint",
        name="OT gateway",
        kind="ot",
        criticality=5,
    )
    db.add(asset)
    db.commit()
    response = _execute(
        auth_client,
        {
            "action_type": "endpoint.isolate",
            "target_type": "endpoint",
            "target_id": str(asset.id),
        },
    )
    assert response.status_code == 403
    assert "OT" in response.json()["error"]["message"]
    assert GuardTestAdapter.CALLS == []


def test_requested_level_cannot_bypass_ceiling(auth_client: TestClient, seeded, db) -> None:
    _reset()
    _set_autonomy(db, seeded["org"], "A2")
    _connector(db, seeded["org"].id)
    denied = _execute(
        auth_client,
        {
            "action_type": "ip.block",
            "target_type": "ip",
            "target_id": "203.0.113.58",
            "requested_level": "A4",
        },
    )
    assert denied.status_code == 403
    assert "ceiling" in denied.json()["error"]["message"]
    assert GuardTestAdapter.CALLS == []

    preview = auth_client.post(
        f"{DEFENCE}/evaluate",
        json={
            "action_type": "ip.block",
            "target_type": "ip",
            "target_id": "203.0.113.58",
            "requested_level": "A4",
        },
    )
    assert preview.status_code == 200
    assert preview.json()["allowed"] is False
    assert preview.json()["org_max_level"] == "A2"


def test_evidence_hash_is_reproducible(auth_client: TestClient, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("HS_EVIDENCE_DIR", str(tmp_path / "evidence"))
    incident = auth_client.post(f"{INCIDENTS}", json={"title": "Hash proof"}).json()
    payload = b'{"event": "logon", "user": "alice"}'
    response = auth_client.post(
        f"{INCIDENTS}/{incident['id']}/evidence",
        files={"file": ("events.json", payload, "application/json")},
        data={"title": "JSON events"},
    )
    assert response.status_code == 201
    assert response.json()["sha256"] == hashlib.sha256(payload).hexdigest()


def test_foreign_organization_cannot_be_used_as_target(auth_client: TestClient, db) -> None:
    other = Organization(slug="guard-foreign", name="Guard Foreign")
    db.add(other)
    db.commit()
    response = _execute(
        auth_client,
        {
            "action_type": "ip.block",
            "target_type": "ip",
            "target_id": "203.0.113.57",
            "incident_id": str(uuid4()),
        },
    )
    assert response.status_code == 404
