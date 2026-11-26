"""Autonomous defence tests: catalogue, approvals, execution, rollback and kill switches."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.models.assets import Asset
from app.models.core import Approval, AuditRecord, Organization
from app.models.incidents import Incident, Remediation
from app.services.connectors.base import (
    WRITE,
    AdapterResult,
    CapabilitySpec,
    ConnectorAdapter,
    register_adapter,
)
from app.services.connectors.http import request_json
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, login

API = "/api/v1/defence"


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


class DefenceTestAdapter(ConnectorAdapter):
    connector_type = "fake_defence_http"
    display_name = "Fake defence connector"
    vendor = "HISPANSHIELD Tests"
    product = "Local HTTP stub"
    capabilities = (
        CapabilitySpec("revoke_sessions", WRITE, "Revoke sessions", risk="medium"),
        CapabilitySpec("block_ip", WRITE, "Block IP", risk="medium"),
        CapabilitySpec("unblock_ip", WRITE, "Unblock IP", risk="medium"),
        CapabilitySpec("isolate_endpoint", WRITE, "Isolate endpoint", risk="high"),
        CapabilitySpec("unisolate_endpoint", WRITE, "Unisolate endpoint", risk="medium"),
        CapabilitySpec("disable_user", WRITE, "Disable user", risk="high"),
        CapabilitySpec("enable_user", WRITE, "Enable user", risk="medium"),
        CapabilitySpec("restore_configuration", WRITE, "Restore configuration", risk="high"),
        CapabilitySpec("apply_patch", WRITE, "Apply patch", risk="high"),
        CapabilitySpec("notify_webhook", WRITE, "Notify webhook", risk="low"),
    )
    CALLS: list[tuple[str, dict]] = []

    def health_check(self) -> AdapterResult:
        return AdapterResult(ok=True, data={"healthy": True})

    def invoke(self, capability: str, params: dict) -> AdapterResult:
        type(self).CALLS.append((capability, dict(params)))
        if self.base_url:
            response = request_json(
                "POST",
                f"{self.base_url}/action",
                json_body={"capability": capability, "params": params},
                timeout=5,
            )
            return AdapterResult(ok=True, data={**response.data, "capability": capability})
        return AdapterResult(ok=True, data={"capability": capability})

    def verify(self, capability: str, params: dict, result: AdapterResult) -> AdapterResult:
        return AdapterResult(ok=True, data={"verified": True, "capability": capability})


register_adapter(DefenceTestAdapter)


class _Handler(BaseHTTPRequestHandler):
    server_version = "DefenceTest/1.0"

    def do_POST(self) -> None:  # noqa: N802 - http.server API
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        self.server.received.append((self.path, body))  # type: ignore[attr-defined]
        payload = json.dumps({"ok": True, "path": self.path}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args) -> None:
        return


@pytest.fixture
def local_server():
    server = HTTPServer(("127.0.0.1", 0), _Handler)
    server.received = []  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", server.received  # type: ignore[attr-defined]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _reset() -> None:
    DefenceTestAdapter.CALLS.clear()


def _set_autonomy(db, org, level: str) -> None:
    organization = db.get(Organization, org.id)
    organization.autonomy_level = level
    db.commit()


def _connector(db, org_id, base_url: str | None = None):
    from app.models.connectors import Connector

    connector = Connector(
        org_id=org_id,
        name="defence-connector",
        connector_type=DefenceTestAdapter.connector_type,
        base_url=base_url,
        status="healthy",
        enabled=True,
        config={},
    )
    db.add(connector)
    db.commit()
    return connector


def _relax_rollback_threshold(db, org, threshold: str = "A4") -> None:
    """Keep A3 actions approval-gated but let policy-authorized rollbacks run."""
    from app.models.core import Policy

    db.add(
        Policy(
            org_id=org.id,
            name=f"rollback-{uuid4().hex[:8]}",
            kind="autonomy",
            version=2,
            enabled=True,
            definition={"require_approval_from": threshold},
        )
    )
    db.commit()
    stored = db.execute(select(Policy).where(Policy.org_id == org.id)).scalars().all()
    assert any(row.definition.get("require_approval_from") == threshold for row in stored)


def _add_admin(client: TestClient, email: str) -> None:
    response = client.post(
        "/api/v1/organizations/current/members",
        json={
            "email": email,
            "full_name": "Defence Approver",
            "role": "org_admin",
            "password": "Guardian-Str0ng-Pass!9",
        },
    )
    assert response.status_code == 201, response.text


def _switch_user(client: TestClient, email: str, password: str = "Guardian-Str0ng-Pass!9") -> None:
    client.cookies.clear()
    login(client, email=email, password=password)


def _approved_remediation(client: TestClient, *, target: str = "203.0.113.7") -> tuple[str, str]:
    started = client.post(
        f"{API}/execute",
        json={
            "action_type": "ip.block",
            "target_type": "ip",
            "target_id": target,
            "parameters": {"reason": "C2 traffic"},
        },
    )
    assert started.status_code == 202, started.text
    body = started.json()
    approval_id = body["approval_id"]
    remediation_id = body["remediation_id"]
    assert approval_id and remediation_id

    self_approval = client.post(
        f"/api/v1/organizations/current/approvals/{approval_id}/decision",
        json={"decision": "approved", "reason": "self"},
    )
    assert self_approval.status_code == 403

    _add_admin(client, "defence-approver@hispanshield.eu")
    _switch_user(client, "defence-approver@hispanshield.eu")
    approved = client.post(
        f"/api/v1/organizations/current/approvals/{approval_id}/decision",
        json={"decision": "approved", "reason": "validated indicator"},
    )
    assert approved.status_code == 200, approved.text
    _switch_user(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    return approval_id, remediation_id


def test_action_catalogue_and_forbidden_list(auth_client: TestClient) -> None:
    response = auth_client.get(f"{API}/actions")
    assert response.status_code == 200, response.text
    body = response.json()
    keys = {item["key"] for item in body["actions"]}
    assert {"session.revoke", "ip.block", "endpoint.isolate"} <= keys
    forbidden = {item["key"] for item in body["forbidden"]}
    assert {"ot.write_register", "ot.firmware_update", "attack.exploit"} <= forbidden
    assert body["org_max_level"] == "A1"
    ip_block = next(item for item in body["actions"] if item["key"] == "ip.block")
    assert ip_block["decision"]["allowed"] is False
    assert ip_block["approval_required"] is True
    assert "policy_id" in body["policy"]


def test_evaluate_denies_ceiling_and_allows_when_raised(auth_client: TestClient, seeded, db) -> None:
    denied = auth_client.post(
        f"{API}/evaluate", json={"action_type": "session.revoke", "target_type": "identity", "target_id": "u1"}
    )
    assert denied.status_code == 200
    assert denied.json()["allowed"] is False
    assert "ceiling" in denied.json()["reason"]

    _set_autonomy(db, seeded["org"], "A3")
    allowed = auth_client.post(
        f"{API}/evaluate", json={"action_type": "session.revoke", "target_type": "identity", "target_id": "u1"}
    )
    assert allowed.status_code == 200
    assert allowed.json()["allowed"] is True


def test_execute_allowed_action_through_local_connector(auth_client: TestClient, seeded, db, local_server) -> None:
    _reset()
    url, received = local_server
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id, base_url=url)

    response = auth_client.post(
        f"{API}/execute",
        json={
            "action_type": "session.revoke",
            "target_type": "identity",
            "target_id": "compromised-user",
            "parameters": {"reason": "impossible travel"},
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["status"] == "executed"
    assert body["remediation"]["status"] == "executed"
    assert body["result"]["verified"] is True
    assert len(received) == 1
    assert received[0][0] == "/action"
    assert any(capability == "revoke_sessions" for capability, _ in DefenceTestAdapter.CALLS)


def test_execute_requires_approval_and_creates_pending_remediation(
    auth_client: TestClient, seeded, db, local_server
) -> None:
    _reset()
    url, received = local_server
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id, base_url=url)

    response = auth_client.post(
        f"{API}/execute",
        json={"action_type": "ip.block", "target_type": "ip", "target_id": "198.51.100.44"},
    )
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "pending_approval"
    assert body["approval_required"] is True
    assert received == []
    assert DefenceTestAdapter.CALLS == []

    remediation = db.execute(select(Remediation).where(Remediation.id == UUID(body["remediation_id"]))).scalar_one()
    assert remediation.status == "pending_approval"
    approval = db.get(Approval, UUID(body["approval_id"]))
    assert approval.status == "pending"
    assert approval.requested_by_user_id is not None


def test_approved_remediation_executes_and_verifies(auth_client: TestClient, seeded, db, local_server) -> None:
    _reset()
    url, received = local_server
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id, base_url=url)

    _, remediation_id = _approved_remediation(auth_client)
    executed = auth_client.post(f"{API}/remediations/{remediation_id}/execute")
    assert executed.status_code == 200, executed.text
    assert executed.json()["status"] == "executed"
    assert executed.json()["executed_by"] == ADMIN_EMAIL
    assert any(capability == "block_ip" for capability, _ in DefenceTestAdapter.CALLS)
    assert len(received) == 1

    verified = auth_client.post(f"{API}/remediations/{remediation_id}/verify", json={"recheck": True})
    assert verified.status_code == 200, verified.text
    assert verified.json()["verified"] is True
    assert verified.json()["rechecked"] is True
    assert verified.json()["recorded"]["recheck"]["ok"] is True


def test_rollback_reversible_remediation(auth_client: TestClient, seeded, db, local_server) -> None:
    _reset()
    url, received = local_server
    _set_autonomy(db, seeded["org"], "A3")
    _relax_rollback_threshold(db, seeded["org"])
    _connector(db, seeded["org"].id, base_url=url)
    _, remediation_id = _approved_remediation(auth_client, target="203.0.113.23")
    assert auth_client.post(f"{API}/remediations/{remediation_id}/execute").status_code == 200

    rolled_back = auth_client.post(f"{API}/remediations/{remediation_id}/rollback")
    assert rolled_back.status_code == 200, rolled_back.text
    assert rolled_back.json()["rollback_status"] == "success"
    assert any(capability == "unblock_ip" for capability, _ in DefenceTestAdapter.CALLS)
    assert len(received) == 2


def test_rollback_refused_for_non_reversible_action(auth_client: TestClient, seeded, db) -> None:
    _set_autonomy(db, seeded["org"], "A3")
    remediation = Remediation(
        org_id=seeded["org"].id,
        action_type="patch.apply",
        target_type="endpoint",
        target_id="endpoint-1",
        parameters={},
        status="executed",
        risk_level="high",
        autonomy_level="A3",
    )
    db.add(remediation)
    db.commit()
    response = auth_client.post(f"{API}/remediations/{remediation.id}/rollback")
    assert response.status_code == 409
    assert "not reversible" in response.text


def test_kill_switch_blocks_state_changing_action(auth_client: TestClient, seeded, db, local_server) -> None:
    _reset()
    url, received = local_server
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id, base_url=url)
    engaged = auth_client.post(
        "/api/v1/organizations/current/kill-switches",
        json={"scope": "organization", "reason": "Autonomy drill"},
    )
    assert engaged.status_code == 201

    response = auth_client.post(
        f"{API}/execute",
        json={"action_type": "session.revoke", "target_type": "identity", "target_id": "user-9"},
    )
    assert response.status_code == 403
    assert "kill switch" in response.json()["error"]["message"].lower()
    assert received == []
    denial = db.execute(select(AuditRecord).where(AuditRecord.action == "defence.action.denied")).scalars()
    assert list(denial)


def test_ot_asset_is_blocked(auth_client: TestClient, seeded, db, local_server) -> None:
    _reset()
    url, received = local_server
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id, base_url=url)
    asset = Asset(
        org_id=seeded["org"].id,
        asset_key="plc-1",
        name="PLC line 1",
        kind="ot",
        criticality=5,
    )
    db.add(asset)
    db.commit()

    response = auth_client.post(
        f"{API}/execute",
        json={
            "action_type": "configuration.restore",
            "target_type": "asset",
            "target_id": str(asset.id),
        },
    )
    assert response.status_code == 403
    assert "OT" in response.json()["error"]["message"]
    assert received == []
    assert db.execute(select(func.count()).select_from(Remediation)).scalar_one() == 0


def test_unknown_and_forbidden_actions_are_denied(auth_client: TestClient, seeded, db) -> None:
    _set_autonomy(db, seeded["org"], "A3")
    forbidden = auth_client.post(
        f"{API}/execute",
        json={"action_type": "ot.write_register", "target_type": "asset", "target_id": "plc"},
    )
    assert forbidden.status_code == 403
    unknown = auth_client.post(
        f"{API}/execute",
        json={"action_type": "made.up", "target_type": "ip", "target_id": "1.1.1.1"},
    )
    assert unknown.status_code == 403


def test_dry_run_execute_has_no_side_effects(auth_client: TestClient, seeded, db, local_server) -> None:
    _reset()
    url, received = local_server
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id, base_url=url)
    response = auth_client.post(
        f"{API}/execute",
        json={
            "action_type": "session.revoke",
            "target_type": "identity",
            "target_id": "user-dry",
            "dry_run": True,
        },
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "simulated"
    assert received == []
    assert DefenceTestAdapter.CALLS == []
    assert db.execute(select(func.count()).select_from(Remediation)).scalar_one() == 0


def test_policy_snapshot_and_effective_kill_switches(auth_client: TestClient, seeded, db) -> None:
    snapshot = auth_client.get(f"{API}/policy/snapshot")
    assert snapshot.status_code == 200
    body = snapshot.json()
    assert body["org_id"] == str(seeded["org"].id)
    assert body["approval_threshold"] == "A3"
    assert body["kill_switches"]["autonomy_halted"] is False

    auth_client.post(
        "/api/v1/organizations/current/kill-switches",
        json={"scope": "organization", "reason": "Maintenance window"},
    )
    effective = auth_client.get(f"{API}/kill-switches/effective")
    assert effective.status_code == 200
    assert effective.json()["organization_engaged"] is True
    assert effective.json()["autonomy_halted"] is True

    refreshed = auth_client.get(f"{API}/policy/snapshot").json()
    assert refreshed["kill_switches"]["organization_engaged"] is True


def test_ceiling_denial_leaves_no_remediation(auth_client: TestClient, seeded, db, local_server) -> None:
    _reset()
    url, received = local_server
    _connector(db, seeded["org"].id, base_url=url)
    # Organization is still A1: session.revoke needs A2.
    response = auth_client.post(
        f"{API}/execute",
        json={"action_type": "session.revoke", "target_type": "identity", "target_id": "user-1"},
    )
    assert response.status_code == 403
    assert received == []
    assert db.execute(select(func.count()).select_from(Remediation)).scalar_one() == 0


def test_simulate_alias_returns_plan(auth_client: TestClient, seeded, db, local_server) -> None:
    url, received = local_server
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id, base_url=url)
    response = auth_client.post(
        f"{API}/simulate",
        json={
            "action_type": "ip.block",
            "target_type": "ip",
            "target_id": "203.0.113.88",
            "parameters": {"reason": "test"},
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["decision"]["requires_approval"] is True
    assert body["plan"]["requires_approval"] is True
    assert body["plan"]["connector"]["capability"] == "block_ip"
    assert received == []


def test_remediation_filters_and_incident_linkage(auth_client: TestClient, seeded, db, local_server) -> None:
    _reset()
    url, _received = local_server
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id, base_url=url)
    incident = auth_client.post("/api/v1/incidents", json={"title": "Defence incident", "severity": "high"}).json()

    executed = auth_client.post(
        f"{API}/execute",
        json={
            "action_type": "session.revoke",
            "target_type": "identity",
            "target_id": "user-incident",
            "incident_id": incident["id"],
        },
    )
    assert executed.status_code == 200, executed.text
    remediation_id = executed.json()["remediation_id"]

    listed = auth_client.get(f"{API}/remediations", params={"incident_id": incident["id"]})
    assert listed.status_code == 200
    assert listed.json()["meta"]["total"] == 1
    assert listed.json()["items"][0]["id"] == remediation_id
    detail = auth_client.get(f"{API}/remediations/{remediation_id}")
    assert detail.status_code == 200
    assert detail.json()["incident_id"] == incident["id"]

    assert auth_client.get(f"{API}/remediations/{uuid4()}").status_code == 404
    assert auth_client.get(f"{API}/remediations", params={"sort": "inject"}).status_code == 422


def test_approval_expiry_blocks_remediation_execution(auth_client: TestClient, seeded, db, local_server) -> None:
    from datetime import timedelta

    from app.core.db import utcnow

    _reset()
    url, _received = local_server
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id, base_url=url)
    started = auth_client.post(
        f"{API}/execute",
        json={"action_type": "ip.block", "target_type": "ip", "target_id": "203.0.113.66"},
    )
    assert started.status_code == 202
    approval = db.get(Approval, UUID(started.json()["approval_id"]))
    approval.status = "approved"
    approval.decided_at = utcnow() - timedelta(days=2)
    approval.expires_at = utcnow() - timedelta(days=1)
    db.commit()
    blocked = auth_client.post(f"{API}/remediations/{started.json()['remediation_id']}/execute")
    assert blocked.status_code == 409


def test_cross_tenant_remediation_is_404(auth_client: TestClient, db) -> None:
    other = Organization(slug="foreign-defence", name="Foreign Defence")
    db.add(other)
    db.commit()
    remediation = Remediation(
        org_id=other.id,
        action_type="ip.block",
        target_type="ip",
        target_id="203.0.113.99",
        parameters={},
        status="pending",
        risk_level="medium",
        autonomy_level="A3",
    )
    db.add(remediation)
    db.commit()
    assert auth_client.get(f"{API}/remediations/{remediation.id}").status_code == 404
    assert auth_client.post(f"{API}/remediations/{remediation.id}/execute").status_code == 404
    assert auth_client.post(f"{API}/remediations/{remediation.id}/rollback").status_code == 404
    assert auth_client.post(f"{API}/remediations/{remediation.id}/verify", json={}).status_code == 404


def test_incident_tenant_validation_on_execute(auth_client: TestClient, seeded, db) -> None:
    _set_autonomy(db, seeded["org"], "A3")
    other = Organization(slug="foreign-defence-2", name="Foreign Defence 2")
    db.add(other)
    db.commit()
    foreign = Incident(
        org_id=other.id,
        ref="HS-2026-9600",
        title="Foreign",
        severity="high",
        status="new",
        priority=2,
        mitre=[],
        affected_asset_ids=[],
    )
    db.add(foreign)
    db.commit()
    response = auth_client.post(
        f"{API}/execute",
        json={
            "action_type": "session.revoke",
            "target_type": "identity",
            "target_id": "user-1",
            "incident_id": str(foreign.id),
        },
    )
    assert response.status_code == 404
