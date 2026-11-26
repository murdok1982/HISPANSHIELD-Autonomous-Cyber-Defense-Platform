"""SOAR playbook validation, simulation, durable execution, approval and compensation."""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.models.core import Approval, Notification, Organization
from app.models.incidents import (
    Incident,
    Playbook,
    PlaybookExecution,
    PlaybookStep,
    Remediation,
)
from app.services.connectors.base import (
    READ,
    WRITE,
    AdapterResult,
    CapabilitySpec,
    ConnectorAdapter,
    ConnectorError,
    register_adapter,
)
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, login

API = "/api/v1/soar"


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


class SoarTestAdapter(ConnectorAdapter):
    connector_type = "fake_soar_local"
    display_name = "Fake SOAR connector"
    vendor = "HISPANSHIELD Tests"
    product = "Local stub"
    capabilities = (
        CapabilitySpec("read_events", READ, "Read recent events"),
        CapabilitySpec("flaky_read", READ, "Read that fails once"),
        CapabilitySpec("block_ip", WRITE, "Block an IP", risk="medium"),
        CapabilitySpec("unblock_ip", WRITE, "Unblock an IP", risk="medium"),
    )
    CALLS: list[tuple[str, dict]] = []
    FLAKY_REMAINING = 0

    def health_check(self) -> AdapterResult:
        return AdapterResult(ok=True, data={"healthy": True})

    def invoke(self, capability: str, params: dict) -> AdapterResult:
        type(self).CALLS.append((capability, dict(params)))
        if capability == "flaky_read":
            if type(self).FLAKY_REMAINING > 0:
                type(self).FLAKY_REMAINING -= 1
                raise ConnectorError("transient read failure", retryable=True)
        return AdapterResult(ok=True, data={"capability": capability, "echo": params})

    def verify(self, capability: str, params: dict, result: AdapterResult) -> AdapterResult:
        return AdapterResult(ok=True, data={"verified": True, "capability": capability})


register_adapter(SoarTestAdapter)


def _reset_adapter() -> None:
    SoarTestAdapter.CALLS.clear()
    SoarTestAdapter.FLAKY_REMAINING = 0


def _connector(db, org_id, name: str = "soar-connector"):
    from app.models.connectors import Connector

    connector = Connector(
        org_id=org_id,
        name=name,
        connector_type=SoarTestAdapter.connector_type,
        status="healthy",
        enabled=True,
        config={},
    )
    db.add(connector)
    db.commit()
    return connector


def _incident(client: TestClient, severity: str = "high") -> dict:
    response = client.post(
        "/api/v1/incidents",
        json={"title": "Playbook test incident", "severity": severity},
    )
    assert response.status_code == 201, response.text
    return response.json()


def _simple_definition() -> dict:
    return {
        "steps": [
            {"key": "investigate", "name": "Investigate", "action": "internal.investigate", "params": {}},
            {
                "key": "note",
                "name": "Record triage",
                "action": "internal.add_timeline",
                "params": {"summary": "Playbook triage complete", "kind": "playbook"},
                "condition": {"field": "incident.severity", "op": "in", "value": ["high", "critical"]},
            },
            {
                "key": "notify",
                "name": "Notify responders",
                "action": "internal.notify",
                "params": {"title": "Playbook finished", "body": "Triage complete"},
            },
        ]
    }


def _approval_definition(target: str = "203.0.113.9") -> dict:
    return {
        "steps": [
            {
                "key": "approval",
                "name": "Request approval",
                "action": "internal.request_approval",
                "params": {
                    "action_type": "ip.block",
                    "target_type": "ip",
                    "target_id": target,
                    "justification": "Block malicious indicator",
                },
            },
            {
                "key": "block",
                "name": "Block indicator",
                "action": "defence.execute",
                "params": {
                    "action_type": "ip.block",
                    "target_type": "ip",
                    "target_id": target,
                    "parameters": {"reason": "C2 beacon"},
                },
            },
        ]
    }


def _create_playbook(
    client: TestClient,
    definition: dict,
    *,
    name: str = "Test playbook",
    min_level: str = "A1",
    publish: bool = True,
) -> dict:
    response = client.post(
        f"{API}/playbooks",
        json={"name": name, "definition": definition, "min_autonomy_level": min_level},
    )
    assert response.status_code == 201, response.text
    playbook = response.json()
    if publish:
        published = client.post(f"{API}/playbooks/{playbook['id']}/publish")
        assert published.status_code == 200, published.text
        return published.json()
    return playbook


def _set_autonomy(db, org, level: str) -> None:
    organization = db.get(Organization, org.id)
    organization.autonomy_level = level
    db.commit()


def _add_admin(client: TestClient, email: str) -> None:
    response = client.post(
        "/api/v1/organizations/current/members",
        json={
            "email": email,
            "full_name": "Approver",
            "role": "org_admin",
            "password": "Guardian-Str0ng-Pass!9",
        },
    )
    assert response.status_code == 201, response.text


def _switch_user(client: TestClient, email: str, password: str = "Guardian-Str0ng-Pass!9") -> None:
    client.cookies.clear()
    login(client, email=email, password=password)


def test_playbook_crud_publish_and_versioning(auth_client: TestClient) -> None:
    playbook = _create_playbook(auth_client, _simple_definition(), publish=False)
    assert playbook["status"] == "draft"
    assert playbook["version"] == 1
    assert playbook["published_at"] is None
    assert len(playbook["definition"]["steps"]) == 3

    listed = auth_client.get(f"{API}/playbooks", params={"status": "draft"})
    assert listed.status_code == 200
    assert listed.json()["meta"]["total"] == 1

    patched = auth_client.patch(f"{API}/playbooks/{playbook['id']}", json={"name": "Renamed playbook"})
    assert patched.status_code == 200
    assert patched.json()["name"] == "Renamed playbook"
    assert patched.json()["version"] == 1

    published = auth_client.post(f"{API}/playbooks/{playbook['id']}/publish")
    assert published.status_code == 200
    assert published.json()["status"] == "published"
    assert published.json()["published_at"] is not None

    edited = auth_client.patch(f"{API}/playbooks/{playbook['id']}", json={"description": "Next iteration"})
    assert edited.status_code == 200, edited.text
    assert edited.json()["id"] != playbook["id"]
    assert edited.json()["version"] == 2
    assert edited.json()["status"] == "draft"

    old = auth_client.get(f"{API}/playbooks/{playbook['id']}")
    assert old.json()["status"] == "published"
    assert old.json()["version"] == 1

    archived = auth_client.post(f"{API}/playbooks/{edited.json()['id']}/archive")
    assert archived.status_code == 200
    assert archived.json()["status"] == "archived"
    assert auth_client.post(f"{API}/playbooks/{edited.json()['id']}/archive").status_code == 409


def test_validate_endpoint_reports_errors_and_normalizes(auth_client: TestClient) -> None:
    bad = auth_client.post(
        f"{API}/playbooks/validate",
        json={"definition": {"steps": [{"key": "x", "name": "X", "action": "internal.unknown"}]}},
    )
    assert bad.status_code == 200
    assert bad.json()["valid"] is False
    assert bad.json()["errors"]

    good = auth_client.post(
        f"{API}/playbooks/validate",
        json={"definition": _simple_definition(), "min_autonomy_level": "A2"},
    )
    assert good.status_code == 200
    assert good.json()["valid"] is True
    assert good.json()["normalized"]["steps"][0]["retries"] == 0


def test_validate_rejects_duplicate_keys(auth_client: TestClient) -> None:
    definition = {
        "steps": [
            {"key": "same", "name": "One", "action": "internal.investigate", "params": {}},
            {"key": "same", "name": "Two", "action": "internal.investigate", "params": {}},
        ]
    }
    response = auth_client.post(f"{API}/playbooks", json={"name": "Duplicates", "definition": definition})
    assert response.status_code == 422
    messages = " ".join(item["message"] for item in response.json()["error"]["details"])
    assert "Duplicate step key" in messages


def test_validate_rejects_forbidden_ot_action(auth_client: TestClient) -> None:
    definition = {
        "steps": [
            {
                "key": "write",
                "name": "Write PLC",
                "action": "defence.execute",
                "params": {"action_type": "ot.write_register", "target_id": "10.0.0.1"},
            }
        ]
    }
    response = auth_client.post(f"{API}/playbooks", json={"name": "OT write", "definition": definition})
    assert response.status_code == 422


def test_validate_rejects_too_many_steps(auth_client: TestClient) -> None:
    steps = [
        {"key": f"step{i}", "name": f"Step {i}", "action": "internal.investigate", "params": {}} for i in range(51)
    ]
    response = auth_client.post(f"{API}/playbooks", json={"name": "Too many", "definition": {"steps": steps}})
    assert response.status_code == 422
    assert "50" in response.text


def test_validate_rejects_defence_without_approval(auth_client: TestClient) -> None:
    definition = {
        "steps": [
            {
                "key": "block",
                "name": "Block without approval",
                "action": "defence.execute",
                "params": {"action_type": "ip.block", "target_type": "ip", "target_id": "203.0.113.7"},
            }
        ]
    }
    response = auth_client.post(f"{API}/playbooks", json={"name": "No approval", "definition": definition})
    assert response.status_code == 422
    assert "requires a preceding internal.request_approval" in response.text


def test_validate_rejects_bad_condition_operator(auth_client: TestClient) -> None:
    definition = {
        "steps": [
            {
                "key": "investigate",
                "name": "Investigate",
                "action": "internal.investigate",
                "condition": {"field": "alert.severity", "op": "approximately", "value": "high"},
            }
        ]
    }
    response = auth_client.post(f"{API}/playbooks", json={"name": "Bad op", "definition": definition})
    assert response.status_code == 422


def test_simulate_returns_plan_without_side_effects(auth_client: TestClient, seeded, db) -> None:
    _reset_adapter()
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id)
    playbook = _create_playbook(auth_client, _approval_definition(), name="Block with approval", min_level="A3")

    response = auth_client.post(
        f"{API}/playbooks/{playbook['id']}/simulate",
        json={"context": {"alert": {"severity": "critical", "src_ip": "203.0.113.9"}}},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["summary"]["steps"] == 2
    assert body["steps"][1]["action"] == "defence.execute"
    assert body["steps"][1]["approval_required"] is True
    assert body["steps"][1]["would_execute"] is False
    assert SoarTestAdapter.CALLS == []
    assert db.execute(select(func.count()).select_from(PlaybookExecution)).scalar_one() == 0
    assert db.execute(select(func.count()).select_from(Approval)).scalar_one() == 0


def test_execute_internal_playbook_and_timeline(auth_client: TestClient, seeded, db) -> None:
    incident = _incident(auth_client)
    playbook = _create_playbook(auth_client, _simple_definition())

    response = auth_client.post(
        f"{API}/executions",
        json={"playbook_id": playbook["id"], "incident_id": incident["id"]},
    )
    assert response.status_code == 201, response.text
    execution = response.json()
    assert execution["status"] == "succeeded"
    assert execution["trigger"] == "incident"
    assert execution["incident_id"] == incident["id"]
    assert [step["step_key"] for step in execution["steps"]] == ["investigate", "note", "notify"]
    assert all(step["status"] == "succeeded" for step in execution["steps"])

    timeline = auth_client.get(f"/api/v1/incidents/{incident['id']}/timeline")
    summaries = [item["summary"] for item in timeline.json()["items"]]
    assert "Playbook triage complete" in summaries

    notifications = db.execute(select(Notification).where(Notification.org_id == seeded["org"].id)).scalars()
    assert list(notifications)

    detail = auth_client.get(f"{API}/executions/{execution['id']}")
    assert detail.status_code == 200
    steps = auth_client.get(f"{API}/executions/{execution['id']}/steps")
    assert steps.status_code == 200
    assert len(steps.json()) == 3


def test_condition_false_skips_step(auth_client: TestClient) -> None:
    incident = _incident(auth_client, severity="low")
    playbook = _create_playbook(auth_client, _simple_definition())
    response = auth_client.post(
        f"{API}/executions",
        json={"playbook_id": playbook["id"], "incident_id": incident["id"]},
    )
    assert response.status_code == 201, response.text
    execution = response.json()
    note = next(step for step in execution["steps"] if step["step_key"] == "note")
    assert note["status"] == "skipped"
    assert execution["status"] == "succeeded"


def test_dry_run_execution_records_would_execute(auth_client: TestClient, seeded, db) -> None:
    _reset_adapter()
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id)
    playbook = _create_playbook(auth_client, _approval_definition(), name="Dry run block", min_level="A3")

    response = auth_client.post(
        f"{API}/executions",
        json={"playbook_id": playbook["id"], "dry_run": True, "context": {"alert": {"severity": "high"}}},
    )
    assert response.status_code == 201, response.text
    execution = response.json()
    assert execution["status"] == "simulated"
    assert execution["dry_run"] is True
    assert all(step["status"] == "would_execute" for step in execution["steps"])
    assert SoarTestAdapter.CALLS == []
    assert db.execute(select(func.count()).select_from(Approval)).scalar_one() == 0
    assert db.execute(select(func.count()).select_from(Remediation)).scalar_one() == 0


def test_approval_pause_self_approval_block_and_resume(auth_client: TestClient, seeded, db) -> None:
    _reset_adapter()
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id)
    playbook = _create_playbook(auth_client, _approval_definition(), name="Block with approval", min_level="A3")

    started = auth_client.post(f"{API}/executions", json={"playbook_id": playbook["id"]})
    assert started.status_code == 202, started.text
    execution = started.json()
    assert execution["status"] == "waiting_approval"
    assert execution["approval_id"] is not None
    assert SoarTestAdapter.CALLS == []
    approval_id = execution["approval_id"]

    self_approval = auth_client.post(
        f"/api/v1/organizations/current/approvals/{approval_id}/decision",
        json={"decision": "approved", "reason": "I approve my own action"},
    )
    assert self_approval.status_code == 403

    pending_resume = auth_client.post(f"{API}/executions/{execution['id']}/resume")
    assert pending_resume.status_code == 409

    _add_admin(auth_client, "approver@hispanshield.eu")
    _switch_user(auth_client, "approver@hispanshield.eu")
    approved = auth_client.post(
        f"/api/v1/organizations/current/approvals/{approval_id}/decision",
        json={"decision": "approved", "reason": "Validated the indicator"},
    )
    assert approved.status_code == 200, approved.text

    _switch_user(auth_client, ADMIN_EMAIL, ADMIN_PASSWORD)
    resumed = auth_client.post(f"{API}/executions/{execution['id']}/resume")
    assert resumed.status_code == 200, resumed.text
    body = resumed.json()
    assert body["resumed"] is True
    assert body["execution"]["status"] == "succeeded"
    assert body["execution"]["approval_status"] == "approved"
    assert [step["status"] for step in body["execution"]["steps"]] == ["succeeded", "succeeded"]
    assert any(capability == "block_ip" for capability, _ in SoarTestAdapter.CALLS)

    remediation = db.execute(select(Remediation).where(Remediation.execution_id == UUID(execution["id"]))).scalar_one()
    assert remediation.status == "executed"
    assert remediation.executed_at is not None


def test_rejected_approval_denies_execution(auth_client: TestClient, seeded, db) -> None:
    _reset_adapter()
    _set_autonomy(db, seeded["org"], "A3")
    _connector(db, seeded["org"].id)
    playbook = _create_playbook(auth_client, _approval_definition(), name="Rejected block", min_level="A3")
    started = auth_client.post(f"{API}/executions", json={"playbook_id": playbook["id"]})
    assert started.status_code == 202, started.text
    execution = started.json()

    _add_admin(auth_client, "rejector@hispanshield.eu")
    _switch_user(auth_client, "rejector@hispanshield.eu")
    rejected = auth_client.post(
        f"/api/v1/organizations/current/approvals/{execution['approval_id']}/decision",
        json={"decision": "rejected", "reason": "False positive"},
    )
    assert rejected.status_code == 200

    _switch_user(auth_client, ADMIN_EMAIL, ADMIN_PASSWORD)
    resumed = auth_client.post(f"{API}/executions/{execution['id']}/resume")
    assert resumed.status_code == 200, resumed.text
    body = resumed.json()
    assert body["resumed"] is False
    assert body["reason"] == "approval_rejected"
    assert body["execution"]["status"] == "denied"
    assert SoarTestAdapter.CALLS == []


def test_compensation_runs_in_reverse_order(auth_client: TestClient, seeded, db) -> None:
    _reset_adapter()
    incident = _incident(auth_client)
    definition = {
        "steps": [
            {
                "key": "first",
                "name": "Add first note",
                "action": "internal.add_timeline",
                "params": {"summary": "First action executed"},
                "compensation": {
                    "action": "internal.add_timeline",
                    "params": {"summary": "Compensating first action"},
                },
            },
            {
                "key": "read",
                "name": "Broken read",
                "action": "connector.read",
                "params": {"capability": "read_events", "connector_id": str(uuid4())},
                "on_failure": "compensate",
            },
        ]
    }
    playbook = _create_playbook(auth_client, definition, name="Compensating playbook")
    response = auth_client.post(
        f"{API}/executions",
        json={"playbook_id": playbook["id"], "incident_id": incident["id"]},
    )
    assert response.status_code == 201, response.text
    execution = response.json()
    assert execution["status"] == "compensated"
    first = next(step for step in execution["steps"] if step["step_key"] == "first")
    read = next(step for step in execution["steps"] if step["step_key"] == "read")
    assert first["status"] == "succeeded"
    assert first["compensation_status"] == "succeeded"
    assert read["status"] == "failed"

    timeline = auth_client.get(f"/api/v1/incidents/{incident['id']}/timeline").json()
    summaries = [item["summary"] for item in timeline["items"]]
    assert summaries.index("First action executed") < summaries.index("Compensating first action")


def test_abort_failure_does_not_compensate(auth_client: TestClient, seeded, db) -> None:
    _reset_adapter()
    incident = _incident(auth_client)
    definition = {
        "steps": [
            {
                "key": "first",
                "name": "Add note",
                "action": "internal.add_timeline",
                "params": {"summary": "Executed before abort"},
                "compensation": {
                    "action": "internal.add_timeline",
                    "params": {"summary": "Should not run"},
                },
            },
            {
                "key": "read",
                "name": "Broken read",
                "action": "connector.read",
                "params": {"capability": "read_events", "connector_id": str(uuid4())},
                "on_failure": "abort",
            },
        ]
    }
    playbook = _create_playbook(auth_client, definition, name="Aborting playbook")
    response = auth_client.post(
        f"{API}/executions",
        json={"playbook_id": playbook["id"], "incident_id": incident["id"]},
    )
    assert response.status_code == 201, response.text
    execution = response.json()
    assert execution["status"] == "failed"
    first = next(step for step in execution["steps"] if step["step_key"] == "first")
    assert first["compensation_status"] is None
    timeline = auth_client.get(f"/api/v1/incidents/{incident['id']}/timeline").json()
    assert "Should not run" not in [item["summary"] for item in timeline["items"]]


def test_worker_resumes_pending_execution(auth_client: TestClient, seeded, db) -> None:
    from app.services.broker import BrokerActor
    from app.services.playbook_engine import create_execution, worker_run_once

    incident = _incident(auth_client)
    playbook_payload = _create_playbook(auth_client, _simple_definition(), name="Worker playbook")
    playbook = db.get(Playbook, UUID(playbook_payload["id"]))
    execution = create_execution(
        db,
        org=seeded["org"],
        playbook=playbook,
        actor=BrokerActor(id="test-operator", email="operator@hispanshield.eu"),
        trigger="manual",
        context={},
        incident_id=UUID(incident["id"]),
    )
    assert execution.status == "pending"
    result = worker_run_once(db, limit=5)
    assert result["processed"] >= 1
    db.refresh(execution)
    assert execution.status == "succeeded"
    assert execution.finished_at is not None


def test_retry_with_backoff_on_transient_read(auth_client: TestClient, seeded, db) -> None:
    _reset_adapter()
    SoarTestAdapter.FLAKY_REMAINING = 1
    connector = _connector(db, seeded["org"].id)
    definition = {
        "steps": [
            {
                "key": "flaky",
                "name": "Flaky read",
                "action": "connector.read",
                "params": {"capability": "flaky_read", "connector_id": str(connector.id)},
                "retries": 1,
            }
        ]
    }
    playbook = _create_playbook(auth_client, definition, name="Retry playbook")
    response = auth_client.post(f"{API}/executions", json={"playbook_id": playbook["id"]})
    assert response.status_code == 201, response.text
    execution = response.json()
    assert execution["status"] == "succeeded"
    assert execution["steps"][0]["attempts"] == 2
    assert SoarTestAdapter.FLAKY_REMAINING == 0


def test_unpublished_playbook_cannot_execute(auth_client: TestClient) -> None:
    playbook = _create_playbook(auth_client, _simple_definition(), publish=False)
    response = auth_client.post(f"{API}/executions", json={"playbook_id": playbook["id"]})
    assert response.status_code == 409


def test_cross_tenant_playbook_and_incident_are_404(seeded, auth_client: TestClient, db) -> None:
    other = Organization(slug="foreign-soar", name="Foreign SOAR")
    db.add(other)
    db.commit()
    foreign_playbook = Playbook(
        org_id=other.id,
        name="Foreign playbook",
        version=1,
        status="published",
        trigger={},
        definition=_simple_definition(),
        min_autonomy_level="A1",
    )
    foreign_incident = Incident(
        org_id=other.id,
        ref="HS-2026-9500",
        title="Foreign incident",
        severity="high",
        status="new",
        priority=2,
        mitre=[],
        affected_asset_ids=[],
    )
    db.add_all([foreign_playbook, foreign_incident])
    db.commit()

    assert auth_client.get(f"{API}/playbooks/{foreign_playbook.id}").status_code == 404
    assert auth_client.post(f"{API}/playbooks/{foreign_playbook.id}/publish").status_code == 404
    missing = auth_client.post(f"{API}/playbooks/{foreign_playbook.id}/execute", json={})
    assert missing.status_code == 404 or missing.status_code == 422
    foreign_execution = PlaybookExecution(
        org_id=other.id,
        playbook_id=foreign_playbook.id,
        status="succeeded",
        trigger="manual",
        context={},
        autonomy_level="A1",
    )
    db.add(foreign_execution)
    db.commit()
    assert auth_client.get(f"{API}/executions/{foreign_execution.id}").status_code == 404
    assert auth_client.get(f"{API}/executions/{foreign_execution.id}/steps").status_code == 404


def test_execution_list_filters(auth_client: TestClient) -> None:
    incident = _incident(auth_client)
    playbook = _create_playbook(auth_client, _simple_definition())
    created = auth_client.post(
        f"{API}/executions",
        json={"playbook_id": playbook["id"], "incident_id": incident["id"]},
    )
    assert created.status_code == 201

    listed = auth_client.get(f"{API}/executions", params={"status": "succeeded"})
    assert listed.status_code == 200
    assert listed.json()["meta"]["total"] == 1
    assert listed.json()["items"][0]["id"] == created.json()["id"]

    by_incident = auth_client.get(f"{API}/executions", params={"incident_id": incident["id"]})
    assert by_incident.json()["meta"]["total"] == 1
    dry = auth_client.get(f"{API}/executions", params={"dry_run": "false"})
    assert dry.json()["meta"]["total"] == 1
    invalid_sort = auth_client.get(f"{API}/executions", params={"sort": "drop"})
    assert invalid_sort.status_code == 422


def test_trigger_with_alert_context_and_tenant_validation(auth_client: TestClient, seeded, db) -> None:
    from app.models.events import Alert

    incident = _incident(auth_client, severity="critical")
    alert = Alert(
        org_id=seeded["org"].id,
        title="Beacon detected",
        severity="critical",
        status="new",
        incident_id=UUID(incident["id"]),
        event_ids=[1],
        mitre=["T1071"],
        evidence={},
    )
    db.add(alert)
    db.commit()
    playbook = _create_playbook(auth_client, _simple_definition(), name="Alert driven")

    response = auth_client.post(f"{API}/executions", json={"playbook_id": playbook["id"], "alert_id": str(alert.id)})
    assert response.status_code == 201, response.text
    execution = response.json()
    assert execution["trigger"] == "alert"
    assert execution["incident_id"] == incident["id"]

    unknown_alert = auth_client.post(
        f"{API}/executions", json={"playbook_id": playbook["id"], "alert_id": str(uuid4())}
    )
    assert unknown_alert.status_code == 404

    other = Organization(slug="foreign-alert", name="Foreign Alert")
    db.add(other)
    db.commit()
    foreign_alert = Alert(
        org_id=other.id,
        title="Foreign alert",
        severity="high",
        status="new",
        event_ids=[],
        mitre=[],
        evidence={},
    )
    db.add(foreign_alert)
    db.commit()
    assert (
        auth_client.post(
            f"{API}/executions", json={"playbook_id": playbook["id"], "alert_id": str(foreign_alert.id)}
        ).status_code
        == 404
    )


def test_publishing_new_version_archives_previous(auth_client: TestClient) -> None:
    playbook = _create_playbook(auth_client, _simple_definition(), name="Versioned")
    edited = auth_client.patch(f"{API}/playbooks/{playbook['id']}", json={"description": "v2"})
    assert edited.status_code == 200
    second = edited.json()
    assert second["version"] == 2
    published = auth_client.post(f"{API}/playbooks/{second['id']}/publish")
    assert published.status_code == 200
    old = auth_client.get(f"{API}/playbooks/{playbook['id']}")
    assert old.json()["status"] == "archived"


def test_execution_steps_are_persisted_once_per_key(auth_client: TestClient, db) -> None:
    incident = _incident(auth_client)
    playbook = _create_playbook(auth_client, _simple_definition())
    created = auth_client.post(
        f"{API}/executions",
        json={"playbook_id": playbook["id"], "incident_id": incident["id"]},
    )
    assert created.status_code == 201
    rows = list(
        db.execute(select(PlaybookStep).where(PlaybookStep.execution_id == UUID(created.json()["id"]))).scalars()
    )
    assert len(rows) == 3
    assert len({row.step_key for row in rows}) == 3


def test_unknown_playbook_and_bad_sort(auth_client: TestClient) -> None:
    assert auth_client.get(f"{API}/playbooks/{uuid4()}").status_code == 404
    assert auth_client.get(f"{API}/executions/{uuid4()}").status_code == 404
    assert auth_client.get(f"{API}/playbooks", params={"sort": "steps"}).status_code == 422


@pytest.mark.parametrize("field,value", [("context", "not-an-object"), ("requested_level", "A9")])
def test_execution_input_validation(auth_client: TestClient, field: str, value: str) -> None:
    playbook = _create_playbook(auth_client, _simple_definition())
    payload = {"playbook_id": playbook["id"], field: value}
    response = auth_client.post(f"{API}/executions", json=payload)
    assert response.status_code == 422


def test_timeline_step_outputs_are_bounded(auth_client: TestClient, db) -> None:
    incident = _incident(auth_client)
    playbook = _create_playbook(auth_client, _simple_definition())
    created = auth_client.post(
        f"{API}/executions",
        json={"playbook_id": playbook["id"], "incident_id": incident["id"]},
    )
    assert created.status_code == 201
    investigation = next(step for step in created.json()["steps"] if step["step_key"] == "investigate")
    assert investigation["output"]["scope"] == "incident"
    assert investigation["finished_at"] is not None
