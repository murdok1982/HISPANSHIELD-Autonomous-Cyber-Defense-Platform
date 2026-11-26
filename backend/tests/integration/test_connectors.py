"""Integration tests for the connector registry API, sync pipeline and broker path."""

from __future__ import annotations

import json
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from uuid import UUID

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.core.config import settings
from app.core.crypto import decrypt_secret, encrypt_secret, hash_password
from app.core.db import utcnow
from app.models.connectors import Connector, ConnectorRun
from app.models.core import Approval, AuditRecord, KillSwitch, Membership, Organization, User
from app.models.events import IngestSource, SecurityEvent
from app.services.broker import BrokerActor, execute_action
from app.services.connectors.runtime import circuit_breaker
from tests.conftest import login

API = "/api/v1"


class FakeAPI:
    """Minimal threaded HTTP server with per-route JSON responses."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], tuple[int, Any]] = {}
        self.handlers: dict[tuple[str, str], Any] = {}
        self.requests: list[dict[str, Any]] = []
        self.default: tuple[int, Any] = (404, {"error": "not found"})
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), self._build_handler())
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()

    @property
    def base_url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def route(self, method: str, path: str, status: int = 200, payload: Any = None) -> None:
        self.routes[(method.upper(), path)] = (status, payload if payload is not None else {})

    def handle(self, method: str, path: str, handler: Any) -> None:
        self.handlers[(method.upper(), path)] = handler

    def _resolve(self, method: str, path: str, body: bytes) -> tuple[int, Any]:
        key = (method.upper(), path.split("?", 1)[0])
        if key in self.handlers:
            return self.handlers[key](self, body)
        if key in self.routes:
            return self.routes[key]
        return self.default

    def requests_for(self, method: str, path: str) -> list[dict[str, Any]]:
        return [
            request
            for request in self.requests
            if request["method"] == method.upper() and request["path"].split("?", 1)[0] == path
        ]

    def _build_handler(self) -> type[BaseHTTPRequestHandler]:
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _serve(self) -> None:
                length = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(length) if length else b""
                fake.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "headers": {key.lower(): value for key, value in self.headers.items()},
                        "body": body,
                    }
                )
                status, payload = fake._resolve(self.command, self.path, body)
                raw = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            do_GET = _serve
            do_POST = _serve
            do_PUT = _serve
            do_DELETE = _serve
            do_PATCH = _serve

            def log_message(self, *args: Any) -> None:  # noqa: D401 - silence test server
                return None

        return Handler

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


@pytest.fixture
def fake_api():
    api = FakeAPI()
    try:
        yield api
    finally:
        api.stop()


@pytest.fixture(autouse=True)
def _allow_private_networks(monkeypatch):
    # The suite intentionally talks to 127.0.0.1 fake protocols.
    monkeypatch.setattr(settings, "connector_allow_private_networks", True)


def _wazuh_routes(fake: FakeAPI, alerts: list[dict[str, Any]] | None = None) -> None:
    fake.route("POST", "/security/user/authenticate", 200, {"data": {"token": "wazuh-jwt"}, "error": 0})
    fake.route("GET", "/manager/info", 200, {"data": {"affected_items": [{"version": "4.8.0"}]}, "error": 0})
    fake.route(
        "GET", "/alerts", 200, {"data": {"affected_items": alerts or [], "total_affected_items": len(alerts or [])}}
    )
    fake.route("GET", "/agents", 200, {"data": {"affected_items": [{"id": "001", "name": "web-01"}]}})


def _create(client: TestClient, name: str, base_url: str, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": name,
        "connector_type": "wazuh",
        "base_url": base_url,
        "auth_type": "basic",
        "secret": "Wazuh-Super-Secret-123",
        "config": {"username": "wazuh"},
        **overrides,
    }
    response = client.post(f"{API}/connectors", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _wazuh_alert(external_id: str, src_ip: str, description: str = "Brute force detected") -> dict[str, Any]:
    return {
        "id": external_id,
        "timestamp": "2024-06-10T10:15:30.000Z",
        "rule": {"id": "5710", "level": 12, "description": description, "mitre": {"id": ["T1110"]}},
        "agent": {"id": "001", "name": "web-01"},
        "data": {"srcip": src_ip, "dstport": "22", "protocol": "tcp"},
    }


def test_catalog_lists_adapters_and_configuration_gaps(auth_client: TestClient) -> None:
    response = auth_client.get(f"{API}/connectors/catalog")
    assert response.status_code == 200, response.text
    body = response.json()
    adapter_ids = {adapter["connector_id"] for adapter in body["adapters"]}
    assert len(adapter_ids) == 12
    assert {"wazuh", "elastic_security", "microsoft_sentinel", "misp", "opencti"} <= adapter_ids
    assert {"suricata_file", "zeek_file", "keycloak", "pfsense", "opnsense"} <= adapter_ids
    assert {"generic_webhook", "microsoft_defender"} <= adapter_ids
    assert body["missing"] == sorted(adapter_ids)
    assert body["configured"] == []
    wazuh = next(adapter for adapter in body["adapters"] if adapter["connector_id"] == "wazuh")
    assert wazuh["requires_base_url"] is True
    assert any(capability["name"] == "read_alerts" for capability in wazuh["capabilities"])
    suricata = next(adapter for adapter in body["adapters"] if adapter["connector_id"] == "suricata_file")
    assert suricata["file_based"] is True
    assert suricata["requires_base_url"] is False


def test_create_encrypts_secret_copies_manifest_and_audits(
    auth_client: TestClient, fake_api: FakeAPI, db, seeded
) -> None:
    connector = _create(auth_client, "wazuh-prod", fake_api.base_url)
    assert connector["has_secret"] is True
    assert connector["status"] == "unknown"
    assert connector["capabilities"]["read"] == ["read_alerts", "read_agents"]
    assert "active_response" in connector["capabilities"]["write"]
    assert connector["config"]["username"] == "wazuh"

    row = db.get(Connector, UUID(connector["id"]))
    assert row is not None
    assert row.secret_encrypted != "Wazuh-Super-Secret-123"
    assert decrypt_secret(row.secret_encrypted) == "Wazuh-Super-Secret-123"
    assert row.org_id == seeded["org"].id
    audit = db.execute(select(AuditRecord).where(AuditRecord.action == "connector.create")).scalar_one()
    assert audit.resource_id == connector["id"]
    assert audit.payload["auth_material_present"] is True


def test_get_never_returns_secret_and_redacts_config(auth_client: TestClient, fake_api: FakeAPI) -> None:
    connector = _create(
        auth_client,
        "wazuh-redacted",
        fake_api.base_url,
        config={"username": "wazuh", "api_password": "Config-Should-Not-Leak"},
    )
    response = auth_client.get(f"{API}/connectors/{connector['id']}")
    assert response.status_code == 200
    text = response.text
    assert "Wazuh-Super-Secret-123" not in text
    assert "Config-Should-Not-Leak" not in text
    assert response.json()["config"]["api_password"] == "[redacted]"
    assert response.json()["has_secret"] is True


def test_create_rejects_metadata_ip_and_invalid_types(auth_client: TestClient, fake_api: FakeAPI) -> None:
    blocked = auth_client.post(
        f"{API}/connectors",
        json={
            "name": "ssrf-attempt",
            "connector_type": "elastic_security",
            "base_url": "http://169.254.169.254/latest/meta-data",
            "auth_type": "api_key",
            "secret": "key",
        },
    )
    assert blocked.status_code == 422
    assert any("base_url" in detail["field"] for detail in blocked.json()["error"]["details"])

    unknown = auth_client.post(
        f"{API}/connectors",
        json={"name": "unknown", "connector_type": "not_real", "base_url": fake_api.base_url},
    )
    assert unknown.status_code == 422

    file_with_url = auth_client.post(
        f"{API}/connectors",
        json={
            "name": "bad-file",
            "connector_type": "suricata_file",
            "base_url": fake_api.base_url,
            "auth_type": "none",
            "config": {"path": "/var/log/suricata/eve.json"},
        },
    )
    assert file_with_url.status_code == 422


def test_duplicate_name_conflicts(auth_client: TestClient, fake_api: FakeAPI) -> None:
    _create(auth_client, "duplicate-name", fake_api.base_url)
    duplicate = auth_client.post(
        f"{API}/connectors",
        json={
            "name": "DUPLICATE-NAME",
            "connector_type": "wazuh",
            "base_url": fake_api.base_url,
            "auth_type": "basic",
            "secret": "another-secret",
        },
    )
    assert duplicate.status_code == 409


def test_patch_rotates_secret_without_auditing_plaintext(auth_client: TestClient, fake_api: FakeAPI, db) -> None:
    connector = _create(auth_client, "wazuh-rotate", fake_api.base_url)
    rotated = auth_client.patch(
        f"{API}/connectors/{connector['id']}", json={"secret": "Rotated-Secret-456", "config": {"username": "wazuh"}}
    )
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["has_secret"] is True

    row = db.get(Connector, UUID(connector["id"]))
    assert decrypt_secret(row.secret_encrypted) == "Rotated-Secret-456"
    records = list(db.execute(select(AuditRecord).where(AuditRecord.action == "connector.rotate_secret")).scalars())
    assert len(records) == 1
    assert "Rotated-Secret-456" not in json.dumps(records[0].payload)
    assert "Wazuh-Super-Secret-123" not in json.dumps(records[0].payload)

    disabled = auth_client.patch(f"{API}/connectors/{connector['id']}", json={"enabled": False})
    assert disabled.status_code == 200
    assert disabled.json()["status"] == "disabled"
    enabled = auth_client.patch(f"{API}/connectors/{connector['id']}", json={"enabled": True})
    assert enabled.json()["status"] == "unknown"


def test_cross_tenant_access_returns_404(auth_client: TestClient, fake_api: FakeAPI, db, seeded) -> None:
    connector = _create(auth_client, "tenant-a-connector", fake_api.base_url)
    other = Organization(slug="other-tenant", name="Other Tenant", kind="private", country="ES", sector="general")
    db.add(other)
    db.commit()
    headers = {"X-Organization-Id": str(other.id)}

    detail = auth_client.get(f"{API}/connectors/{connector['id']}", headers=headers)
    assert detail.status_code == 404
    listing = auth_client.get(f"{API}/connectors", headers=headers)
    assert listing.status_code == 200
    assert listing.json()["meta"]["total"] == 0
    update = auth_client.patch(f"{API}/connectors/{connector['id']}", json={"name": "renamed"}, headers=headers)
    assert update.status_code == 404
    probe = auth_client.post(f"{API}/connectors/{connector['id']}/health", headers=headers)
    assert probe.status_code == 404


def test_rbac_viewer_cannot_write_or_execute(
    seeded, auth_client: TestClient, client: TestClient, fake_api: FakeAPI, db
) -> None:
    connector = _create(auth_client, "rbac-connector", fake_api.base_url)
    user = User(
        email="viewer@hispanshield.eu",
        full_name="Read Only Viewer",
        password_hash=hash_password("Viewer-Str0ng-Pass!9"),
        status="active",
        locale="es",
    )
    db.add(user)
    db.flush()
    db.add(Membership(org_id=seeded["org"].id, user_id=user.id, role="viewer", status="active"))
    db.commit()

    with TestClient(client.app) as viewer_client:
        login(viewer_client, "viewer@hispanshield.eu", "Viewer-Str0ng-Pass!9")
        assert viewer_client.get(f"{API}/connectors").status_code == 200
        denied = viewer_client.post(
            f"{API}/connectors",
            json={
                "name": "viewer-attempt",
                "connector_type": "wazuh",
                "base_url": fake_api.base_url,
                "auth_type": "basic",
                "secret": "secret",
            },
        )
        assert denied.status_code == 403
        assert viewer_client.post(f"{API}/connectors/{connector['id']}/health").status_code == 403


def test_delete_is_blocked_while_referenced(auth_client: TestClient, fake_api: FakeAPI, db, seeded) -> None:
    connector = _create(auth_client, "referenced-connector", fake_api.base_url)
    source = IngestSource(
        org_id=seeded["org"].id,
        name="syslog source",
        kind="connector",
        parser="auto",
        connector_id=UUID(connector["id"]),
    )
    db.add(source)
    db.commit()

    blocked = auth_client.delete(f"{API}/connectors/{connector['id']}")
    assert blocked.status_code == 409
    assert blocked.json()["error"]["code"] == "connector_in_use"

    db.delete(source)
    db.commit()
    removed = auth_client.delete(f"{API}/connectors/{connector['id']}")
    assert removed.status_code == 204
    assert auth_client.get(f"{API}/connectors/{connector['id']}").status_code == 404


def test_health_transitions_and_run_history(auth_client: TestClient, fake_api: FakeAPI, db) -> None:
    connector = _create(auth_client, "wazuh-health", fake_api.base_url)
    _wazuh_routes(fake_api)

    healthy = auth_client.post(f"{API}/connectors/{connector['id']}/health")
    assert healthy.status_code == 200, healthy.text
    assert healthy.json()["status"] == "healthy"
    assert healthy.json()["ok"] is True
    assert healthy.json()["run_id"]

    fake_api.route("GET", "/manager/info", 500, {"error": "manager unavailable"})
    unhealthy = auth_client.post(f"{API}/connectors/{connector['id']}/health")
    assert unhealthy.status_code == 200
    assert unhealthy.json()["status"] == "unhealthy"
    assert unhealthy.json()["ok"] is False

    detail = auth_client.get(f"{API}/connectors/{connector['id']}").json()
    assert detail["status"] == "unhealthy"
    assert detail["health"]["circuit_open"] is False

    runs = auth_client.get(f"{API}/connectors/{connector['id']}/runs").json()
    assert runs["meta"]["total"] == 2
    statuses = [item["status"] for item in runs["items"]]
    assert statuses.count("success") == 1
    assert statuses.count("failed") == 1
    assert all(item["operation"] == "health_check" for item in runs["items"])

    row = db.execute(select(Connector).where(Connector.id == UUID(connector["id"]))).scalar_one()
    assert row.last_health_at is not None
    assert row.last_error is not None


def test_invoke_read_capability_and_reject_write(auth_client: TestClient, fake_api: FakeAPI, db) -> None:
    connector = _create(auth_client, "wazuh-invoke", fake_api.base_url)
    _wazuh_routes(fake_api)

    invoked = auth_client.post(f"{API}/connectors/{connector['id']}/invoke/read_agents", json={"params": {}})
    assert invoked.status_code == 200, invoked.text
    body = invoked.json()
    assert body["ok"] is True
    assert body["data"]["items"][0]["name"] == "web-01"
    assert fake_api.requests_for("GET", "/agents")[0]["headers"]["authorization"] == "Bearer wazuh-jwt"

    rejected = auth_client.post(
        f"{API}/connectors/{connector['id']}/invoke/active_response",
        json={"params": {"agents": ["001"], "command": "firewall-drop"}},
    )
    assert rejected.status_code == 403
    assert rejected.json()["error"]["code"] == "policy_denied"
    assert "broker" in rejected.json()["error"]["message"].lower()
    assert fake_api.requests_for("PUT", "/active-response") == []

    unknown = auth_client.post(f"{API}/connectors/{connector['id']}/invoke/not_a_capability", json={"params": {}})
    assert unknown.status_code == 422

    run = db.execute(select(ConnectorRun).where(ConnectorRun.operation == "read_agents")).scalar_one()
    assert run.direction == "read"
    assert run.status == "success"


def test_sync_normalizes_and_dedupes_events(auth_client: TestClient, fake_api: FakeAPI, db) -> None:
    alerts = [
        _wazuh_alert("alert-1", "203.0.113.10"),
        _wazuh_alert("alert-2", "203.0.113.11", "Suspicious sudo"),
    ]
    connector = _create(auth_client, "wazuh-sync", fake_api.base_url)
    _wazuh_routes(fake_api, alerts)

    first = auth_client.post(f"{API}/connectors/{connector['id']}/sync", json={"limit": 50})
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["events_created"] == 2
    assert body["events_duplicate"] == 0
    assert body["alerts_read"] == 2
    assert body["capabilities"] == ["read_alerts"]

    second = auth_client.post(f"{API}/connectors/{connector['id']}/sync", json={"limit": 50})
    assert second.status_code == 200
    assert second.json()["events_created"] == 0
    assert second.json()["events_duplicate"] == 2

    events = list(db.execute(select(SecurityEvent).order_by(SecurityEvent.event_uid)).scalars())
    assert len(events) == 2
    assert all(event.source_connector == "wazuh-sync" for event in events)
    assert all(event.dedupe_key and len(event.dedupe_key) == 64 for event in events)
    assert {event.src_ip for event in events} == {"203.0.113.10", "203.0.113.11"}

    row = db.execute(select(Connector).where(Connector.id == UUID(connector["id"]))).scalar_one()
    assert row.last_success_at is not None
    assert row.status == "healthy"

    audit_actions = list(
        db.execute(select(AuditRecord.action).where(AuditRecord.resource_id == connector["id"])).scalars()
    )
    assert audit_actions.count("connector.sync") == 2


def test_sync_respects_limit_and_lists_paginated_runs(auth_client: TestClient, fake_api: FakeAPI) -> None:
    alerts = [_wazuh_alert(f"limit-{index}", f"203.0.113.{index + 20}") for index in range(4)]
    connector = _create(auth_client, "wazuh-limit", fake_api.base_url)
    _wazuh_routes(fake_api, alerts)

    limited = auth_client.post(f"{API}/connectors/{connector['id']}/sync", json={"limit": 2})
    assert limited.status_code == 200
    assert limited.json()["events_created"] == 2

    too_large = auth_client.post(f"{API}/connectors/{connector['id']}/sync", json={"limit": 500})
    assert too_large.status_code == 422

    runs = auth_client.get(f"{API}/connectors/{connector['id']}/runs?page=1&page_size=1").json()
    assert runs["meta"]["total"] == 1
    assert runs["meta"]["page_size"] == 1
    assert runs["meta"]["has_next"] is False
    assert runs["items"][0]["operation"] == "sync"


def test_health_summary_reports_counts_and_stale_connectors(auth_client: TestClient, fake_api: FakeAPI) -> None:
    _create(auth_client, "summary-one", fake_api.base_url)
    _create(auth_client, "summary-two", fake_api.base_url)
    summary = auth_client.get(f"{API}/connectors/health/summary")
    assert summary.status_code == 200
    body = summary.json()
    assert body["total"] == 2
    assert body["enabled"] == 2
    assert body["stale_count"] == 2
    assert body["catalog_size"] == 12
    assert body["by_status"] == {"unknown": 2}

    _wazuh_routes(fake_api)
    connector = auth_client.get(f"{API}/connectors?q=summary-one").json()["items"][0]
    assert auth_client.post(f"{API}/connectors/{connector['id']}/health").status_code == 200
    refreshed = auth_client.get(f"{API}/connectors/health/summary").json()
    assert refreshed["stale_count"] == 1
    assert refreshed["by_status"]["healthy"] == 1


def test_sync_failure_marks_connector_degraded(auth_client: TestClient, fake_api: FakeAPI, db) -> None:
    connector = _create(auth_client, "wazuh-sync-fail", fake_api.base_url)
    fake_api.route("POST", "/security/user/authenticate", 200, {"data": {"token": "jwt"}})
    fake_api.route("GET", "/alerts", 500, {"error": "index unavailable"})

    failed = auth_client.post(f"{API}/connectors/{connector['id']}/sync", json={"limit": 10})
    assert failed.status_code == 503
    row = db.execute(select(Connector).where(Connector.id == UUID(connector["id"]))).scalar_one()
    assert row.status == "degraded"
    assert row.last_error
    runs = list(db.execute(select(ConnectorRun).where(ConnectorRun.connector_id == row.id)).scalars())
    assert [run.status for run in runs] == ["failed"]


def test_circuit_breaker_opens_after_repeated_health_failures(auth_client: TestClient, fake_api: FakeAPI) -> None:
    connector = _create(auth_client, "wazuh-breaker", fake_api.base_url)
    fake_api.route("POST", "/security/user/authenticate", 200, {"data": {"token": "jwt"}})
    fake_api.route("GET", "/manager/info", 500, {"error": "down"})

    for _ in range(5):
        response = auth_client.post(f"{API}/connectors/{connector['id']}/health")
        assert response.status_code == 200
        assert response.json()["status"] == "unhealthy"

    opened = auth_client.post(f"{API}/connectors/{connector['id']}/health")
    assert opened.status_code == 503
    assert f"connector:{connector['id']}" in circuit_breaker.snapshot()["open"]

    connector_view = auth_client.get(f"{API}/connectors/{connector['id']}").json()
    assert connector_view["health"]["circuit_open"] is True
    circuit_breaker.record_success(f"connector:{connector['id']}")


def _enable_a3(db, seeded) -> Organization:
    org = db.get(Organization, seeded["org"].id)
    org.autonomy_level = "A3"
    db.commit()
    return org


def _approval(db, org: Organization, user: User) -> Approval:
    approval = Approval(
        org_id=org.id,
        request_type="defence.action",
        resource_type="ip",
        resource_id="203.0.113.9",
        payload={"action_type": "ip.block", "target_type": "ip", "target_id": "203.0.113.9"},
        status="approved",
        requested_by=user.email,
        requested_by_user_id=user.id,
        expires_at=utcnow() + timedelta(hours=1),
    )
    db.add(approval)
    db.commit()
    return approval


def test_broker_executes_pfsense_block_and_records_write_run(
    auth_client: TestClient, fake_api: FakeAPI, db, seeded
) -> None:
    state: dict[str, Any] = {"entries": []}

    def entries(fake: FakeAPI, body: bytes) -> tuple[int, Any]:
        return 200, {"data": state["entries"]}

    def create_entry(fake: FakeAPI, body: bytes) -> tuple[int, Any]:
        payload = json.loads(body)
        entry = {"id": 7, "address": payload["address"], "detail": payload.get("detail")}
        state["entries"].append(entry)
        return 200, {"data": entry}

    fake_api.route("GET", "/api/v2/firewall/aliases", 200, {"data": [{"id": 1, "name": "hs_block"}]})
    fake_api.handle("GET", "/api/v2/firewall/alias_entries", entries)
    fake_api.handle("POST", "/api/v2/firewall/alias_entries", create_entry)
    fake_api.route("POST", "/api/v2/firewall/apply", 200, {"status": "ok"})

    connector = _create(
        auth_client,
        "pfsense-edge",
        fake_api.base_url,
        connector_type="pfsense",
        auth_type="api_key_header",
        secret="pfsense-key",
        config={"alias_name": "hs_block"},
    )
    org = _enable_a3(db, seeded)
    approval = _approval(db, org, seeded["user"])

    result = execute_action(
        db,
        org=org,
        actor=BrokerActor(id=str(seeded["user"].id), email=seeded["user"].email, user_id=seeded["user"].id),
        action_type="ip.block",
        target_type="ip",
        target_id="203.0.113.9",
        parameters={"ip": "203.0.113.9"},
        approval_id=approval.id,
        connector_id=UUID(connector["id"]),
    )
    assert result.status == "executed"
    assert result.verified is True
    assert state["entries"][0]["address"] == "203.0.113.9"
    create_requests = fake_api.requests_for("POST", "/api/v2/firewall/alias_entries")
    assert create_requests[0]["headers"]["x-api-key"] == "pfsense-key"

    write_run = db.execute(
        select(ConnectorRun).where(
            ConnectorRun.connector_id == UUID(connector["id"]), ConnectorRun.direction == "write"
        )
    ).scalar_one()
    assert write_run.status == "success"
    assert write_run.operation == "block_ip"
    audit = db.execute(select(AuditRecord).where(AuditRecord.action == "defence.action.execute")).scalar_one()
    assert audit.outcome == "success"


def test_broker_failure_and_connector_kill_switch(auth_client: TestClient, fake_api: FakeAPI, db, seeded) -> None:
    fake_api.route("GET", "/api/v2/firewall/aliases", 200, {"data": [{"id": 1, "name": "hs_block"}]})
    fake_api.route("GET", "/api/v2/firewall/alias_entries", 200, {"data": []})
    fake_api.route("POST", "/api/v2/firewall/alias_entries", 500, {"error": "alias locked"})
    fake_api.route("POST", "/api/v2/firewall/apply", 200, {"status": "ok"})

    connector = _create(
        auth_client,
        "pfsense-failure",
        fake_api.base_url,
        connector_type="pfsense",
        auth_type="api_key_header",
        secret="pfsense-key",
        config={"alias_name": "hs_block"},
    )
    org = _enable_a3(db, seeded)
    approval = _approval(db, org, seeded["user"])
    connector_id = UUID(connector["id"])

    with pytest.raises(Exception) as failure:
        execute_action(
            db,
            org=org,
            actor=BrokerActor(id=str(seeded["user"].id), email=seeded["user"].email, user_id=seeded["user"].id),
            action_type="ip.block",
            target_type="ip",
            target_id="203.0.113.9",
            parameters={"ip": "203.0.113.9"},
            approval_id=approval.id,
            connector_id=connector_id,
        )
    assert "connector" in str(failure.value).lower() or failure.value.status_code == 503

    row = db.get(Connector, connector_id)
    assert row.status == "degraded"
    runs = list(db.execute(select(ConnectorRun).where(ConnectorRun.connector_id == connector_id)).scalars())
    assert runs and runs[-1].status == "failed"

    switch = KillSwitch(
        org_id=org.id,
        scope="connector",
        target_id=str(connector_id),
        engaged=True,
        reason="operator freeze",
    )
    db.add(switch)
    db.commit()
    before = len(fake_api.requests_for("POST", "/api/v2/firewall/alias_entries"))
    with pytest.raises(Exception) as denied:
        execute_action(
            db,
            org=org,
            actor=BrokerActor(id=str(seeded["user"].id), email=seeded["user"].email, user_id=seeded["user"].id),
            action_type="ip.block",
            target_type="ip",
            target_id="203.0.113.9",
            parameters={"ip": "203.0.113.9"},
            approval_id=approval.id,
            connector_id=connector_id,
        )
    assert denied.value.status_code == 403
    assert len(fake_api.requests_for("POST", "/api/v2/firewall/alias_entries")) == before

    db.delete(switch)
    db.commit()


def test_run_records_are_org_scoped(auth_client: TestClient, fake_api: FakeAPI, db, seeded) -> None:
    connector = _create(auth_client, "runs-scope", fake_api.base_url)
    _wazuh_routes(fake_api)
    assert auth_client.post(f"{API}/connectors/{connector['id']}/health").status_code == 200
    total = db.execute(
        select(func.count())
        .select_from(ConnectorRun)
        .where(ConnectorRun.org_id == seeded["org"].id, ConnectorRun.connector_id == UUID(connector["id"]))
    ).scalar_one()
    assert total == 1
    stored = db.execute(select(ConnectorRun)).scalar_one()
    assert stored.request_id is not None
    assert stored.latency_ms is not None


def test_unconfigured_connector_requires_secret_before_use(auth_client: TestClient, fake_api: FakeAPI) -> None:
    response = auth_client.post(
        f"{API}/connectors",
        json={
            "name": "wazuh-unconfigured",
            "connector_type": "wazuh",
            "base_url": fake_api.base_url,
            "auth_type": "basic",
        },
    )
    assert response.status_code == 201
    assert response.json()["status"] == "unconfigured"
    assert response.json()["has_secret"] is False

    fake_api.route("POST", "/security/user/authenticate", 401, {"error": "bad credentials"})
    health = auth_client.post(f"{API}/connectors/{response.json()['id']}/health")
    assert health.status_code == 200
    assert health.json()["status"] == "unhealthy"


def test_secret_is_encrypted_at_rest_with_fernet(db, seeded) -> None:
    plaintext = "standalone-secret"
    ciphertext = encrypt_secret(plaintext)
    assert ciphertext != plaintext
    assert decrypt_secret(ciphertext) == plaintext
    connector = Connector(
        org_id=seeded["org"].id,
        name="encryption-proof",
        connector_type="generic_webhook",
        base_url="https://example.test/hook",
        auth_type="hmac",
        secret_encrypted=ciphertext,
        config={},
        capabilities={},
        status="unknown",
        enabled=True,
        verify_tls=True,
        rate_limit_per_minute=60,
    )
    db.add(connector)
    db.commit()
    assert db.get(Connector, connector.id).secret_encrypted == ciphertext
