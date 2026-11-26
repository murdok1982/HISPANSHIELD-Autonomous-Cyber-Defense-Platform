"""Security invariants for the connector hub: SSRF, file sandboxing, secrets, RBAC."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from uuid import UUID, uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.models.connectors import Connector, ConnectorRun
from app.models.core import AuditRecord
from app.services.connectors.adapters._support import read_file_tail, resolve_file_path
from app.services.connectors.adapters.suricata_file import SuricataFileAdapter
from app.services.connectors.adapters.wazuh import WazuhAdapter
from app.services.connectors.adapters.zeek_file import ZeekFileAdapter
from app.services.connectors.base import ConnectorError
from app.services.connectors.normalize import sanitize_text

API = "/api/v1"
SECRET = "Wazuh-Secret-Must-Never-Leak-9000"


class FakeServer:
    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], tuple[int, Any]] = {}
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

    def requests_for(self, method: str, path: str) -> list[dict[str, Any]]:
        return [
            request
            for request in self.requests
            if request["method"] == method.upper() and request["path"].split("?", 1)[0] == path
        ]

    def _build_handler(self) -> type[BaseHTTPRequestHandler]:
        server = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _serve(self) -> None:
                length = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(length) if length else b""
                server.requests.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "headers": {key.lower(): value for key, value in self.headers.items()},
                        "body": body,
                    }
                )
                key = (self.command, self.path.split("?", 1)[0])
                status, payload = server.routes.get(key, server.default)
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

            def log_message(self, *args: Any) -> None:
                return None

        return Handler

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


@pytest.fixture
def fake():
    server = FakeServer()
    try:
        yield server
    finally:
        server.stop()


@pytest.fixture(autouse=True)
def _allow_private_networks(monkeypatch):
    monkeypatch.setattr(settings, "connector_allow_private_networks", True)


def make_connector(
    connector_type: str,
    base_url: str | None,
    *,
    auth_type: str = "none",
    config: dict[str, Any] | None = None,
    verify_tls: bool = True,
) -> Connector:
    return Connector(
        id=uuid4(),
        org_id=uuid4(),
        name=f"security-{connector_type}",
        connector_type=connector_type,
        version="1.0.0",
        base_url=base_url,
        auth_type=auth_type,
        secret_encrypted=None,
        config=config or {},
        capabilities={},
        status="unknown",
        enabled=True,
        verify_tls=verify_tls,
        rate_limit_per_minute=60,
    )


def _create_wazuh(client: TestClient, base_url: str, **overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "name": "security-wazuh",
        "connector_type": "wazuh",
        "base_url": base_url,
        "auth_type": "basic",
        "secret": SECRET,
        "config": {"username": "wazuh"},
        **overrides,
    }
    response = client.post(f"{API}/connectors", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def test_metadata_ip_is_blocked_before_any_request(monkeypatch) -> None:
    monkeypatch.setattr(settings, "connector_allow_private_networks", False)
    adapter = WazuhAdapter(make_connector("wazuh", "http://169.254.169.254", auth_type="basic"), "user:pass")
    with pytest.raises(ConnectorError) as blocked:
        adapter.health_check()
    assert "Blocked outbound destination" in str(blocked.value)


def test_loopback_is_blocked_unless_private_networks_enabled(monkeypatch, fake: FakeServer) -> None:
    monkeypatch.setattr(settings, "connector_allow_private_networks", False)
    adapter = WazuhAdapter(make_connector("wazuh", fake.base_url, auth_type="basic"), "user:pass")
    with pytest.raises(ConnectorError) as blocked:
        adapter.health_check()
    assert any(marker in str(blocked.value).lower() for marker in ("private", "loopback", "reserved"))
    assert fake.requests == []


def test_api_rejects_metadata_ip_at_creation(auth_client: TestClient) -> None:
    response = auth_client.post(
        f"{API}/connectors",
        json={
            "name": "metadata-ssrf",
            "connector_type": "microsoft_sentinel",
            "base_url": "http://169.254.169.254",
            "auth_type": "client_credentials",
            "secret": "x",
        },
    )
    assert response.status_code == 422
    assert response.json()["error"]["details"][0]["field"] == "base_url"


def test_file_adapter_rejects_outside_roots_and_traversal(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HS_CONNECTOR_FILE_ROOTS", str(tmp_path))
    outside = tmp_path.parent / "outside.log"
    outside.write_text('{"event_type": "alert"}\n')

    for path, fragment in (
        (str(outside), "outside the approved"),
        (str(tmp_path / ".." / "outside.log"), "traversal"),
        ("relative/eve.json", "absolute"),
        ("/etc/passwd", "outside the approved"),
    ):
        adapter = SuricataFileAdapter(make_connector("suricata_file", None, config={"path": path}), None)
        with pytest.raises(ConnectorError) as rejected:
            adapter.health_check()
        assert fragment in str(rejected.value)

    symlink = tmp_path / "escape.log"
    symlink.symlink_to("/etc/passwd")
    with pytest.raises(ConnectorError):
        resolve_file_path(symlink, directory=False, must_exist=True)


def test_file_adapter_limits_bytes_read(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HS_CONNECTOR_FILE_ROOTS", str(tmp_path))
    path = tmp_path / "eve.json"
    path.write_text("A" * 1000 + "\n" + "B" * 1000 + "\n" + "C" * 1000 + "\n")
    lines = read_file_tail(path, max_lines=10, max_bytes=2100)
    assert lines[-1] == "C" * 1000
    assert all(not line.startswith("A" * 10) for line in lines)


def test_file_config_rejects_nested_log_file_names(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HS_CONNECTOR_FILE_ROOTS", str(tmp_path))
    (tmp_path / "notice.log").write_text("{}\n")
    with pytest.raises(ConnectorError):
        ZeekFileAdapter.validate_config({"path": str(tmp_path), "log_files": ["../etc/passwd"]})
    with pytest.raises(ConnectorError):
        ZeekFileAdapter.validate_config({"path": str(tmp_path), "log_files": "notice.log"})


def test_api_validates_file_paths_before_persisting(auth_client: TestClient, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HS_CONNECTOR_FILE_ROOTS", str(tmp_path))
    rejected = auth_client.post(
        f"{API}/connectors",
        json={
            "name": "bad-file-path",
            "connector_type": "suricata_file",
            "auth_type": "none",
            "config": {"path": "/etc/passwd"},
        },
    )
    assert rejected.status_code == 422
    assert rejected.json()["error"]["details"][0]["field"] == "config"


def test_secret_never_leaks_in_errors_runs_or_audit(auth_client: TestClient, fake: FakeServer, db) -> None:
    fake.route("POST", "/security/user/authenticate", 200, {"data": {"token": "jwt"}})
    fake.route("GET", "/manager/info", 500, {"detail": f"credential {SECRET} rejected"})
    connector = _create_wazuh(auth_client, fake.base_url)

    probe = auth_client.post(f"{API}/connectors/{connector['id']}/health")
    assert probe.status_code == 200
    assert probe.json()["status"] == "unhealthy"
    assert SECRET not in probe.text
    assert "rejected" in probe.json()["error"]

    row = db.get(Connector, UUID(connector["id"]))
    assert SECRET not in (row.last_error or "")
    assert row.config == {"username": "wazuh"}
    runs = list(db.execute(select(ConnectorRun).where(ConnectorRun.connector_id == row.id)).scalars())
    assert runs and all(SECRET not in (run.error or "") for run in runs)

    audit_payloads = [json.dumps(record.payload) for record in db.execute(select(AuditRecord)).scalars()]
    assert audit_payloads
    assert all(SECRET not in payload for payload in audit_payloads)
    assert all("jwt" not in json.dumps(record.detail) for record in runs)


def test_write_capability_is_rejected_without_remote_side_effect(auth_client: TestClient, fake: FakeServer) -> None:
    fake.route("POST", "/security/user/authenticate", 200, {"data": {"token": "jwt"}})
    connector = _create_wazuh(auth_client, fake.base_url)
    rejected = auth_client.post(
        f"{API}/connectors/{connector['id']}/invoke/isolate_endpoint",
        json={"params": {"agents": ["001"]}},
    )
    assert rejected.status_code == 403
    assert rejected.json()["error"]["code"] == "policy_denied"
    assert fake.requests_for("PUT", "/active-response") == []


def test_health_rate_limit_is_enforced(auth_client: TestClient, fake: FakeServer, monkeypatch) -> None:
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    fake.route("POST", "/security/user/authenticate", 200, {"data": {"token": "jwt"}})
    fake.route("GET", "/manager/info", 200, {"data": {"affected_items": [{"version": "4.8"}]}})
    connector = _create_wazuh(auth_client, fake.base_url, rate_limit_per_minute=1)

    first = auth_client.post(f"{API}/connectors/{connector['id']}/health")
    assert first.status_code == 200
    second = auth_client.post(f"{API}/connectors/{connector['id']}/health")
    assert second.status_code == 429
    assert second.json()["error"]["code"] == "rate_limited"
    assert second.headers.get("Retry-After")


def test_sync_rejects_out_of_bounds_limits(auth_client: TestClient, fake: FakeServer) -> None:
    connector = _create_wazuh(auth_client, fake.base_url)
    for limit in (0, 201, -5):
        response = auth_client.post(f"{API}/connectors/{connector['id']}/sync", json={"limit": limit})
        assert response.status_code == 422


def test_secret_with_control_characters_is_rejected(auth_client: TestClient, fake: FakeServer) -> None:
    response = auth_client.post(
        f"{API}/connectors",
        json={
            "name": "control-char-secret",
            "connector_type": "wazuh",
            "base_url": fake.base_url,
            "auth_type": "basic",
            "secret": "line1\nline2",
        },
    )
    assert response.status_code == 422


def test_verify_tls_cannot_be_disabled_in_production(auth_client: TestClient, fake: FakeServer, monkeypatch) -> None:
    monkeypatch.setattr(settings, "env", "production")
    response = auth_client.post(
        f"{API}/connectors",
        json={
            "name": "insecure-tls",
            "connector_type": "wazuh",
            "base_url": fake.base_url,
            "auth_type": "basic",
            "secret": "secret",
            "verify_tls": False,
        },
    )
    assert response.status_code == 422
    assert response.json()["error"]["details"][0]["field"] == "verify_tls"


def test_sanitize_text_removes_terminal_escape_sequences() -> None:
    assert sanitize_text("safe\x1b[31mred\x1b[0m") == "safered"


def test_cross_tenant_mutation_returns_404_not_403(auth_client: TestClient, fake: FakeServer, db) -> None:
    from app.models.core import Organization

    connector = _create_wazuh(auth_client, fake.base_url)
    other = Organization(slug="security-other", name="Other", kind="private", country="ES", sector="general")
    db.add(other)
    db.commit()
    headers = {"X-Organization-Id": str(other.id)}
    for method, path in (
        ("get", f"{API}/connectors/{connector['id']}"),
        ("delete", f"{API}/connectors/{connector['id']}"),
        ("post", f"{API}/connectors/{connector['id']}/sync"),
    ):
        response = getattr(auth_client, method)(
            path, headers=headers, **({"json": {"limit": 10}} if method == "post" else {})
        )
        assert response.status_code == 404
        assert "forbidden" not in response.text.lower()


def test_audit_redacts_secret_bearing_config_keys(auth_client: TestClient, fake: FakeServer, db) -> None:
    connector = _create_wazuh(
        auth_client, fake.base_url, config={"username": "wazuh", "client_secret": "config-secret-value"}
    )
    assert connector["config"]["client_secret"] == "[redacted]"
    audit = db.execute(select(AuditRecord).where(AuditRecord.action == "connector.create")).scalar_one()
    assert "config-secret-value" not in json.dumps(audit.payload)
    assert SECRET not in json.dumps(audit.payload)
