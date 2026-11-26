"""Protocol-level adapter tests against local fake vendor endpoints."""

from __future__ import annotations

import hashlib
import hmac
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from uuid import uuid4

import pytest

from app.core.config import settings
from app.models.connectors import Connector
from app.services.connectors.adapters.elastic_security import ElasticSecurityAdapter
from app.services.connectors.adapters.generic_webhook import GenericWebhookAdapter
from app.services.connectors.adapters.keycloak import KeycloakAdapter
from app.services.connectors.adapters.microsoft_defender import MicrosoftDefenderAdapter
from app.services.connectors.adapters.microsoft_sentinel import MicrosoftSentinelAdapter
from app.services.connectors.adapters.misp import MispAdapter
from app.services.connectors.adapters.opencti import OpenCTIAdapter
from app.services.connectors.adapters.opnsense import OPNsenseAdapter
from app.services.connectors.adapters.pfsense import PfSenseAdapter
from app.services.connectors.adapters.suricata_file import SuricataFileAdapter
from app.services.connectors.adapters.wazuh import WazuhAdapter
from app.services.connectors.adapters.zeek_file import ZeekFileAdapter
from app.services.connectors.base import adapter_catalog


class FakeAPI:
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

    def requests_for(self, method: str, path: str) -> list[dict[str, Any]]:
        return [
            request
            for request in self.requests
            if request["method"] == method.upper() and request["path"].split("?", 1)[0] == path
        ]

    def _resolve(self, method: str, path: str, body: bytes) -> tuple[int, Any]:
        key = (method.upper(), path.split("?", 1)[0])
        if key in self.handlers:
            return self.handlers[key](self, body)
        if key in self.routes:
            return self.routes[key]
        return self.default

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
                raw = (
                    b"" if status == 204 else (payload if isinstance(payload, bytes) else json.dumps(payload).encode())
                )
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                if raw:
                    self.wfile.write(raw)

            do_GET = _serve
            do_POST = _serve
            do_PUT = _serve
            do_DELETE = _serve
            do_PATCH = _serve

            def log_message(self, *args: Any) -> None:
                return None

        return Handler

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)


@pytest.fixture
def fake():
    api = FakeAPI()
    try:
        yield api
    finally:
        api.stop()


@pytest.fixture(autouse=True)
def _allow_private_networks(monkeypatch):
    monkeypatch.setattr(settings, "connector_allow_private_networks", True)


def make_connector(
    connector_type: str,
    base_url: str | None,
    *,
    auth_type: str = "none",
    config: dict[str, Any] | None = None,
) -> Connector:
    return Connector(
        id=uuid4(),
        org_id=uuid4(),
        name=f"test-{connector_type}",
        connector_type=connector_type,
        version="1.0.0",
        base_url=base_url,
        auth_type=auth_type,
        secret_encrypted=None,
        config=config or {},
        capabilities={},
        status="unknown",
        enabled=True,
        verify_tls=True,
        rate_limit_per_minute=60,
    )


def test_wazuh_authenticates_reads_agents_and_alerts(fake: FakeAPI) -> None:
    fake.route("POST", "/security/user/authenticate", 200, {"data": {"token": "wazuh-jwt"}})
    fake.route("GET", "/manager/info", 200, {"data": {"affected_items": [{"version": "4.8.0"}]}})
    fake.route(
        "GET",
        "/alerts",
        200,
        {"data": {"affected_items": [{"id": "a-1", "rule": {"level": 12}}], "total_affected_items": 1}},
    )
    fake.route("GET", "/agents", 200, {"data": {"affected_items": [{"id": "001", "name": "web-01"}]}})
    adapter = WazuhAdapter(make_connector("wazuh", fake.base_url, auth_type="basic"), "admin:secret-pass")

    health = adapter.health_check()
    assert health.ok is True
    assert health.data["authenticated"] is True
    alerts = adapter.invoke("read_alerts", {"limit": 25})
    assert alerts.ok and len(alerts.data["items"]) == 1
    agents = adapter.invoke("read_agents", {"limit": 25})
    assert agents.data["items"][0]["name"] == "web-01"

    auth_requests = fake.requests_for("POST", "/security/user/authenticate")
    assert len(auth_requests) == 1  # JWT reused from the in-memory cache
    assert auth_requests[0]["headers"]["authorization"].startswith("Basic ")
    assert fake.requests_for("GET", "/agents")[0]["headers"]["authorization"] == "Bearer wazuh-jwt"


def test_elastic_api_key_search(fake: FakeAPI) -> None:
    fake.route("GET", "/api/status", 200, {"cluster_name": "prod", "version": {"number": "8.13.0"}})
    fake.route(
        "POST",
        "/api/detection_engine/signals/search",
        200,
        {
            "hits": {
                "hits": [
                    {"_id": "signal-1", "_source": {"@timestamp": "2024-06-10T10:00:00Z"}},
                    {"_id": "signal-2", "_source": {"@timestamp": "2024-06-10T10:01:00Z"}},
                ]
            }
        },
    )
    adapter = ElasticSecurityAdapter(
        make_connector("elastic_security", fake.base_url, auth_type="api_key"), "elastic-key"
    )
    health = adapter.health_check()
    assert health.ok is True
    assert health.data["version"] == "8.13.0"
    result = adapter.invoke("read_alerts", {"limit": 10})
    assert len(result.data["items"]) == 2
    search_requests = fake.requests_for("POST", "/api/detection_engine/signals/search")
    assert search_requests[0]["headers"]["authorization"] == "ApiKey elastic-key"
    assert json.loads(search_requests[0]["body"])["size"] == 10


def test_sentinel_oauth_and_log_analytics_query() -> None:
    login = FakeAPI()
    analytics = FakeAPI()
    try:
        login.route(
            "POST",
            "/tenant-1/oauth2/v2.0/token",
            200,
            {"access_token": "sentinel-token", "expires_in": 3600},
        )
        analytics.route(
            "POST",
            "/v1/workspaces/workspace-1/query",
            200,
            {
                "tables": [
                    {
                        "columns": [{"name": "TimeGenerated"}, {"name": "AlertName"}],
                        "rows": [["2024-06-10T10:00:00Z", "Suspicious sign-in"]],
                    }
                ]
            },
        )
        connector = make_connector(
            "microsoft_sentinel",
            analytics.base_url,
            auth_type="client_credentials",
            config={
                "tenant_id": "tenant-1",
                "client_id": "client-1",
                "workspace_id": "workspace-1",
                "login_base_url": login.base_url,
                "log_analytics_url": analytics.base_url,
            },
        )
        adapter = MicrosoftSentinelAdapter(connector, "client-secret-value")
        assert adapter.health_check().ok is True
        result = adapter.invoke("read_alerts", {"limit": 10})
        assert result.ok is True
        assert result.data["items"][0]["AlertName"] == "Suspicious sign-in"

        token_request = login.requests_for("POST", "/tenant-1/oauth2/v2.0/token")[0]
        assert b"grant_type=client_credentials" in token_request["body"]
        assert b"client_secret=client-secret-value" in token_request["body"]
        query_request = analytics.requests_for("POST", "/v1/workspaces/workspace-1/query")[0]
        assert query_request["headers"]["authorization"] == "Bearer sentinel-token"
    finally:
        login.stop()
        analytics.stop()


def test_misp_events_and_attribute_search(fake: FakeAPI) -> None:
    fake.route("GET", "/servers/getVersion", 200, {"version": "2.4.180"})
    fake.route(
        "POST",
        "/events/restSearch",
        200,
        {
            "response": [
                {
                    "Event": {
                        "uuid": "event-1",
                        "info": "Phishing",
                        "threat_level_id": "1",
                        "Attribute": [
                            {"type": "ip-dst", "value": "198.51.100.5"},
                            {"type": "domain", "value": "phish.example"},
                        ],
                    }
                }
            ]
        },
    )
    fake.route(
        "POST",
        "/attributes/restSearch",
        200,
        {"response": {"Attribute": [{"type": "sha256", "value": "e" * 64}]}},
    )
    adapter = MispAdapter(make_connector("misp", fake.base_url, auth_type="token_header"), "misp-key")
    assert adapter.health_check().ok is True
    events = adapter.invoke("read_indicators", {"limit": 10})
    assert len(events.data["items"]) == 2
    assert events.data["items"][0]["Attribute"]["type"] == "ip-dst"

    attributes_adapter = MispAdapter(
        make_connector("misp", fake.base_url, auth_type="token_header", config={"search_mode": "attributes"}),
        "misp-key",
    )
    attributes = attributes_adapter.invoke("read_indicators", {"limit": 10})
    assert attributes.data["items"][0]["Attribute"]["type"] == "sha256"
    assert fake.requests_for("GET", "/servers/getVersion")[0]["headers"]["authorization"] == "misp-key"


def test_opencti_graphql_health_and_indicators(fake: FakeAPI) -> None:
    def graphql(api: FakeAPI, body: bytes) -> tuple[int, Any]:
        query = json.loads(body)["query"]
        if "about" in query:
            return 200, {"data": {"about": {"version": "6.2.0"}}}
        return 200, {
            "data": {
                "indicators": {
                    "edges": [
                        {
                            "node": {
                                "id": "indicator--1",
                                "pattern": "[domain-name:value = 'evil.example']",
                                "pattern_type": "stix",
                                "confidence": 80,
                                "x_opencti_score": 70,
                                "objectLabel": [{"value": "c2"}],
                            }
                        }
                    ]
                }
            }
        }

    fake.handle("POST", "/graphql", graphql)
    adapter = OpenCTIAdapter(make_connector("opencti", fake.base_url, auth_type="bearer"), "opencti-token")
    assert adapter.health_check().data["version"] == "6.2.0"
    result = adapter.invoke("read_indicators", {"limit": 20})
    assert result.data["items"][0]["id"] == "indicator--1"
    assert fake.requests_for("POST", "/graphql")[0]["headers"]["authorization"] == "Bearer opencti-token"


def test_keycloak_users_sessions_and_disable(fake: FakeAPI) -> None:
    state = {"enabled": True}
    fake.route("POST", "/realms/master/protocol/openid-connect/token", 200, {"access_token": "kc-token"})
    fake.route("GET", "/admin/serverinfo", 200, {"systemInfo": {"version": "26.0.0"}})
    fake.route("GET", "/admin/realms/master/users", 200, [{"id": "u1", "username": "alice"}])
    fake.route("GET", "/admin/realms/master/users/u1/sessions", 200, [{"id": "s1", "username": "alice"}])

    def update_user(api: FakeAPI, body: bytes) -> tuple[int, Any]:
        state["enabled"] = json.loads(body)["enabled"]
        return 204, {}

    def get_user(api: FakeAPI, body: bytes) -> tuple[int, Any]:
        return 200, {"id": "u1", "username": "alice", "enabled": state["enabled"]}

    fake.handle("PUT", "/admin/realms/master/users/u1", update_user)
    fake.handle("GET", "/admin/realms/master/users/u1", get_user)
    fake.route("POST", "/admin/realms/master/users/u1/logout", 204, {})

    adapter = KeycloakAdapter(
        make_connector(
            "keycloak",
            fake.base_url,
            auth_type="client_credentials",
            config={"realm": "master", "client_id": "hs-admin"},
        ),
        "kc-secret",
    )
    assert adapter.health_check().ok is True
    users = adapter.invoke("read_users", {"limit": 10})
    assert users.data["items"][0]["username"] == "alice"
    sessions = adapter.invoke("read_sessions", {"user_id": "u1"})
    assert sessions.data["items"][0]["id"] == "s1"

    disabled = adapter.invoke("disable_user", {"user_id": "u1"})
    assert disabled.ok is True
    verification = adapter.verify("disable_user", {"user_id": "u1"}, disabled)
    assert verification.ok is True
    assert state["enabled"] is False

    revoked = adapter.invoke("revoke_sessions", {"user_id": "u1"})
    assert revoked.ok is True
    token_request = fake.requests_for("POST", "/realms/master/protocol/openid-connect/token")[0]
    assert b"grant_type=client_credentials" in token_request["body"]
    assert b"client_secret=kc-secret" in token_request["body"]


def test_pfsense_block_and_unblock(fake: FakeAPI) -> None:
    state: dict[str, Any] = {"entries": [], "applied": 0}

    def entries(api: FakeAPI, body: bytes) -> tuple[int, Any]:
        return 200, {"data": state["entries"]}

    def create_entry(api: FakeAPI, body: bytes) -> tuple[int, Any]:
        payload = json.loads(body)
        entry = {"id": 11, "address": payload["address"]}
        state["entries"].append(entry)
        return 200, {"data": entry}

    def delete_entry(api: FakeAPI, body: bytes) -> tuple[int, Any]:
        return 204, {}

    def apply_rules(api: FakeAPI, body: bytes) -> tuple[int, Any]:
        state["applied"] += 1
        return 200, {"status": "ok"}

    fake.route("GET", "/api/v2/firewall/aliases", 200, {"data": [{"id": 3, "name": "hs_block"}]})
    fake.handle("GET", "/api/v2/firewall/alias_entries", entries)
    fake.handle("POST", "/api/v2/firewall/alias_entries", create_entry)
    fake.handle("DELETE", "/api/v2/firewall/alias_entries", delete_entry)
    fake.handle("POST", "/api/v2/firewall/apply", apply_rules)

    adapter = PfSenseAdapter(
        make_connector("pfsense", fake.base_url, auth_type="api_key_header", config={"alias_name": "hs_block"}),
        "pf-key",
    )
    assert adapter.health_check().ok is True
    blocked = adapter.invoke("block_ip", {"ip": "203.0.113.77"})
    assert blocked.ok is True
    assert state["entries"][0]["address"] == "203.0.113.77"
    assert adapter.verify("block_ip", {"ip": "203.0.113.77"}, blocked).ok is True
    assert fake.requests_for("GET", "/api/v2/firewall/aliases")[0]["headers"]["x-api-key"] == "pf-key"

    state["entries"].clear()
    state["entries"].append({"id": 12, "address": "203.0.113.77"})
    unblocked = adapter.invoke("unblock_ip", {"ip": "203.0.113.77"})
    assert unblocked.ok is True
    assert state["applied"] >= 2
    assert fake.requests_for("DELETE", "/api/v2/firewall/alias_entries")


def test_opnsense_alias_add_and_delete(fake: FakeAPI) -> None:
    state: dict[str, Any] = {"rows": []}

    def list_alias(api: FakeAPI, body: bytes) -> tuple[int, Any]:
        return 200, {"rows": state["rows"], "rowCount": len(state["rows"])}

    def add_alias(api: FakeAPI, body: bytes) -> tuple[int, Any]:
        payload = json.loads(body)
        state["rows"].append({"ip": payload["address"]})
        return 200, {"result": "saved"}

    def delete_alias(api: FakeAPI, body: bytes) -> tuple[int, Any]:
        address = json.loads(body)["address"]
        state["rows"] = [row for row in state["rows"] if row["ip"] != address]
        return 200, {"result": "deleted"}

    fake.handle("GET", "/api/firewall/alias_util/list/hs_block", list_alias)
    fake.handle("POST", "/api/firewall/alias_util/add/hs_block", add_alias)
    fake.handle("POST", "/api/firewall/alias_util/delete/hs_block", delete_alias)

    adapter = OPNsenseAdapter(
        make_connector("opnsense", fake.base_url, auth_type="basic", config={"alias_name": "hs_block"}),
        "api-key:api-secret",
    )
    assert adapter.health_check().ok is True
    blocked = adapter.invoke("block_ip", {"ip": "203.0.113.88"})
    assert blocked.ok is True
    assert state["rows"] == [{"ip": "203.0.113.88"}]
    assert adapter.verify("block_ip", {"ip": "203.0.113.88"}, blocked).ok is True
    assert fake.requests_for("GET", "/api/firewall/alias_util/list/hs_block")[0]["headers"]["authorization"].startswith(
        "Basic "
    )
    unblocked = adapter.invoke("unblock_ip", {"ip": "203.0.113.88"})
    assert unblocked.ok is True
    assert state["rows"] == []


def test_generic_webhook_hmac_signature_and_health(fake: FakeAPI) -> None:
    state: dict[str, Any] = {"verified": False, "body": None}

    def hook(api: FakeAPI, body: bytes) -> tuple[int, Any]:
        header = api.requests[-1]["headers"].get("x-hs-signature", "")
        expected = "sha256=" + hmac.new(b"shared-secret", body, hashlib.sha256).hexdigest()
        state["verified"] = hmac.compare_digest(header, expected)
        state["body"] = json.loads(body)
        return 202, {"accepted": True}

    fake.handle("POST", "/hook", hook)
    connector = make_connector(
        "generic_webhook", f"{fake.base_url}/hook", auth_type="hmac", config={"health_check": "no-op"}
    )
    adapter = GenericWebhookAdapter(connector, "shared-secret")
    health = adapter.health_check()
    assert health.ok is True
    assert health.data["health"] == "no-op"

    result = adapter.invoke(
        "notify_webhook",
        {"event": "incident.opened", "summary": "Critical incident", "severity": "critical", "target": "SOC"},
    )
    assert result.ok is True
    assert result.data["delivered"] is True
    assert state["verified"] is True
    assert state["body"]["event"] == "incident.opened"

    fake.route("GET", "/health", 200, {"ok": True})
    healthy_adapter = GenericWebhookAdapter(
        make_connector(
            "generic_webhook",
            fake.base_url,
            auth_type="bearer",
            config={"health_url": f"{fake.base_url}/health"},
        ),
        "webhook-token",
    )
    assert healthy_adapter.health_check().ok is True
    assert fake.requests_for("GET", "/health")[0]["headers"]["authorization"] == "Bearer webhook-token"


def test_microsoft_defender_oauth_alerts_and_isolation() -> None:
    login = FakeAPI()
    api = FakeAPI()
    state = {"isolated": False}
    try:
        login.route("POST", "/tenant-1/oauth2/v2.0/token", 200, {"access_token": "defender-token"})
        api.route("GET", "/api/machines", 200, {"value": [{"id": "m1"}]})
        api.route("GET", "/api/alerts", 200, {"value": [{"id": "alert-1", "title": "Malware"}]})

        def isolate(api_fake: FakeAPI, body: bytes) -> tuple[int, Any]:
            state["isolated"] = True
            return 200, {"status": "pending"}

        def machine(api_fake: FakeAPI, body: bytes) -> tuple[int, Any]:
            return 200, {"id": "m1", "healthStatus": "Isolated" if state["isolated"] else "Active"}

        api.handle("POST", "/api/machines/m1/isolate", isolate)
        api.handle("GET", "/api/machines/m1", machine)

        adapter = MicrosoftDefenderAdapter(
            make_connector(
                "microsoft_defender",
                api.base_url,
                auth_type="client_credentials",
                config={
                    "tenant_id": "tenant-1",
                    "client_id": "client-1",
                    "login_base_url": login.base_url,
                    "api_base_url": api.base_url,
                },
            ),
            "defender-secret",
        )
        assert adapter.health_check().ok is True
        alerts = adapter.invoke("read_alerts", {"limit": 10})
        assert alerts.data["items"][0]["title"] == "Malware"
        isolated = adapter.invoke("isolate_endpoint", {"machine_id": "m1", "comment": "contain"})
        assert isolated.ok is True
        assert state["isolated"] is True
        assert adapter.verify("isolate_endpoint", {"machine_id": "m1"}, isolated).ok is True
        isolate_request = api.requests_for("POST", "/api/machines/m1/isolate")[0]
        assert json.loads(isolate_request["body"])["IsolationType"] == "Full"
    finally:
        login.stop()
        api.stop()


def test_suricata_file_reads_only_alert_lines(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HS_CONNECTOR_FILE_ROOTS", str(tmp_path))
    eve = tmp_path / "eve.json"
    records = [
        {"timestamp": "2024-06-10T10:00:00Z", "event_type": "dns", "dns": {"rrname": "example.test"}},
        {
            "timestamp": "2024-06-10T10:01:00Z",
            "event_type": "alert",
            "flow_id": 1,
            "src_ip": "203.0.113.5",
            "alert": {"signature": "ET SCAN", "severity": 1},
        },
        {
            "timestamp": "2024-06-10T10:02:00Z",
            "event_type": "alert",
            "flow_id": 2,
            "src_ip": "203.0.113.6",
            "alert": {"signature": "ET EXPLOIT", "severity": 2},
        },
    ]
    eve.write_text("\n".join(json.dumps(record) for record in records) + "\n")
    adapter = SuricataFileAdapter(make_connector("suricata_file", None, config={"path": str(eve)}), None)
    health = adapter.health_check()
    assert health.ok is True
    assert health.data["size"] > 0
    result = adapter.invoke("read_alerts", {"limit": 10})
    assert len(result.data["items"]) == 2
    assert {item["src_ip"] for item in result.data["items"]} == {"203.0.113.5", "203.0.113.6"}


def test_zeek_file_reads_configured_logs(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("HS_CONNECTOR_FILE_ROOTS", str(tmp_path))
    notice = tmp_path / "notice.log"
    notice.write_text(
        "\n".join(
            [
                json.dumps(
                    {"ts": 1718014530.0, "uid": "C1", "_path": "notice", "msg": "Tunnel", "severity": "WARNING"}
                ),
                json.dumps({"ts": 1718014531.0, "uid": "C2", "_path": "notice", "msg": "Scan", "severity": "NOTICE"}),
            ]
        )
        + "\n"
    )
    adapter = ZeekFileAdapter(
        make_connector("zeek_file", None, config={"path": str(tmp_path), "log_files": ["notice.log"]}),
        None,
    )
    health = adapter.health_check()
    assert health.ok is True
    assert "notice.log" in health.data["present"]
    result = adapter.invoke("read_alerts", {"limit": 5})
    assert [item["msg"] for item in result.data["items"]] == ["Scan", "Tunnel"]


def test_adapter_catalog_is_complete_and_consistent() -> None:
    catalog = {entry["connector_id"]: entry for entry in adapter_catalog()}
    assert len(catalog) == 12
    for connector_id, entry in catalog.items():
        assert entry["display_name"], connector_id
        assert entry["auth_methods"], connector_id
        assert entry["capabilities"], connector_id
        for capability in entry["capabilities"]:
            assert capability["direction"] in {"read", "write", "admin", "destructive"}
            assert capability["description"], connector_id
    assert "read_alerts" in {capability["name"] for capability in catalog["wazuh"]["capabilities"]}
    assert "isolate_endpoint" in {capability["name"] for capability in catalog["microsoft_defender"]["capabilities"]}
    assert catalog["suricata_file"]["security_profile"] == "local-file-readonly"
