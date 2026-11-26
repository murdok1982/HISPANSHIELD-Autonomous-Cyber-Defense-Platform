"""Attack surface: findings, inventory analysis and bounded discovery jobs."""

from __future__ import annotations

import socketserver
import threading
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import break_glass, login


def _asset(client: TestClient, key: str, **overrides) -> dict:
    payload = {"asset_key": key, "name": key, "kind": "host", "criticality": 3}
    payload.update(overrides)
    response = client.post("/api/v1/assets", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _make_foreign_tenant(admin: TestClient, slug: str, email: str) -> None:
    org = admin.post("/api/v1/organizations", json={"name": f"Org {slug}", "slug": slug})
    assert org.status_code == 201, org.text
    org_id = org.json()["id"]
    with break_glass(admin, org_id):
        member = admin.post(
            "/api/v1/organizations/current/members",
            json={
                "email": email,
                "full_name": "Foreign",
                "role": "vulnerability_manager",
                "password": "Str0ng-Viewer-Pass!2026",
            },
        )
        assert member.status_code == 201, member.text


def _login(email: str) -> TestClient:
    other = TestClient(app)
    login(other, email=email, password="Str0ng-Viewer-Pass!2026")
    return other


class _QuietHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:  # pragma: no cover - exercised through the probe
        self.request.close()


@pytest.fixture
def tcp_server() -> int:
    server = socketserver.TCPServer(("127.0.0.1", 0), _QuietHandler)
    server.allow_reuse_address = True
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_findings_crud_and_status(auth_client: TestClient) -> None:
    asset = _asset(auth_client, "asm-asset")
    created = auth_client.post(
        "/api/v1/attack-surface/findings",
        json={
            "asset_id": asset["id"],
            "kind": "exposed_admin_panel",
            "title": "Admin panel reachable from internet",
            "severity": "high",
            "evidence": "GET /admin returned 200",
            "metadata": {"url": "https://example.test/admin"},
        },
    )
    assert created.status_code == 201, created.text
    finding = created.json()
    assert finding["severity"] == "high"
    assert finding["metadata"]["url"].endswith("/admin")

    listing = auth_client.get("/api/v1/attack-surface/findings", params={"q": "admin"})
    assert listing.status_code == 200
    assert listing.json()["meta"]["total"] == 1

    detail = auth_client.get(f"/api/v1/attack-surface/findings/{finding['id']}")
    assert detail.status_code == 200

    patched = auth_client.patch(
        f"/api/v1/attack-surface/findings/{finding['id']}", json={"status": "triaged", "severity": "critical"}
    )
    assert patched.status_code == 200
    assert patched.json()["status"] == "triaged"
    assert patched.json()["severity"] == "critical"

    invalid = auth_client.patch(f"/api/v1/attack-surface/findings/{finding['id']}", json={"status": "ignored"})
    assert invalid.status_code == 422

    invalid_severity = auth_client.post(
        "/api/v1/attack-surface/findings",
        json={"kind": "bad", "title": "x", "severity": "apocalyptic"},
    )
    assert invalid_severity.status_code == 422


def test_analyze_creates_deduped_findings(auth_client: TestClient) -> None:
    soon = (datetime.now(UTC) + timedelta(days=10)).isoformat()
    _asset(
        auth_client,
        "risky-edge",
        criticality=4,
        ip_addresses=["8.8.8.8"],
        confidence=42,
        os_name="Windows 7 Professional",
        metadata={
            "exposed_ports": [23, 3389],
            "certificates": [
                {"subject": "legacy.example", "expires_at": "2020-01-01T00:00:00Z"},
                {"subject": "soon.example", "expires_at": soon, "self_signed": True},
            ],
        },
    )

    first = auth_client.post("/api/v1/attack-surface/analyze")
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["scanned_assets"] == 1
    assert body["created"] == 9
    for kind in (
        "public_exposure",
        "exposed_service",
        "missing_owner",
        "unverified_asset",
        "end_of_life_software",
        "expired_certificate",
        "expiring_certificate",
        "self_signed_certificate",
    ):
        assert kind in body["by_kind"], kind

    second = auth_client.post("/api/v1/attack-surface/analyze")
    assert second.status_code == 200
    assert second.json()["created"] == 0
    assert second.json()["updated"] == 9

    summary = auth_client.get("/api/v1/attack-surface/summary")
    assert summary.status_code == 200
    assert summary.json()["total"] == 9
    assert summary.json()["by_severity"]["critical"] >= 1

    filtered = auth_client.get("/api/v1/attack-surface/findings", params={"kind": "public_exposure"})
    assert filtered.json()["meta"]["total"] == 1


def test_discovery_scope_validation_rejects_unsafe_targets(auth_client: TestClient) -> None:
    cases = [
        {"mode": "active", "scope_cidrs": ["0.0.0.0/0"]},
        {"mode": "active", "scope_cidrs": ["10.0.0.0/16"]},
        {"mode": "active", "scope_cidrs": ["8.8.8.0/24"]},
        {"mode": "active", "scope_cidrs": ["2001:db8::/120"]},
        {"mode": "active", "scope_cidrs": []},
        {"mode": "active", "scope_cidrs": ["192.168.0.0/24", "192.168.1.0/24"]},
    ]
    for index, case in enumerate(cases):
        response = auth_client.post(
            "/api/v1/attack-surface/discovery-jobs",
            json={"name": f"unsafe-{index}", **case},
        )
        assert response.status_code == 422, (case, response.text)

    passive = auth_client.post(
        "/api/v1/attack-surface/discovery-jobs",
        json={"name": "passive-no-scope", "mode": "passive"},
    )
    assert passive.status_code == 201, passive.text


def test_active_discovery_probes_loopback_and_excludes_ot(auth_client: TestClient, tcp_server: int) -> None:
    job = auth_client.post(
        "/api/v1/attack-surface/discovery-jobs",
        json={
            "name": "loopback-lab",
            "mode": "active",
            "scope_cidrs": ["127.0.0.1/32"],
            "authorization_reference": "AUTH-LAB-2026-001",
            "authorized_by": "CISO",
        },
    )
    assert job.status_code == 201, job.text
    job_id = job.json()["id"]

    run = auth_client.post(f"/api/v1/attack-surface/discovery-jobs/{job_id}/run", json={"ports": [tcp_server]})
    assert run.status_code == 200, run.text
    body = run.json()
    assert body["summary"]["mode"] == "active"
    assert body["summary"]["hosts_scanned"] == 1
    assert body["summary"]["open_ports"] == {"127.0.0.1": [tcp_server]}
    assert body["summary"]["payload_sent"] is False
    assert body["job"]["status"] == "completed"
    assert body["job"]["authorization_reference"] == "AUTH-LAB-2026-001"
    assert body["summary"]["findings_created"] == 1

    findings = auth_client.get("/api/v1/attack-surface/findings", params={"kind": "discovered_open_port"})
    assert findings.json()["meta"]["total"] == 1

    _asset(auth_client, "ot-in-scope", kind="ot", ip_addresses=["127.0.0.1"])
    ot_job = auth_client.post(
        "/api/v1/attack-surface/discovery-jobs",
        json={
            "name": "ot-exclusion",
            "mode": "active",
            "scope_cidrs": ["127.0.0.1/32"],
            "authorization_reference": "AUTH-LAB-2026-002",
        },
    ).json()
    ot_run = auth_client.post(f"/api/v1/attack-surface/discovery-jobs/{ot_job['id']}/run", json={"ports": [tcp_server]})
    assert ot_run.status_code == 200, ot_run.text
    assert ot_run.json()["summary"]["ot_hosts_excluded"] == 1
    assert ot_run.json()["summary"]["open_ports"] == {}

    unauthenticated = auth_client.post(
        "/api/v1/attack-surface/discovery-jobs",
        json={"name": "no-auth", "mode": "active", "scope_cidrs": ["127.0.0.1/32"]},
    )
    assert unauthenticated.status_code == 201
    denied = auth_client.post(
        f"/api/v1/attack-surface/discovery-jobs/{unauthenticated.json()['id']}/run",
        json={"ports": [tcp_server]},
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "policy_denied"


def test_passive_discovery_imports_observed_records(auth_client: TestClient) -> None:
    _asset(
        auth_client,
        "observed-asset",
        ip_addresses=["192.168.10.15"],
        metadata={"exposed_ports": [502, 80]},
    )
    job = auth_client.post(
        "/api/v1/attack-surface/discovery-jobs",
        json={"name": "passive-import", "mode": "passive", "scope_cidrs": ["192.168.10.0/24"]},
    )
    assert job.status_code == 201
    job_id = job.json()["id"]

    run = auth_client.post(f"/api/v1/attack-surface/discovery-jobs/{job_id}/run", json={})
    assert run.status_code == 200, run.text
    summary = run.json()["summary"]
    assert summary["mode"] == "passive"
    assert summary["assets_observed"] == 1
    assert summary["services_observed"] == 2
    assert summary["findings_created"] == 2
    assert summary["network_calls"] == 0

    findings = auth_client.get("/api/v1/attack-surface/findings", params={"kind": "observed_service"})
    assert findings.json()["meta"]["total"] == 2


def test_discovery_job_crud_lifecycle(auth_client: TestClient) -> None:
    created = auth_client.post(
        "/api/v1/attack-surface/discovery-jobs",
        json={"name": "crud-job", "mode": "passive", "scope_cidrs": ["172.16.5.0/24"]},
    )
    assert created.status_code == 201
    job_id = created.json()["id"]

    patched = auth_client.patch(
        f"/api/v1/attack-surface/discovery-jobs/{job_id}",
        json={"name": "crud-job-renamed", "scope_cidrs": ["172.16.6.0/24"], "mode": "passive"},
    )
    assert patched.status_code == 200
    assert patched.json()["name"] == "crud-job-renamed"

    unsafe_patch = auth_client.patch(
        f"/api/v1/attack-surface/discovery-jobs/{job_id}",
        json={"scope_cidrs": ["10.0.0.0/8"], "mode": "active"},
    )
    assert unsafe_patch.status_code == 422

    assert auth_client.get(f"/api/v1/attack-surface/discovery-jobs/{job_id}").status_code == 200
    assert auth_client.delete(f"/api/v1/attack-surface/discovery-jobs/{job_id}").status_code == 204
    assert auth_client.get(f"/api/v1/attack-surface/discovery-jobs/{job_id}").status_code == 404


def test_attack_surface_cross_tenant_and_rbac(auth_client: TestClient) -> None:
    finding = auth_client.post(
        "/api/v1/attack-surface/findings",
        json={"kind": "weak_tls", "title": "TLS 1.0 enabled", "severity": "medium"},
    ).json()
    job = auth_client.post(
        "/api/v1/attack-surface/discovery-jobs", json={"name": "scope-job", "mode": "passive"}
    ).json()

    _make_foreign_tenant(auth_client, "foreign-asm", "foreign.asm@example.eu")
    other = _login("foreign.asm@example.eu")
    try:
        assert other.get(f"/api/v1/attack-surface/findings/{finding['id']}").status_code == 404
        assert other.get(f"/api/v1/attack-surface/discovery-jobs/{job['id']}").status_code == 404
        assert other.get("/api/v1/attack-surface/findings").json()["meta"]["total"] == 0
    finally:
        other.close()

    membership = auth_client.post(
        "/api/v1/organizations/current/members",
        json={
            "email": "viewer.asm@example.eu",
            "full_name": "Viewer ASM",
            "role": "viewer",
            "password": "Str0ng-Viewer-Pass!2026",
        },
    )
    assert membership.status_code == 201
    viewer = _login("viewer.asm@example.eu")
    try:
        assert viewer.get("/api/v1/attack-surface/findings").status_code == 200
        assert viewer.get("/api/v1/attack-surface/summary").status_code == 200
        assert viewer.post("/api/v1/attack-surface/analyze").status_code == 403
        assert (
            viewer.post("/api/v1/attack-surface/discovery-jobs", json={"name": "nope", "mode": "passive"}).status_code
            == 403
        )
    finally:
        viewer.close()
