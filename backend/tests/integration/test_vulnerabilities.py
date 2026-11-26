"""Vulnerability lifecycle, imports and explainable prioritisation."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.models.ti import ThreatIndicator
from tests.conftest import login


def _asset(client: TestClient, key: str, **overrides) -> dict:
    payload = {"asset_key": key, "name": key, "kind": "host", "criticality": 3}
    payload.update(overrides)
    response = client.post("/api/v1/assets", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _vuln(**overrides) -> dict:
    payload = {"title": "Sample vulnerability", "cvss_score": 6.5, "exposure": "internal"}
    payload.update(overrides)
    return payload


def _make_foreign_tenant(admin: TestClient, slug: str, email: str) -> None:
    org = admin.post("/api/v1/organizations", json={"name": f"Org {slug}", "slug": slug})
    assert org.status_code == 201, org.text
    org_id = org.json()["id"]
    member = admin.post(
        "/api/v1/organizations/current/members",
        json={
            "email": email,
            "full_name": "Foreign",
            "role": "vulnerability_manager",
            "password": "Str0ng-Viewer-Pass!2026",
        },
        headers={"X-Organization-Id": org_id},
    )
    assert member.status_code == 201, member.text


def _login(email: str) -> TestClient:
    other = TestClient(app)
    login(other, email=email, password="Str0ng-Viewer-Pass!2026")
    return other


def test_vulnerability_crud_transitions_and_priority_order(auth_client: TestClient) -> None:
    low_asset = _asset(auth_client, "low-asset", criticality=1)
    high_asset = _asset(auth_client, "high-asset", criticality=5, ip_addresses=["203.0.113.10"])

    low = auth_client.post(
        "/api/v1/vulnerabilities",
        json=_vuln(title="Low internal", asset_id=low_asset["id"], cvss_score=5.0, epss_score=0.01),
    )
    assert low.status_code == 201, low.text

    high = auth_client.post(
        "/api/v1/vulnerabilities",
        json=_vuln(
            title="High public KEV",
            asset_id=high_asset["id"],
            cvss_score=7.5,
            epss_score=0.85,
            kev=True,
            exploitable=True,
            exposure="public",
            cve_id="CVE-2024-20001",
        ),
    )
    assert high.status_code == 201, high.text
    assert high.json()["priority_score"] > low.json()["priority_score"]
    assert "cvss=" in high.json()["priority_reason"]
    assert "kev=" in high.json()["priority_reason"]

    listing = auth_client.get("/api/v1/vulnerabilities")
    assert listing.status_code == 200
    items = listing.json()["items"]
    assert items[0]["title"] == "High public KEV"
    assert items[0]["priority_score"] >= items[1]["priority_score"]

    detail = auth_client.get(f"/api/v1/vulnerabilities/{high.json()['id']}")
    assert detail.status_code == 200
    assert detail.json()["asset"]["asset_key"] == "high-asset"
    assert detail.json()["catalog"] is None

    mitigated = auth_client.patch(f"/api/v1/vulnerabilities/{high.json()['id']}", json={"status": "mitigated"})
    assert mitigated.status_code == 200
    assert mitigated.json()["status"] == "mitigated"

    invalid = auth_client.patch(f"/api/v1/vulnerabilities/{high.json()['id']}", json={"status": "accepted"})
    assert invalid.status_code == 409

    reopened = auth_client.patch(f"/api/v1/vulnerabilities/{high.json()['id']}", json={"status": "reopened"})
    assert reopened.status_code == 200

    deleted = auth_client.delete(f"/api/v1/vulnerabilities/{high.json()['id']}")
    assert deleted.status_code == 204
    assert auth_client.get(f"/api/v1/vulnerabilities/{high.json()['id']}").status_code == 404


def test_vulnerability_validation_errors(auth_client: TestClient) -> None:
    assert auth_client.post("/api/v1/vulnerabilities", json=_vuln(cvss_score=11)).status_code == 422
    assert auth_client.post("/api/v1/vulnerabilities", json=_vuln(cve_id="CVE-24-1")).status_code == 422
    assert auth_client.post("/api/v1/vulnerabilities", json=_vuln(exposure="wan")).status_code == 422
    assert auth_client.post("/api/v1/vulnerabilities", json=_vuln(epss_score=2.0)).status_code == 422
    assert auth_client.post("/api/v1/vulnerabilities", json={**_vuln(), "org_id": "x"}).status_code == 422
    assert auth_client.post("/api/v1/vulnerabilities", json=_vuln(due_at="not-a-date")).status_code == 422


def test_vulnerability_cross_tenant_isolation(auth_client: TestClient) -> None:
    vulnerability = auth_client.post("/api/v1/vulnerabilities", json=_vuln()).json()
    _make_foreign_tenant(auth_client, "foreign-vulns", "foreign.vulns@example.eu")
    other = _login("foreign.vulns@example.eu")
    try:
        assert other.get(f"/api/v1/vulnerabilities/{vulnerability['id']}").status_code == 404
        assert (
            other.patch(f"/api/v1/vulnerabilities/{vulnerability['id']}", json={"status": "mitigated"}).status_code
            == 404
        )
        assert other.get("/api/v1/vulnerabilities").json()["meta"]["total"] == 0
        assert other.get("/api/v1/vulnerabilities/summary").json()["total"] == 0
    finally:
        other.close()


def test_viewer_cannot_write_vulnerabilities(auth_client: TestClient) -> None:
    membership = auth_client.post(
        "/api/v1/organizations/current/members",
        json={
            "email": "viewer.vulns@example.eu",
            "full_name": "Viewer Vulns",
            "role": "viewer",
            "password": "Str0ng-Viewer-Pass!2026",
        },
    )
    assert membership.status_code == 201
    viewer = _login("viewer.vulns@example.eu")
    try:
        assert viewer.get("/api/v1/vulnerabilities").status_code == 200
        assert viewer.post("/api/v1/vulnerabilities", json=_vuln()).status_code == 403
        assert (
            viewer.post(
                "/api/v1/vulnerabilities/import/cve",
                json={"items": [{"cve_id": "CVE-2025-19999", "description": "denied"}]},
            ).status_code
            == 403
        )
    finally:
        viewer.close()


def test_cve_import_idempotency_and_asset_findings(auth_client: TestClient) -> None:
    asset = _asset(auth_client, "cve-asset", criticality=4)

    first = auth_client.post(
        "/api/v1/vulnerabilities/import/cve",
        json={
            "items": [
                {
                    "cve_id": "CVE-2025-10001",
                    "description": "Remote code execution in example daemon",
                    "cvss_score": 9.1,
                    "epss_score": 0.2,
                    "kev": True,
                    "asset_ids": [asset["id"]],
                }
            ]
        },
    )
    assert first.status_code == 200, first.text
    assert first.json()["catalog_created"] == 1
    assert first.json()["vulnerabilities_created"] == 1

    second = auth_client.post(
        "/api/v1/vulnerabilities/import/cve",
        json={
            "items": [
                {
                    "cve_id": "CVE-2025-10001",
                    "description": "Remote code execution in example daemon",
                    "cvss_score": 9.1,
                    "epss_score": 0.65,
                    "kev": True,
                    "asset_ids": [asset["id"]],
                }
            ]
        },
    )
    body = second.json()
    assert body["catalog_updated"] == 1
    assert body["vulnerabilities_created"] == 0
    assert body["vulnerabilities_updated"] == 1

    listed = auth_client.get("/api/v1/vulnerabilities", params={"q": "CVE-2025-10001"}).json()
    assert listed["meta"]["total"] == 1
    vulnerability = listed["items"][0]
    assert vulnerability["kev"] is True
    assert vulnerability["epss_score"] == 0.65

    missing_asset = auth_client.post(
        "/api/v1/vulnerabilities/import/cve",
        json={
            "items": [
                {
                    "cve_id": "CVE-2025-10002",
                    "description": "Another issue",
                    "asset_ids": ["00000000-0000-0000-0000-000000000001"],
                }
            ]
        },
    )
    assert missing_asset.status_code == 200
    assert len(missing_asset.json()["errors"]) == 1

    oversized = auth_client.post(
        "/api/v1/vulnerabilities/import/cve",
        json={"items": [{"cve_id": f"CVE-2025-{20000 + i}", "description": "bulk"} for i in range(501)]},
    )
    assert oversized.status_code == 422


def test_kev_and_epss_imports_recalculate_priority(seeded, auth_client: TestClient) -> None:
    vulnerability = auth_client.post(
        "/api/v1/vulnerabilities", json=_vuln(cve_id="CVE-2024-30001", cvss_score=8.0)
    ).json()
    before = vulnerability["priority_score"]

    kev = auth_client.post(
        "/api/v1/vulnerabilities/import/kev",
        json={
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-30001",
                    "shortDescription": "Actively exploited issue",
                    "requiredAction": "Apply vendor patch",
                }
            ]
        },
    )
    assert kev.status_code == 200, kev.text
    assert kev.json()["catalog_created"] == 1
    assert kev.json()["vulnerabilities_marked"] == 1

    after_kev = auth_client.get(f"/api/v1/vulnerabilities/{vulnerability['id']}").json()
    assert after_kev["kev"] is True
    assert after_kev["priority_score"] > before

    epss = auth_client.post(
        "/api/v1/vulnerabilities/import/epss",
        json={"items": [{"cve": "CVE-2024-30001", "epss": 0.97, "percentile": 0.99}]},
    )
    assert epss.status_code == 200, epss.text
    assert epss.json()["catalog_updated"] == 1
    assert epss.json()["vulnerabilities_updated"] == 1

    after_epss = auth_client.get(f"/api/v1/vulnerabilities/{vulnerability['id']}").json()
    assert after_epss["epss_score"] == 0.97
    assert after_epss["priority_score"] > after_kev["priority_score"]

    csv_vuln = auth_client.post("/api/v1/vulnerabilities", json=_vuln(cve_id="CVE-2024-30002", cvss_score=5.0)).json()
    csv_import = auth_client.post(
        "/api/v1/vulnerabilities/import/epss",
        json={"csv": "cve,epss,percentile\nCVE-2024-30002,0.42,0.8\n"},
    )
    assert csv_import.status_code == 200
    assert csv_import.json()["parsed"] == 1
    assert csv_import.json()["errors"] == []
    csv_after = auth_client.get(f"/api/v1/vulnerabilities/{csv_vuln['id']}").json()
    assert csv_after["epss_score"] == 0.42

    unknown = auth_client.post("/api/v1/vulnerabilities/import/kev", json={"cves": ["CVE-2024-99999"]})
    assert unknown.status_code == 200
    assert unknown.json()["unknown_cves"] == ["CVE-2024-99999"]

    invalid_csv = auth_client.post("/api/v1/vulnerabilities/import/epss", json={"csv": "not-a-cve,0.5\n"})
    assert invalid_csv.status_code == 200
    assert len(invalid_csv.json()["errors"]) == 1


def test_recalculate_summary_and_threat_match(seeded, auth_client: TestClient, db) -> None:
    asset = _asset(auth_client, "ti-asset", criticality=4, ip_addresses=["198.51.100.7"], hostnames=["ti.local"])
    db.add(
        ThreatIndicator(
            org_id=seeded["org"].id,
            indicator_type="ip",
            value="198.51.100.7",
            confidence=95,
            severity="high",
            source="test",
        )
    )
    db.commit()

    vulnerability = auth_client.post(
        "/api/v1/vulnerabilities",
        json=_vuln(asset_id=asset["id"], cvss_score=7.2, exposure="public"),
    )
    assert vulnerability.status_code == 201, vulnerability.text
    assert "threat_intel=10.00" in vulnerability.json()["priority_reason"]

    recalculated = auth_client.post(f"/api/v1/vulnerabilities/{vulnerability.json()['id']}/recalculate")
    assert recalculated.status_code == 200
    assert "asset_criticality=" in recalculated.json()["priority_reason"]

    summary = auth_client.get("/api/v1/vulnerabilities/summary")
    assert summary.status_code == 200
    body = summary.json()
    assert body["total"] == 1
    assert body["by_severity"]["high"] == 1
    assert body["top_risky"][0]["id"] == vulnerability.json()["id"]
    assert body["mean_priority"] > 0

    accepted = auth_client.patch(f"/api/v1/vulnerabilities/{vulnerability.json()['id']}", json={"status": "accepted"})
    assert accepted.status_code == 200
    blocked = auth_client.post(f"/api/v1/vulnerabilities/{vulnerability.json()['id']}/recalculate")
    assert blocked.status_code == 403


def test_vulnerability_lifecycle_and_filters(auth_client: TestClient) -> None:
    asset = _asset(auth_client, "filter-asset")
    auth_client.post(
        "/api/v1/vulnerabilities",
        json=_vuln(title="KEV issue", asset_id=asset["id"], kev=True, cvss_score=9.0, severity="critical"),
    )
    auth_client.post(
        "/api/v1/vulnerabilities",
        json=_vuln(title="Plain issue", asset_id=asset["id"], kev=False, cvss_score=3.0, severity="low"),
    )

    kev_only = auth_client.get("/api/v1/vulnerabilities", params={"kev": "true"}).json()
    assert kev_only["meta"]["total"] == 1

    critical = auth_client.get("/api/v1/vulnerabilities", params={"severity": "critical"}).json()
    assert critical["meta"]["total"] == 1

    by_asset = auth_client.get("/api/v1/vulnerabilities", params={"asset_id": asset["id"]}).json()
    assert by_asset["meta"]["total"] == 2

    ascending = auth_client.get("/api/v1/vulnerabilities", params={"sort": "cvss_score", "order": "asc"}).json()
    assert ascending["items"][0]["cvss_score"] <= ascending["items"][1]["cvss_score"]

    assert auth_client.get("/api/v1/vulnerabilities", params={"sort": "raw_sql"}).status_code == 422
    assert auth_client.get("/api/v1/vulnerabilities/summary").json()["total"] == 2

    assert db_count(auth_client) == 2


def db_count(client: TestClient) -> int:
    response = client.get("/api/v1/vulnerabilities", params={"page_size": 200})
    return response.json()["meta"]["total"]
