"""AC-31: Nessus/OpenVAS/Trivy importers normalize into one vulnerability instance."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient
from sqlalchemy import func, select

from app.models.assets import Vulnerability

NESSUS = """<?xml version="1.0" ?>
<NessusClientData_v2><Report name="scan"><ReportHost name="10.20.30.40">
<ReportItem port="443" protocol="tcp" severity="3" pluginID="12345" pluginName="Weak TLS cipher">
<cve>CVE-2024-1234</cve><cvss3_base_score>7.5</cvss3_base_score>
<description>The service negotiates a weak cipher.</description>
</ReportItem></ReportHost></Report></NessusClientData_v2>
"""

TRIVY = json.dumps(
    {
        "ArtifactName": "10.20.30.40",
        "Results": [
            {
                "Target": "10.20.30.40",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2024-1234",
                        "PkgName": "openssl",
                        "Severity": "HIGH",
                        "Title": "OpenSSL issue",
                        "Description": "Buffer overflow",
                        "CVSS": {"nvd": {"V3Score": 9.8}},
                    }
                ],
            }
        ],
    }
)


def _asset() -> dict:
    return {
        "asset_key": "scanner-host",
        "name": "Scanner Host",
        "kind": "host",
        "criticality": 4,
        "environment": "production",
        "ip_addresses": ["10.20.30.40"],
        "hostnames": ["scanner-host.corp.local"],
    }


def test_trivy_import_and_cross_scanner_dedupe(auth_client: TestClient, db) -> None:
    assert auth_client.post("/api/v1/assets", json=_asset()).status_code == 201

    first = auth_client.post(
        "/api/v1/vulnerabilities/import",
        json={"format": "trivy", "content": TRIVY},
    )
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["created"] == 1 and body["updated"] == 0
    vulnerability_id = db.execute(select(Vulnerability.id)).scalar_one()

    # The same CVE/port imported from a different scanner updates the instance
    # instead of creating a duplicate (AC-28 cross-scanner dedupe).
    second = auth_client.post(
        "/api/v1/vulnerabilities/import",
        json={"format": "nessus", "content": NESSUS},
    )
    assert second.status_code == 200, second.text
    assert second.json()["created"] == 0
    assert second.json()["updated"] == 1
    assert db.execute(select(func.count()).select_from(Vulnerability)).scalar_one() == 1
    assert db.execute(select(Vulnerability.id)).scalar_one() == vulnerability_id

    stored = db.execute(select(Vulnerability)).scalar_one()
    assert stored.cve_id == "CVE-2024-1234"
    assert stored.metadata_json["port"] == 443
    assert stored.metadata_json["fingerprint"]


def test_unknown_host_is_reported_and_not_created(auth_client: TestClient, db) -> None:
    response = auth_client.post(
        "/api/v1/vulnerabilities/import",
        json={"format": "trivy", "content": TRIVY},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["created"] == 0
    assert body["errors"]
    assert db.execute(select(func.count()).select_from(Vulnerability)).scalar_one() == 0


def test_xml_doctype_is_rejected(auth_client: TestClient) -> None:
    bomb = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><report><results/></report>'
    response = auth_client.post(
        "/api/v1/vulnerabilities/import",
        json={"format": "nessus", "content": bomb},
    )
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_import_is_idempotent_with_header(auth_client: TestClient) -> None:
    auth_client.post("/api/v1/assets", json=_asset())
    payload = {"format": "trivy", "content": TRIVY}
    headers = {"Idempotency-Key": "scanner-import-001"}
    first = auth_client.post("/api/v1/vulnerabilities/import", json=payload, headers=headers)
    assert first.status_code == 200, first.text
    replay = auth_client.post("/api/v1/vulnerabilities/import", json=payload, headers=headers)
    assert replay.status_code == 200
    assert replay.headers.get("Idempotent-Replayed") == "true"
    assert replay.json() == first.json()
