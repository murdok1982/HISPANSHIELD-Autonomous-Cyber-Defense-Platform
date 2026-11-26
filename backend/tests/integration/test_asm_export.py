"""AC-25: STIX 2.1 / CSV attack-surface export with lossless ip/port round-trip."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.errors import ValidationFailure
from app.modules.attack_surface.stix import parse_bundle


def _asset(key: str) -> dict:
    return {
        "asset_key": key,
        "name": f"Asset {key}",
        "kind": "host",
        "criticality": 4,
        "environment": "production",
        "ip_addresses": ["203.0.113.10", "10.0.0.5"],
        "metadata": {"exposed_ports": [22, 443], "services": [{"port": 8443, "name": "https-alt"}]},
    }


def test_stix_roundtrip(auth_client: TestClient) -> None:
    created = auth_client.post("/api/v1/assets", json=_asset("asm-export-1"))
    assert created.status_code == 201, created.text

    analyzed = auth_client.post("/api/v1/attack-surface/analyze")
    assert analyzed.status_code == 200, analyzed.text

    response = auth_client.get("/api/v1/attack-surface/export", params={"format": "stix2.1"})
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/stix+json")

    bundle = response.json()
    assert bundle["type"] == "bundle"
    assert bundle["id"].startswith("bundle--")
    assert bundle["objects"]

    infrastructure = next(obj for obj in bundle["objects"] if obj["type"] == "infrastructure")
    assert infrastructure["spec_version"] == "2.1"
    assert infrastructure["x_hispanshield_asset_key"] == "asm-export-1"
    assert infrastructure["x_hispanshield_ips"] == ["203.0.113.10", "10.0.0.5"]
    assert infrastructure["x_hispanshield_ports"] == [22, 443, 8443]

    expected = {
        ("asm-export-1", "203.0.113.10", 22),
        ("asm-export-1", "203.0.113.10", 443),
        ("asm-export-1", "203.0.113.10", 8443),
        ("asm-export-1", "10.0.0.5", 22),
        ("asm-export-1", "10.0.0.5", 443),
        ("asm-export-1", "10.0.0.5", 8443),
    }
    imported = {(row["asset_key"], row["ip"], row["port"]) for row in parse_bundle(bundle)}
    assert imported == expected

    addresses = {obj["value"] for obj in bundle["objects"] if obj["type"] in {"ipv4-addr", "ipv6-addr"}}
    assert addresses == {"203.0.113.10", "10.0.0.5"}

    # Custom properties are consistent every time the export runs.
    again = auth_client.get("/api/v1/attack-surface/export", params={"format": "stix2.1"}).json()
    assert again["id"] == bundle["id"]
    assert {obj["id"] for obj in again["objects"]} == {obj["id"] for obj in bundle["objects"]}


def test_csv_export_has_bom_safe_rows(auth_client: TestClient) -> None:
    auth_client.post("/api/v1/assets", json=_asset("asm-export-2"))
    auth_client.post("/api/v1/attack-surface/analyze")

    response = auth_client.get("/api/v1/attack-surface/export", params={"format": "csv"})
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("text/csv")
    lines = response.text.splitlines()
    assert lines[0].startswith("asset_key,asset_name,kind,criticality,ip,port")
    assert any("203.0.113.10" in line and "443" in line for line in lines[1:])

    invalid = auth_client.get("/api/v1/attack-surface/export", params={"format": "xml"})
    assert invalid.status_code == 422


def test_parse_bundle_rejects_non_stix_payloads() -> None:
    with pytest.raises(ValidationFailure):
        parse_bundle({"type": "not-a-bundle", "objects": []})
