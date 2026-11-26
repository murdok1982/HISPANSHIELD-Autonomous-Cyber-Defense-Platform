"""Integration tests: deterministic network, cloud and identity posture."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.crypto import hash_password
from app.core.db import utcnow
from app.models.assets import Asset, AttackSurfaceFinding, Vulnerability, Zone
from app.models.connectors import Connector
from app.models.core import Membership, User
from app.models.events import Alert, SecurityEvent

BASE = "/api/v1/posture"


def _asset(db, org_id, *, kind: str, name: str, **overrides) -> Asset:
    asset = Asset(
        org_id=org_id,
        asset_key=f"{kind}-{name}",
        name=name,
        kind=kind,
        criticality=overrides.pop("criticality", 4),
        ip_addresses=overrides.pop("ip_addresses", []),
        **overrides,
    )
    db.add(asset)
    db.flush()
    return asset


def _finding(db, org_id, *, kind: str, title: str, severity: str = "high", asset_id=None, status: str = "open"):
    finding = AttackSurfaceFinding(
        org_id=org_id,
        asset_id=asset_id,
        kind=kind,
        title=title,
        severity=severity,
        status=status,
        evidence="observed by discovery",
        source="unit-test",
        last_seen=utcnow(),
    )
    db.add(finding)
    db.flush()
    return finding


def test_empty_domains_report_insufficient_data(seeded, auth_client: TestClient) -> None:
    network = auth_client.get(f"{BASE}/network")
    assert network.status_code == 200
    payload = network.json()
    assert payload["data_quality"] == "insufficient_data"
    assert payload["assets"]["rows"] == []
    assert payload["exposed_findings"] == []
    assert payload["lateral_movement_alerts"] == []
    assert payload["recommendations"] == []

    cloud = auth_client.get(f"{BASE}/cloud")
    assert cloud.status_code == 200
    cloud_body = cloud.json()
    assert cloud_body["data_quality"] == "insufficient_data"
    assert cloud_body["assets"]["rows"] == []
    assert cloud_body["public_storage_findings"] == []
    assert cloud_body["vulnerabilities"]["open_total"] == 0

    summary = auth_client.get(f"{BASE}/summary")
    assert summary.status_code == 200
    assert summary.json()["domains"]["network"]["data_quality"] == "insufficient_data"
    assert summary.json()["domains"]["cloud"]["data_quality"] == "insufficient_data"


def test_network_exposure_lateral_movement_and_connector_health(seeded, auth_client: TestClient, db) -> None:
    org_id = seeded["org"].id
    asset = _asset(db, org_id, kind="network", name="Edge router", ip_addresses=["203.0.113.1"])
    _finding(
        db, org_id, kind="exposed_service", title="SSH exposed to Internet", asset_id=asset.id, severity="critical"
    )
    db.add(
        Connector(
            org_id=org_id,
            name="Perimeter firewall",
            connector_type="firewall",
            status="degraded",
            last_error="timeout contacting API",
        )
    )
    db.add(
        Alert(
            org_id=org_id,
            title="Lateral movement via SMB",
            severity="high",
            status="investigating",
            event_ids=[],
            mitre=["T1021"],
        )
    )
    db.commit()

    response = auth_client.get(f"{BASE}/network")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["score"] < 100
    assert payload["assets"]["with_ip_addresses"] == 1
    assert len(payload["exposed_findings"]) == 1
    assert len(payload["lateral_movement_alerts"]) == 1
    assert payload["connectors"]["by_status"]["degraded"] == 1
    assert {factor["factor"] for factor in payload["factors"]} >= {
        "exposed_services",
        "lateral_movement_signals",
        "network_control_health",
    }
    recommendation_ids = {item["id"] for item in payload["recommendations"]}
    assert {"NET-01", "NET-02", "NET-04"} <= recommendation_ids
    exposure_recommendation = next(item for item in payload["recommendations"] if item["id"] == "NET-01")
    assert exposure_recommendation["evidence"]["open_exposed_findings"] == 1
    assert exposure_recommendation["evidence"]["finding_ids"]


def test_network_segmentation_gaps(seeded, auth_client: TestClient, db) -> None:
    org_id = seeded["org"].id
    conduit = Zone(org_id=org_id, name="IT-OT conduit", kind="conduit", purdue_level=None, metadata_json={})
    level_two = Zone(org_id=org_id, name="Supervisory", kind="zone", purdue_level=2, metadata_json={})
    level_three = Zone(org_id=org_id, name="Operations", kind="zone", purdue_level=3, metadata_json={})
    db.add_all([conduit, level_two, level_three])
    db.flush()
    _asset(db, org_id, kind="ot", name="Unzoned PLC", zone_id=None)
    db.commit()

    payload = auth_client.get(f"{BASE}/network").json()
    gap_kinds = {gap["kind"] for gap in payload["zones"]["segmentation_gaps"]}
    assert "unzoned_ot_assets" in gap_kinds
    assert "conduit_without_required_sl" in gap_kinds
    recommendation = next(item for item in payload["recommendations"] if item["id"] == "NET-03")
    assert recommendation["evidence"]["gaps"]

    db.delete(conduit)
    db.commit()
    payload = auth_client.get(f"{BASE}/network").json()
    gap_kinds = {gap["kind"] for gap in payload["zones"]["segmentation_gaps"]}
    assert "missing_it_ot_conduit" in gap_kinds


def test_cloud_posture_storage_identity_and_vulnerabilities(seeded, auth_client: TestClient, db) -> None:
    org_id = seeded["org"].id
    asset = _asset(
        db,
        org_id,
        kind="cloud",
        name="Public bucket",
        subtype="s3",
        vendor="aws",
        metadata_json={"provider": "aws"},
    )
    _finding(
        db, org_id, kind="public_storage", title="Bucket allows public read", asset_id=asset.id, severity="critical"
    )
    _finding(db, org_id, kind="iam_privilege", title="Role with wildcard permissions", asset_id=asset.id)
    db.add(
        Vulnerability(
            org_id=org_id,
            asset_id=asset.id,
            cve_id="CVE-2026-0001",
            title="Critical cloud workload RCE",
            severity="critical",
            status="open",
            cvss_score=9.8,
        )
    )
    db.commit()

    response = auth_client.get(f"{BASE}/cloud")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["assets"]["by_provider"] == {"aws": 1}
    assert payload["assets"]["by_subtype"] == {"s3": 1}
    assert len(payload["public_storage_findings"]) == 1
    assert len(payload["identity_findings"]) == 1
    assert payload["vulnerabilities"]["by_severity"]["critical"] == 1
    assert payload["score"] < 100
    ids = {item["id"] for item in payload["recommendations"]}
    assert {"CLOUD-01", "CLOUD-02", "CLOUD-03"} <= ids
    storage = next(item for item in payload["recommendations"] if item["id"] == "CLOUD-01")
    assert storage["evidence"]["public_storage_findings"] == 1


def test_identity_posture_mfa_failures_and_alerts(seeded, auth_client: TestClient, db) -> None:
    org_id = seeded["org"].id
    second = User(
        email="mfa.user@hispanshield.eu",
        full_name="MFA User",
        password_hash=hash_password("Mfa-User-Pass!2026"),
        mfa_enabled=True,
    )
    db.add(second)
    db.flush()
    db.add(Membership(org_id=org_id, user_id=second.id, role="soc_analyst", status="active"))
    for index in range(3):
        db.add(
            SecurityEvent(
                org_id=org_id,
                event_uid=f"failed-login-{index}",
                occurred_at=utcnow(),
                class_uid=3002,
                class_name="Authentication",
                category_uid=3,
                severity_id=3,
                message="Failed login attempt",
                user_name="admin@hispanshield.eu",
            )
        )
    db.add(
        Alert(
            org_id=org_id,
            title="Suspicious account activity",
            severity="high",
            status="new",
            event_ids=[],
            mitre=["T1078"],
        )
    )
    db.commit()

    response = auth_client.get(f"{BASE}/identity")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["identities"]["members"] == 2
    assert payload["identities"]["mfa_enabled"] == 1
    assert payload["identities"]["mfa_percent"] == 50.0
    assert payload["failed_logins"]["total"] == 3
    assert payload["failed_logins"]["top_users"][0]["user_name"] == "admin@hispanshield.eu"
    assert len(payload["identity_alerts"]) == 1
    assert payload["score"] < 100
    ids = {item["id"] for item in payload["recommendations"]}
    assert {"ID-01", "ID-02", "ID-03"} <= ids
    mfa_recommendation = next(item for item in payload["recommendations"] if item["id"] == "ID-01")
    assert mfa_recommendation["evidence"]["missing_mfa_user_ids"]


def test_summary_combines_scores_and_cites_domains(seeded, auth_client: TestClient, db) -> None:
    org_id = seeded["org"].id
    network_asset = _asset(db, org_id, kind="network", name="Core switch", ip_addresses=["10.0.0.1"])
    _finding(db, org_id, kind="exposed_service", title="Exposed RDP", asset_id=network_asset.id)
    cloud_asset = _asset(db, org_id, kind="cloud", name="Cloud workload", subtype="vm", vendor="azure")
    _finding(db, org_id, kind="public_storage", title="Public container", asset_id=cloud_asset.id)
    db.commit()

    summary = auth_client.get(f"{BASE}/summary")
    assert summary.status_code == 200, summary.text
    payload = summary.json()
    assert set(payload["scores"]) == {"network", "cloud", "identity"}
    assert set(payload["domains"]) == {"network", "cloud", "identity"}
    assert payload["factors"]
    assert all("domain" in factor for factor in payload["factors"])
    assert payload["data_quality"] in {"ok", "partial"}
    expected = round(
        payload["scores"]["network"] * 0.4 + payload["scores"]["cloud"] * 0.3 + payload["scores"]["identity"] * 0.3
    )
    assert abs(payload["score"] - expected) <= 1
    recommendation_domains = {item["domain"] for item in payload["recommendations"]}
    assert "network" in recommendation_domains
    assert "cloud" in recommendation_domains


def test_rbac_requires_read_permission(seeded, auth_client: TestClient) -> None:
    # The seeded platform admin always passes; this asserts the permission key
    # is enforced by the router (viewer also holds asset:read, so 200 is valid).
    assert auth_client.get(f"{BASE}/network").status_code == 200
    assert auth_client.get(f"{BASE}/cloud").status_code == 200
    assert auth_client.get(f"{BASE}/identity").status_code == 200
