"""Cross-tenant isolation gate across independent domain resources."""

from __future__ import annotations

from fastapi.testclient import TestClient

from app.core.crypto import hash_password
from app.models.assets import Asset, Vulnerability
from app.models.core import Membership, Organization, User
from app.models.incidents import Incident
from tests.conftest import login

EMAIL_A = "tenant-a@hispanshield.eu"
EMAIL_B = "tenant-b@hispanshield.eu"
PASSWORD = "Tenant-Str0ng-Pass!1"


def _seed_two_tenants(db):
    org_a = Organization(slug="tenant-a", name="Tenant A", kind="private")
    org_b = Organization(slug="tenant-b", name="Tenant B", kind="public")
    db.add_all([org_a, org_b])
    db.flush()
    user_a = User(email=EMAIL_A, full_name="Tenant A Admin", password_hash=hash_password(PASSWORD), status="active")
    user_b = User(email=EMAIL_B, full_name="Tenant B Admin", password_hash=hash_password(PASSWORD), status="active")
    db.add_all([user_a, user_b])
    db.flush()
    db.add_all(
        [
            Membership(org_id=org_a.id, user_id=user_a.id, role="org_admin", status="active"),
            Membership(org_id=org_b.id, user_id=user_b.id, role="org_admin", status="active"),
        ]
    )
    asset_b = Asset(org_id=org_b.id, asset_key="secret-b", name="Tenant B ERP", kind="host", criticality=5)
    db.add(asset_b)
    db.flush()
    incident_b = Incident(org_id=org_b.id, ref="HS-2026-9999", title="Tenant B incident", severity="high")
    db.add(incident_b)
    vuln_b = Vulnerability(org_id=org_b.id, asset_id=asset_b.id, title="Tenant B vulnerability", severity="high")
    db.add(vuln_b)
    db.commit()
    return org_a, org_b, asset_b, incident_b, vuln_b


def test_cross_tenant_direct_ids_return_404(seeded, client: TestClient, db) -> None:
    org_a, org_b, asset_b, incident_b, vuln_b = _seed_two_tenants(db)
    login(client, email=EMAIL_A, password=PASSWORD)
    # The caller is a legitimate admin of Tenant A, but every direct identifier
    # belongs to Tenant B. Existence must not be disclosed.
    assert client.get(f"/api/v1/assets/{asset_b.id}").status_code == 404
    assert client.get(f"/api/v1/incidents/{incident_b.id}").status_code == 404
    assert client.get(f"/api/v1/vulnerabilities/{vuln_b.id}").status_code == 404
    assert client.get(f"/api/v1/assets/{asset_b.id}/graph").status_code == 404
    assert client.get(f"/api/v1/assets/{asset_b.id}/relationships").status_code == 404
    assert client.patch(f"/api/v1/incidents/{incident_b.id}", json={"severity": "low"}).status_code == 404
    assert client.delete(f"/api/v1/assets/{asset_b.id}").status_code in {403, 404}
    assert client.get(f"/api/v1/organizations/{org_b.id}").status_code == 404


def test_cross_tenant_organization_header_is_denied(seeded, client: TestClient, db) -> None:
    org_a, org_b, *_ = _seed_two_tenants(db)
    login(client, email=EMAIL_A, password=PASSWORD)
    response = client.get("/api/v1/auth/me", headers={"X-Organization-Id": str(org_b.id)})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "not_found"


def test_lists_never_mix_tenants(seeded, client: TestClient, db) -> None:
    _seed_two_tenants(db)
    login(client, email=EMAIL_A, password=PASSWORD)
    assets = client.get("/api/v1/assets?page_size=200").json()
    assert all(item["name"] != "Tenant B ERP" for item in assets["items"])
    incidents = client.get("/api/v1/incidents?page_size=200").json()
    assert all(item["ref"] != "HS-2026-9999" for item in incidents["items"])
    audit = client.get("/api/v1/organizations/current/audit?page_size=200").json()
    assert "tenant-b" not in str(audit)
