"""Asset intelligence: CRUD, pagination, tenancy, imports, graph and zones."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.main import app
from app.models.assets import Vulnerability
from app.models.core import AuditRecord
from tests.conftest import login


def _asset(key: str, **overrides) -> dict:
    payload = {
        "asset_key": key,
        "name": f"Asset {key}",
        "kind": "host",
        "criticality": 3,
        "environment": "production",
    }
    payload.update(overrides)
    return payload


def _make_foreign_tenant(admin: TestClient, slug: str, email: str) -> str:
    org = admin.post("/api/v1/organizations", json={"name": f"Org {slug}", "slug": slug})
    assert org.status_code == 201, org.text
    org_id = org.json()["id"]
    member = admin.post(
        "/api/v1/organizations/current/members",
        json={
            "email": email,
            "full_name": f"User {slug}",
            "role": "vulnerability_manager",
            "password": "Str0ng-Viewer-Pass!2026",
        },
        headers={"X-Organization-Id": org_id},
    )
    assert member.status_code == 201, member.text
    return org_id


def _login_other(email: str) -> TestClient:
    other = TestClient(app)
    login(other, email=email, password="Str0ng-Viewer-Pass!2026")
    return other


def test_asset_crud_and_audit(seeded, auth_client: TestClient, db) -> None:
    created = auth_client.post(
        "/api/v1/assets",
        json=_asset(
            "srv-001",
            ip_addresses=["10.0.0.10", "192.168.1.5"],
            mac_addresses=["aa:bb:cc:dd:ee:ff"],
            hostnames=["srv-001.corp.local"],
            tags=["critical", "erp"],
            metadata={"rack": "R1"},
        ),
    )
    assert created.status_code == 201, created.text
    asset = created.json()
    assert asset["kind"] == "host"
    assert asset["ip_addresses"] == ["10.0.0.10", "192.168.1.5"]
    assert asset["metadata"] == {"rack": "R1"}

    listing = auth_client.get("/api/v1/assets", params={"q": "srv-001"})
    assert listing.status_code == 200
    assert listing.json()["meta"]["total"] == 1

    detail = auth_client.get(f"/api/v1/assets/{asset['id']}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["identities"] == []
    assert body["relationships"] == []
    assert body["iot"] is None and body["ot"] is None
    assert body["vulnerability_summary"]["total"] == 0

    updated = auth_client.patch(f"/api/v1/assets/{asset['id']}", json={"criticality": 5, "status": "quarantined"})
    assert updated.status_code == 200
    assert updated.json()["criticality"] == 5
    assert updated.json()["status"] == "quarantined"

    db.expire_all()
    audit = db.execute(
        select(AuditRecord).where(
            AuditRecord.org_id == seeded["org"].id,
            AuditRecord.action == "asset.create",
            AuditRecord.resource_id == asset["id"],
        )
    ).scalar_one()
    assert audit.outcome == "success"


def test_asset_filters_pagination_and_sort(auth_client: TestClient) -> None:
    for key, kind, criticality in (("db-01", "host", 5), ("iot-01", "iot", 2), ("net-01", "network", 4)):
        response = auth_client.post(
            "/api/v1/assets", json=_asset(key, name=key.upper(), kind=kind, criticality=criticality)
        )
        assert response.status_code == 201, response.text

    by_kind = auth_client.get("/api/v1/assets", params={"kind": "iot"})
    assert by_kind.json()["meta"]["total"] == 1

    by_criticality = auth_client.get("/api/v1/assets", params={"criticality": 5})
    assert by_criticality.json()["meta"]["total"] == 1

    by_q = auth_client.get("/api/v1/assets", params={"q": "db-01"})
    assert by_q.json()["meta"]["total"] == 1

    by_env = auth_client.get("/api/v1/assets", params={"environment": "staging"})
    assert by_env.json()["meta"]["total"] == 0

    paged = auth_client.get("/api/v1/assets", params={"page": 1, "page_size": 1, "sort": "name", "order": "asc"})
    body = paged.json()
    assert body["meta"]["total"] == 3
    assert body["meta"]["page_size"] == 1
    assert body["meta"]["has_next"] is True
    assert len(body["items"]) == 1

    invalid_sort = auth_client.get("/api/v1/assets", params={"sort": "evil;drop table assets"})
    assert invalid_sort.status_code == 422


def test_asset_validation_errors(auth_client: TestClient) -> None:
    bad_criticality = auth_client.post("/api/v1/assets", json=_asset("a1", criticality=9))
    assert bad_criticality.status_code == 422

    bad_kind = auth_client.post("/api/v1/assets", json=_asset("a2", kind="alien"))
    assert bad_kind.status_code == 422

    extra_field = auth_client.post(
        "/api/v1/assets", json={**_asset("a3"), "org_id": "00000000-0000-0000-0000-000000000000"}
    )
    assert extra_field.status_code == 422

    bad_ip = auth_client.post("/api/v1/assets", json=_asset("a4", ip_addresses=["999.1.1.1"]))
    assert bad_ip.status_code == 422

    bad_key = auth_client.post("/api/v1/assets", json=_asset(" bad key "))
    assert bad_key.status_code == 422

    duplicate = auth_client.post("/api/v1/assets", json=_asset("dup-1"))
    assert duplicate.status_code == 201
    assert auth_client.post("/api/v1/assets", json=_asset("dup-1")).status_code == 409


def test_asset_cross_tenant_isolation(seeded, auth_client: TestClient) -> None:
    created = auth_client.post("/api/v1/assets", json=_asset("tenant-secret"))
    assert created.status_code == 201
    asset_id = created.json()["id"]

    _make_foreign_tenant(auth_client, "foreign-assets", "foreign.assets@example.eu")
    other = _login_other("foreign.assets@example.eu")
    try:
        assert other.get(f"/api/v1/assets/{asset_id}").status_code == 404
        assert other.get("/api/v1/assets").json()["meta"]["total"] == 0
        assert other.patch(f"/api/v1/assets/{asset_id}", json={"criticality": 1}).status_code == 404
        assert other.delete(f"/api/v1/assets/{asset_id}").status_code == 404
        assert (
            other.post(f"/api/v1/assets/{asset_id}/identities", json={"kind": "ip", "value": "10.9.9.9"}).status_code
            == 404
        )
    finally:
        other.close()


def test_viewer_cannot_write_assets(seeded, auth_client: TestClient) -> None:
    membership = auth_client.post(
        "/api/v1/organizations/current/members",
        json={
            "email": "viewer.assets@example.eu",
            "full_name": "Viewer Assets",
            "role": "viewer",
            "password": "Str0ng-Viewer-Pass!2026",
        },
    )
    assert membership.status_code == 201, membership.text
    viewer = _login_other("viewer.assets@example.eu")
    try:
        assert viewer.get("/api/v1/assets").status_code == 200
        assert viewer.post("/api/v1/assets", json=_asset("viewer-denied")).status_code == 403
        assert viewer.post("/api/v1/assets/import", json={"items": [_asset("viewer-import")]}).status_code == 403
    finally:
        viewer.close()


def test_asset_import_idempotency_and_row_errors(auth_client: TestClient) -> None:
    rows = [
        _asset("import-1", name="Imported One"),
        _asset("import-2", name="Imported Two", ip_addresses=["10.20.30.40"]),
    ]
    first = auth_client.post("/api/v1/assets/import", json={"items": rows, "source": "cmdb", "confidence": 70})
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["created"] == 2 and body["updated"] == 0 and body["errors"] == []

    second = auth_client.post("/api/v1/assets/import", json={"items": rows, "source": "cmdb", "confidence": 70})
    assert second.json()["created"] == 0
    assert second.json()["updated"] == 0
    assert second.json()["skipped"] == 2

    changed = [_asset("import-1", name="Renamed One"), _asset("import-2", name="Imported Two")]
    third = auth_client.post("/api/v1/assets/import", json={"items": changed})
    assert third.json()["updated"] == 1
    assert third.json()["skipped"] == 1

    mixed = auth_client.post(
        "/api/v1/assets/import",
        json={
            "items": [
                _asset("import-3"),
                _asset("import-3"),
                _asset("import-4", ip_addresses=["not-an-ip"]),
                {**_asset("import-5"), "criticality": 42},
            ]
        },
    )
    assert mixed.status_code == 200
    payload = mixed.json()
    assert payload["created"] == 1
    assert len(payload["errors"]) == 3
    assert payload["errors"][0]["message"] == "Duplicate asset_key in batch"

    oversized = auth_client.post("/api/v1/assets/import", json={"items": [_asset(f"bulk-{i}") for i in range(501)]})
    assert oversized.status_code == 422

    detail = auth_client.get("/api/v1/assets", params={"q": "import-1"}).json()["items"][0]
    assert detail["owner"] is None
    assert detail["discovery_source"] == "cmdb"
    assert detail["confidence"] == 70


def test_identities_lifecycle(auth_client: TestClient) -> None:
    asset = auth_client.post("/api/v1/assets", json=_asset("ident-asset")).json()
    created = auth_client.post(
        f"/api/v1/assets/{asset['id']}/identities",
        json={"kind": "cert_sha256", "value": "ab" * 32, "confidence": 90},
    )
    assert created.status_code == 201, created.text
    identity_id = created.json()["id"]

    duplicate = auth_client.post(
        f"/api/v1/assets/{asset['id']}/identities",
        json={"kind": "cert_sha256", "value": "ab" * 32},
    )
    assert duplicate.status_code == 409

    listed = auth_client.get(f"/api/v1/assets/{asset['id']}/identities")
    assert listed.status_code == 200 and len(listed.json()) == 1

    invalid_kind = auth_client.post(f"/api/v1/assets/{asset['id']}/identities", json={"kind": "passport", "value": "x"})
    assert invalid_kind.status_code == 422

    removed = auth_client.delete(f"/api/v1/assets/{asset['id']}/identities/{identity_id}")
    assert removed.status_code == 204
    assert auth_client.delete(f"/api/v1/assets/{asset['id']}/identities/{identity_id}").status_code == 404


def test_relationships_both_directions_graph_and_validation(seeded, auth_client: TestClient) -> None:
    ids = {}
    for key in ("rel-a", "rel-b", "rel-c"):
        response = auth_client.post("/api/v1/assets", json=_asset(key))
        assert response.status_code == 201
        ids[key] = response.json()["id"]

    ab = auth_client.post(
        f"/api/v1/assets/{ids['rel-a']}/relationships",
        json={"target_asset_id": ids["rel-b"], "kind": "connects_to", "confidence": 80},
    )
    assert ab.status_code == 201, ab.text
    relationship_id = ab.json()["id"]
    assert ab.json()["direction"] == "outbound"

    bc = auth_client.post(
        f"/api/v1/assets/{ids['rel-b']}/relationships",
        json={"target_asset_id": ids["rel-c"], "kind": "hosts"},
    )
    assert bc.status_code == 201

    duplicate = auth_client.post(
        f"/api/v1/assets/{ids['rel-a']}/relationships",
        json={"target_asset_id": ids["rel-b"], "kind": "connects_to"},
    )
    assert duplicate.status_code == 409

    self_relation = auth_client.post(
        f"/api/v1/assets/{ids['rel-a']}/relationships",
        json={"target_asset_id": ids["rel-a"], "kind": "connects_to"},
    )
    assert self_relation.status_code == 422

    from_a = auth_client.get(f"/api/v1/assets/{ids['rel-a']}/relationships").json()
    assert len(from_a) == 1 and from_a[0]["direction"] == "outbound"

    from_b = auth_client.get(f"/api/v1/assets/{ids['rel-b']}/relationships").json()
    assert {item["direction"] for item in from_b} == {"inbound", "outbound"}

    graph_1 = auth_client.get(f"/api/v1/assets/{ids['rel-a']}/graph", params={"depth": 1}).json()
    assert len(graph_1["nodes"]) == 2 and len(graph_1["edges"]) == 1

    graph_2 = auth_client.get(f"/api/v1/assets/{ids['rel-a']}/graph", params={"depth": 2}).json()
    assert len(graph_2["nodes"]) == 3 and len(graph_2["edges"]) == 2

    assert auth_client.get(f"/api/v1/assets/{ids['rel-a']}/graph", params={"depth": 4}).status_code == 422

    _make_foreign_tenant(auth_client, "foreign-graph", "foreign.graph@example.eu")
    other = _login_other("foreign.graph@example.eu")
    try:
        assert other.get(f"/api/v1/assets/{ids['rel-a']}/graph").status_code == 404
        assert other.delete(f"/api/v1/assets/relationships/{relationship_id}").status_code == 404
    finally:
        other.close()

    assert auth_client.delete(f"/api/v1/assets/relationships/{relationship_id}").status_code == 204


def test_zones_crud_reassign_and_cycle_guard(auth_client: TestClient) -> None:
    zone = auth_client.post("/api/v1/zones", json={"name": "Cell 1", "kind": "zone", "purdue_level": 2})
    assert zone.status_code == 201, zone.text
    zone_id = zone.json()["id"]

    conduit = auth_client.post(
        "/api/v1/zones", json={"name": "Conduit 1", "kind": "conduit", "purdue_level": 3, "parent_id": zone_id}
    )
    assert conduit.status_code == 201
    conduit_id = conduit.json()["id"]

    duplicate = auth_client.post("/api/v1/zones", json={"name": "Cell 1", "kind": "zone"})
    assert duplicate.status_code == 409

    invalid_purdue = auth_client.post("/api/v1/zones", json={"name": "Bad", "purdue_level": 9})
    assert invalid_purdue.status_code == 422

    cycle = auth_client.patch(f"/api/v1/zones/{zone_id}", json={"parent_id": conduit_id})
    assert cycle.status_code == 422

    conduits = auth_client.get("/api/v1/zones", params={"kind": "conduit"})
    assert conduits.json()["meta"]["total"] == 1

    asset = auth_client.post("/api/v1/assets", json=_asset("zoned-asset", zone_id=zone_id))
    assert asset.status_code == 201
    zone_assets = auth_client.get(f"/api/v1/zones/{zone_id}/assets")
    assert zone_assets.json()["meta"]["total"] == 1

    blocked = auth_client.delete(f"/api/v1/zones/{zone_id}")
    assert blocked.status_code == 409

    target = auth_client.post("/api/v1/zones", json={"name": "Cell 2", "purdue_level": 1})
    target_id = target.json()["id"]
    reassigned = auth_client.delete(f"/api/v1/zones/{zone_id}", params={"reassign_to": target_id})
    assert reassigned.status_code == 204, reassigned.text

    moved = auth_client.get(f"/api/v1/assets/{asset.json()['id']}").json()
    assert moved["zone_id"] == target_id

    assert auth_client.delete(f"/api/v1/zones/{conduit_id}", params={"reassign_to": target_id}).status_code == 204
    assert auth_client.delete(f"/api/v1/zones/{target_id}").status_code == 409


def test_ot_asset_delete_requires_confirmation(auth_client: TestClient) -> None:
    created = auth_client.post("/api/v1/assets", json=_asset("ot-plc-1", kind="ot", criticality=5))
    assert created.status_code == 201
    asset_id = created.json()["id"]

    denied = auth_client.delete(f"/api/v1/assets/{asset_id}")
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "policy_denied"

    confirmed = auth_client.delete(f"/api/v1/assets/{asset_id}", params={"confirm": "true"})
    assert confirmed.status_code == 204
    assert auth_client.get(f"/api/v1/assets/{asset_id}").status_code == 404


def test_asset_vulnerabilities_endpoint_and_summary(seeded, auth_client: TestClient) -> None:
    asset = auth_client.post("/api/v1/assets", json=_asset("vuln-asset", criticality=4)).json()
    vulnerability = auth_client.post(
        "/api/v1/vulnerabilities",
        json={
            "asset_id": asset["id"],
            "title": "OpenSSL RCE",
            "cve_id": "CVE-2024-12345",
            "cvss_score": 9.8,
            "kev": True,
            "exposure": "public",
        },
    )
    assert vulnerability.status_code == 201, vulnerability.text

    listed = auth_client.get(f"/api/v1/assets/{asset['id']}/vulnerabilities")
    assert listed.status_code == 200
    assert listed.json()["meta"]["total"] == 1
    assert listed.json()["items"][0]["cve_id"] == "CVE-2024-12345"

    filtered = auth_client.get(f"/api/v1/assets/{asset['id']}/vulnerabilities", params={"status": "mitigated"})
    assert filtered.json()["meta"]["total"] == 0

    detail = auth_client.get(f"/api/v1/assets/{asset['id']}").json()
    assert detail["vulnerability_summary"]["open"] == 1
    assert detail["vulnerability_summary"]["kev"] == 1


def test_asset_detail_includes_iot_profile(auth_client: TestClient) -> None:
    created = auth_client.post(
        "/api/v1/iot/devices",
        json=_asset("iot-detail", kind="iot", protocols=["mqtt"], connectivity="wifi"),
    )
    assert created.status_code == 201, created.text
    asset_id = created.json()["asset_id"]

    detail = auth_client.get(f"/api/v1/assets/{asset_id}")
    assert detail.status_code == 200
    body = detail.json()
    assert body["iot"] is not None
    assert body["iot"]["protocols"] == ["MQTT"]
    assert body["iot"]["connectivity"] == "wifi"


def test_asset_vulnerability_model_tenant_scope(seeded, auth_client: TestClient, db) -> None:
    asset = auth_client.post("/api/v1/assets", json=_asset("t-scope")).json()
    assert db.execute(select(Vulnerability).where(Vulnerability.org_id == seeded["org"].id)).all() == []
    detail = auth_client.get(f"/api/v1/assets/{asset['id']}").json()
    assert detail["vulnerability_summary"]["total"] == 0
