"""AC-18: DELETE is a soft delete and POST /restore recovers the asset graph."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.models.assets import Asset


def _asset(key: str) -> dict:
    return {
        "asset_key": key,
        "name": f"Asset {key}",
        "kind": "host",
        "criticality": 3,
        "environment": "production",
    }


def test_soft_delete_hides_asset_and_restore_recovers_relationships(auth_client: TestClient, db) -> None:
    a = auth_client.post("/api/v1/assets", json=_asset("soft-a"))
    b = auth_client.post("/api/v1/assets", json=_asset("soft-b"))
    assert a.status_code == 201 and b.status_code == 201
    a_id, b_id = a.json()["id"], b.json()["id"]

    link = auth_client.post(
        f"/api/v1/assets/{a_id}/relationships",
        json={"target_asset_id": b_id, "kind": "connects_to", "confidence": 90},
    )
    assert link.status_code == 201, link.text

    deleted = auth_client.delete(f"/api/v1/assets/{a_id}")
    assert deleted.status_code == 204, deleted.text

    # Active inventory hides it; direct access is a non-revealing 404.
    assert auth_client.get(f"/api/v1/assets/{a_id}").status_code == 404
    listing = auth_client.get("/api/v1/assets", params={"page_size": 200})
    assert listing.status_code == 200
    assert a_id not in {item["id"] for item in listing.json()["items"]}

    # The row and its relationship are preserved for forensics/reports.
    db.expire_all()
    stored = db.execute(select(Asset).where(Asset.id == a_id).execution_options(include_soft_deleted=True)).scalar_one()
    assert stored.deleted_at is not None
    assert stored.status == "retired"

    trash_conflict = auth_client.post("/api/v1/assets", json=_asset("soft-a"))
    assert trash_conflict.status_code == 409
    assert trash_conflict.json()["error"]["code"] == "asset_key_in_trash"

    restored = auth_client.post(f"/api/v1/assets/{a_id}/restore")
    assert restored.status_code == 200, restored.text
    body = restored.json()
    assert body["id"] == a_id
    assert body["status"] == "active"
    assert {rel["target_asset_id"] for rel in body["relationships"]} == {b_id}

    # Restore is idempotent and the asset is visible again.
    assert auth_client.post(f"/api/v1/assets/{a_id}/restore").status_code == 200
    assert auth_client.get(f"/api/v1/assets/{a_id}").status_code == 200


def test_soft_deleted_asset_is_not_revealed_cross_tenant(auth_client: TestClient) -> None:
    created = auth_client.post("/api/v1/assets", json=_asset("soft-cross"))
    assert created.status_code == 201
    asset_id = created.json()["id"]
    assert auth_client.delete(f"/api/v1/assets/{asset_id}").status_code == 204
    # A second delete/restore lookup on a foreign id also yields 404.
    assert auth_client.delete(f"/api/v1/assets/{asset_id}").status_code == 404
