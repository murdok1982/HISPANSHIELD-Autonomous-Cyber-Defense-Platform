"""Idempotency-Key contract on mutating endpoints."""

from __future__ import annotations

from app.core.idempotency import fingerprint, validate_key


def test_incident_creation_replays_same_response(auth_client) -> None:
    payload = {"title": "Idempotent incident", "severity": "high", "description": "created once"}
    headers = {"Idempotency-Key": "incident-key-0001"}
    first = auth_client.post("/api/v1/incidents", json=payload, headers=headers)
    assert first.status_code == 201, first.text
    second = auth_client.post("/api/v1/incidents", json=payload, headers=headers)
    assert second.status_code == 201, second.text
    assert first.json()["id"] == second.json()["id"]
    assert second.headers.get("Idempotent-Replayed") == "true"

    listing = auth_client.get("/api/v1/incidents", params={"q": "Idempotent incident"})
    assert listing.status_code == 200
    assert listing.json()["meta"]["total"] == 1


def test_same_key_different_payload_is_rejected(auth_client) -> None:
    headers = {"Idempotency-Key": "incident-key-0002"}
    first = auth_client.post("/api/v1/incidents", json={"title": "First payload", "severity": "low"}, headers=headers)
    assert first.status_code == 201
    second = auth_client.post("/api/v1/incidents", json={"title": "Second payload", "severity": "low"}, headers=headers)
    assert second.status_code == 409
    assert "different request" in second.json()["error"]["message"]


def test_invalid_idempotency_key_is_rejected(auth_client) -> None:
    response = auth_client.post(
        "/api/v1/incidents",
        json={"title": "Bad key", "severity": "low"},
        headers={"Idempotency-Key": "short"},
    )
    assert response.status_code == 422
    assert response.json()["error"]["details"][0]["field"] == "Idempotency-Key"


def test_asset_import_replays_original_counts(auth_client) -> None:
    payload = {
        "source": "unit-test",
        "items": [
            {"asset_key": "idem-a", "name": "Idem A", "kind": "host"},
            {"asset_key": "idem-b", "name": "Idem B", "kind": "host"},
        ],
    }
    headers = {"Idempotency-Key": "asset-import-0001"}
    first = auth_client.post("/api/v1/assets/import", json=payload, headers=headers)
    assert first.status_code == 200, first.text
    assert first.json()["created"] == 2
    second = auth_client.post("/api/v1/assets/import", json=payload, headers=headers)
    assert second.status_code == 200
    assert second.json()["created"] == 2  # replayed, not "0 updated"
    assert second.headers.get("Idempotent-Replayed") == "true"
    listing = auth_client.get("/api/v1/assets", params={"q": "idem-"})
    assert listing.json()["meta"]["total"] == 2


def test_keys_are_scoped_per_actor_and_tenant(auth_client) -> None:
    # A different path with the same key is a conflict, never a leaked replay.
    headers = {"Idempotency-Key": "scope-key-0001"}
    first = auth_client.post("/api/v1/incidents", json={"title": "Scope one", "severity": "low"}, headers=headers)
    assert first.status_code == 201
    second = auth_client.post(
        "/api/v1/assets/import",
        json={"source": "x", "items": [{"asset_key": "scope", "name": "Scope", "kind": "host"}]},
        headers=headers,
    )
    assert second.status_code == 409


def test_fingerprint_is_canonical_and_key_validation() -> None:
    assert fingerprint({"b": 2, "a": 1}) == fingerprint({"a": 1, "b": 2})
    assert fingerprint({"a": 1}) != fingerprint({"a": 2})
    assert validate_key("valid-key-123") == "valid-key-123"
    assert validate_key(None) is None
    for bad in ("short", "bad key with spaces", "x" * 129):
        try:
            validate_key(bad)
        except Exception:
            continue
        raise AssertionError(f"key {bad!r} should be rejected")
