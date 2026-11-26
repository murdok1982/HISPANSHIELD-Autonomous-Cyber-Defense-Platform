"""Keyset pagination contract (additive to offset pagination)."""

from __future__ import annotations

import uuid

from app.core.db import utcnow
from app.core.schemas import decode_cursor, encode_cursor
from app.models.events import SecurityEvent


def _asset(key: str, name: str) -> dict:
    return {
        "asset_key": key,
        "name": name,
        "kind": "host",
        "criticality": 3,
        "environment": "production",
    }


def test_assets_cursor_pages_without_duplicates(auth_client) -> None:
    for index in range(5):
        response = auth_client.post(
            "/api/v1/assets",
            json=_asset(f"cursor-{index}", f"Cursor {index}"),
        )
        assert response.status_code == 201, response.text

    seen: list[str] = []
    cursor = None
    for _ in range(4):
        params = {"page_size": 2, "sort": "name", "order": "asc"}
        if cursor:
            params["cursor"] = cursor
        page = auth_client.get("/api/v1/assets", params=params)
        assert page.status_code == 200, page.text
        body = page.json()
        seen.extend(item["id"] for item in body["items"])
        cursor = body["meta"]["next_cursor"]
        if not cursor:
            break
    assert len(seen) == 5
    assert len(set(seen)) == 5


def test_assets_cursor_is_bound_to_sort_and_order(auth_client) -> None:
    for index in range(3):
        auth_client.post("/api/v1/assets", json=_asset(f"bound-{index}", f"Bound {index}"))
    first = auth_client.get("/api/v1/assets", params={"page_size": 2, "sort": "name", "order": "asc"}).json()
    cursor = first["meta"]["next_cursor"]
    assert cursor
    mismatch = auth_client.get(
        "/api/v1/assets", params={"page_size": 2, "sort": "name", "order": "desc", "cursor": cursor}
    )
    assert mismatch.status_code == 422
    assert mismatch.json()["error"]["details"][0]["field"] == "cursor"


def test_invalid_cursor_is_rejected(auth_client) -> None:
    response = auth_client.get("/api/v1/assets", params={"cursor": "not-a-real-cursor"})
    assert response.status_code == 422
    assert response.json()["error"]["details"][0]["field"] == "cursor"


def test_events_cursor_resumes_after_last_id(auth_client, seeded, db) -> None:
    org = seeded["org"]
    events = []
    for index in range(4):
        events.append(
            SecurityEvent(
                org_id=org.id,
                event_uid=str(uuid.uuid4()),
                occurred_at=utcnow(),
                class_uid=6003,
                class_name="Network Activity",
                category_uid=4,
                severity_id=3,
                message=f"event-{index}",
                raw={},
                normalized={},
                raw_format="json",
                schema_version="1.1.0",
                ioc_matches=[],
                mitre_techniques=[],
                is_demo=False,
            )
        )
    db.add_all(events)
    db.commit()

    first = auth_client.get("/api/v1/events", params={"page_size": 2}).json()
    assert len(first["items"]) == 2
    cursor = first["meta"]["next_cursor"]
    assert cursor
    second = auth_client.get("/api/v1/events", params={"page_size": 2, "cursor": cursor}).json()
    ids = {item["id"] for item in first["items"]} | {item["id"] for item in second["items"]}
    assert len(ids) == 4

    wrong_scope = auth_client.get("/api/v1/events", params={"page_size": 2, "sort": "severity_id", "cursor": cursor})
    assert wrong_scope.status_code == 422


def test_cursor_round_trip_and_bounds() -> None:
    cursor = encode_cursor({"kind": "events", "id": 42})
    assert decode_cursor(cursor)["id"] == 42
    assert len(cursor) < 700
    try:
        decode_cursor("!!!!")
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("invalid base64 must be rejected")
    try:
        encode_cursor({"blob": "x" * 600})
    except ValueError:
        pass
    else:  # pragma: no cover
        raise AssertionError("oversized cursor must be rejected")
