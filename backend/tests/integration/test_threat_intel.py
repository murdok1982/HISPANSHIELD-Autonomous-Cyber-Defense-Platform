"""Integration tests: threat intelligence indicators, actors, feeds, enrichment, ATT&CK."""

from __future__ import annotations

import http.server
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.db import utcnow
from app.models.events import SecurityEvent
from tests.conftest import login

BASE = "/api/v1/threat-intel"


def _create_indicator(client: TestClient, **overrides) -> dict:
    payload = {
        "indicator_type": "ip",
        "value": "203.0.113.10",
        "confidence": 80,
        "severity": "high",
        "source": "unit-test",
        "tags": ["c2"],
        "description": "Known command-and-control node",
    }
    payload.update(overrides)
    response = client.post(f"{BASE}/indicators", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


@contextmanager
def _http_server(handler_fn) -> Iterator[int]:  # type: ignore[no-untyped-def]
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            status, content_type, body = handler_fn(urlparse(self.path))
            payload = body.encode() if isinstance(body, str) else body
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args) -> None:  # type: ignore[no-untyped-def]
            return

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_indicator_crud_filters_and_global_visibility(seeded, auth_client: TestClient) -> None:
    tenant = _create_indicator(auth_client)
    global_indicator = _create_indicator(
        auth_client,
        indicator_type="domain",
        value="evil.example",
        confidence=95,
        severity="critical",
        global_indicator=True,
    )
    assert global_indicator["org_id"] is None
    assert tenant["org_id"] == str(seeded["org"].id)

    listed = auth_client.get(f"{BASE}/indicators")
    assert listed.status_code == 200, listed.text
    body = listed.json()
    assert body["meta"]["total"] == 2
    values = {item["value"] for item in body["items"]}
    assert values == {"203.0.113.10", "evil.example"}

    filtered = auth_client.get(f"{BASE}/indicators", params={"type": "ip", "severity": "high", "active": True})
    assert filtered.status_code == 200
    assert [item["value"] for item in filtered.json()["items"]] == ["203.0.113.10"]

    by_query = auth_client.get(f"{BASE}/indicators", params={"q": "203.0.113.10"})
    assert by_query.status_code == 200
    assert by_query.json()["meta"]["total"] == 1

    duplicated = auth_client.post(
        f"{BASE}/indicators",
        json={"indicator_type": "ip", "value": "203.0.113.10"},
    )
    assert duplicated.status_code == 409

    invalid = auth_client.post(f"{BASE}/indicators", json={"indicator_type": "ip", "value": "999.1.1.1"})
    assert invalid.status_code == 422

    patched = auth_client.patch(
        f"{BASE}/indicators/{tenant['id']}",
        json={"confidence": 42, "severity": "low", "tags": ["c2", "botnet"]},
    )
    assert patched.status_code == 200
    assert patched.json()["confidence"] == 42
    assert patched.json()["tags"] == ["c2", "botnet"]

    deactivated = auth_client.post(f"{BASE}/indicators/{tenant['id']}/deactivate")
    assert deactivated.status_code == 200
    assert deactivated.json()["active"] is False

    deleted = auth_client.delete(f"{BASE}/indicators/{tenant['id']}")
    assert deleted.status_code == 204
    assert auth_client.get(f"{BASE}/indicators/{tenant['id']}").status_code == 404


def test_stix_import_is_idempotent_and_rejects_malformed(seeded, auth_client: TestClient) -> None:
    bundle = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "pattern": "[ipv4-addr:value = '198.51.100.50']",
                "confidence": 88,
                "labels": ["malicious-activity"],
            },
            {
                "type": "indicator",
                "pattern": "[file:hashes.'SHA-256' = '" + ("a" * 64) + "']",
                "confidence": 40,
            },
            {"type": "malware", "name": "ignored"},
        ],
    }
    first = auth_client.post(f"{BASE}/indicators/import", json={"bundle": bundle})
    assert first.status_code == 200, first.text
    assert first.json()["created"] == 2
    assert first.json()["skipped"] == 0

    second = auth_client.post(f"{BASE}/indicators/import", json={"bundle": bundle})
    assert second.status_code == 200
    assert second.json()["created"] == 0
    assert second.json()["updated"] == 2

    malformed = auth_client.post(
        f"{BASE}/indicators/import",
        json={"bundle": {"type": "bundle", "objects": [{"type": "indicator", "pattern": "not a pattern"}]}},
    )
    assert malformed.status_code == 422

    wrong_type = auth_client.post(f"{BASE}/indicators/import", json={"bundle": {"type": "report", "objects": []}})
    assert wrong_type.status_code == 422


def test_csv_import_reports_row_errors_and_is_idempotent(seeded, auth_client: TestClient) -> None:
    csv_payload = (
        "type,value,confidence,severity,source,tags\n"
        "ip,198.51.100.77,88,high,csv,c2|botnet\n"
        "domain,bad.example,50,medium,csv,phishing\n"
        "domain,not a domain,50,medium,csv,invalid\n"
    )
    response = auth_client.post(
        f"{BASE}/indicators/import/csv",
        content=csv_payload.encode(),
        headers={"Content-Type": "text/csv"},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["created"] == 2
    assert body["skipped"] == 1
    assert body["errors"][0]["row"] == 4

    repeat = auth_client.post(
        f"{BASE}/indicators/import/csv",
        json={"csv": csv_payload, "source": "csv-json"},
    )
    assert repeat.status_code == 200
    assert repeat.json()["created"] == 0
    assert repeat.json()["updated"] == 2

    missing_header = auth_client.post(
        f"{BASE}/indicators/import/csv",
        content=b"value,confidence\n1.2.3.4,50\n",
        headers={"Content-Type": "text/csv"},
    )
    assert missing_header.status_code == 422


def test_actors_crud_and_enrichment(seeded, auth_client: TestClient, db) -> None:
    actor = auth_client.post(
        f"{BASE}/actors",
        json={
            "name": "Test Bear",
            "aliases": ["Unit Bear"],
            "mitre_id": "G0007",
            "techniques": ["T1078", "T1110"],
            "motivation": "espionage",
        },
    )
    assert actor.status_code == 201, actor.text
    actor_id = actor.json()["id"]

    indicator = _create_indicator(auth_client, actor_id=actor_id, value="198.51.100.200")
    detail = auth_client.get(f"{BASE}/actors/{actor_id}")
    assert detail.status_code == 200
    assert detail.json()["indicator_count"] == 1

    invalid = auth_client.patch(f"{BASE}/actors/{actor_id}", json={"techniques": ["not-a-technique"]})
    assert invalid.status_code == 422

    enriched = auth_client.get(f"{BASE}/enrich", params={"value": "198.51.100.200", "type": "ip"})
    assert enriched.status_code == 200, enriched.text
    payload = enriched.json()
    assert payload["verdict"] == "malicious"
    assert payload["confidence"] == 80
    assert payload["actor"]["id"] == actor_id
    assert "T1078" in {item["id"] for item in payload["techniques"]}
    assert payload["matched"] is True
    assert payload["evidence"][0]["indicator_id"] == indicator["id"]

    unknown = auth_client.get(f"{BASE}/enrich", params={"value": "192.0.2.250", "type": "ip"})
    assert unknown.status_code == 200
    assert unknown.json()["verdict"] == "unknown"
    assert unknown.json()["matches"] == []
    assert unknown.json()["matched"] is False

    bad_value = auth_client.get(f"{BASE}/enrich", params={"value": "not an indicator"})
    assert bad_value.status_code == 422

    deleted = auth_client.delete(f"{BASE}/actors/{actor_id}")
    assert deleted.status_code == 204
    assert auth_client.get(f"{BASE}/actors/{actor_id}").status_code == 404


def test_enrichment_includes_operational_events(seeded, auth_client: TestClient, db) -> None:
    _create_indicator(auth_client, value="203.0.113.66", confidence=90, severity="critical")
    db.add(
        SecurityEvent(
            org_id=seeded["org"].id,
            event_uid="evt-enrich-1",
            occurred_at=utcnow(),
            class_uid=4001,
            class_name="Network Activity",
            category_uid=4,
            severity_id=4,
            message="Outbound connection to known C2",
            src_ip="10.0.0.5",
            dst_ip="203.0.113.66",
        )
    )
    db.commit()

    enriched = auth_client.get(f"{BASE}/enrich", params={"value": "203.0.113.66", "type": "ip"})
    assert enriched.status_code == 200
    events = enriched.json()["events"]
    assert len(events) == 1
    assert events[0]["event_uid"] == "evt-enrich-1"


def test_mitre_catalogue_coverage_and_summary(seeded, auth_client: TestClient, db) -> None:
    techniques = auth_client.get(f"{BASE}/mitre/techniques", params={"tactic": "lateral-movement"})
    assert techniques.status_code == 200
    body = techniques.json()
    assert body["count"] >= 1
    assert all("lateral-movement" in item["tactics"] for item in body["items"])
    assert "T1021" in {item["id"] for item in body["items"]}

    search = auth_client.get(f"{BASE}/mitre/techniques", params={"q": "phishing"})
    assert search.status_code == 200
    assert "T1566" in {item["id"] for item in search.json()["items"]}

    db.add(
        SecurityEvent(
            org_id=seeded["org"].id,
            event_uid="evt-mitre-1",
            occurred_at=utcnow(),
            class_uid=3002,
            class_name="Authentication",
            category_uid=3,
            severity_id=4,
            message="Valid account abuse",
            mitre_techniques=["T1078"],
        )
    )
    _create_indicator(auth_client, tags=["T1110"], value="198.51.100.31")
    db.commit()

    coverage = auth_client.get(f"{BASE}/mitre/coverage")
    assert coverage.status_code == 200
    covered = {item["id"]: item for item in coverage.json()["techniques"]}
    assert covered["T1078"]["event_count"] == 1
    assert covered["T1110"]["indicator_count"] == 1
    assert coverage.json()["coverage_percent"] > 0

    summary = auth_client.get(f"{BASE}/summary")
    assert summary.status_code == 200
    payload = summary.json()
    assert payload["indicators"]["total"] == 1
    assert payload["mitre"]["covered_count"] == 2


def test_feed_crud_redacts_secrets_and_rejects_unknown_config(seeded, auth_client: TestClient) -> None:
    created = auth_client.post(
        f"{BASE}/feeds",
        json={
            "name": "Unit CSV feed",
            "kind": "csv",
            "enabled": False,
            "schedule_minutes": 30,
            "config": {"url": "https://feeds.example.com/iocs.csv", "api_key": "super-secret-value"},
        },
    )
    assert created.status_code == 201, created.text
    feed = created.json()
    assert feed["config"]["api_key"] == "[redacted]"

    invalid_key = auth_client.post(
        f"{BASE}/feeds",
        json={"name": "Bad feed", "kind": "csv", "config": {"url": "https://x.example", "policy": "allow-all"}},
    )
    assert invalid_key.status_code == 422

    patched = auth_client.patch(f"{BASE}/feeds/{feed['id']}", json={"name": "Unit CSV feed v2"})
    assert patched.status_code == 200
    assert patched.json()["name"] == "Unit CSV feed v2"

    disabled_sync = auth_client.post(f"{BASE}/feeds/{feed['id']}/sync")
    assert disabled_sync.status_code == 409

    listed = auth_client.get(f"{BASE}/feeds")
    assert listed.status_code == 200
    assert listed.json()["meta"]["total"] == 1

    deleted = auth_client.delete(f"{BASE}/feeds/{feed['id']}")
    assert deleted.status_code == 204


def test_stix_feed_sync_creates_indicators(seeded, auth_client: TestClient, monkeypatch) -> None:
    bundle = {
        "type": "bundle",
        "objects": [
            {"type": "indicator", "pattern": "[ipv4-addr:value = '198.51.100.90']", "confidence": 70},
            {"type": "indicator", "pattern": "[domain-name:value = 'feed.example']", "confidence": 30},
        ],
    }

    def handler(_parsed) -> tuple[int, str, bytes]:  # type: ignore[no-untyped-def]
        return 200, "application/json", json.dumps(bundle).encode()

    monkeypatch.setattr(settings, "connector_allow_private_networks", True)
    with _http_server(handler) as port:
        feed = auth_client.post(
            f"{BASE}/feeds",
            json={
                "name": "Local STIX",
                "kind": "stix",
                "schedule_minutes": 30,
                "config": {"url": f"http://127.0.0.1:{port}/bundle.json"},
            },
        )
        assert feed.status_code == 201, feed.text
        synced = auth_client.post(f"{BASE}/feeds/{feed.json()['id']}/sync")
        assert synced.status_code == 200, synced.text
        body = synced.json()
        assert body["status"] == "success"
        assert body["created"] == 2
        assert body["objects_read"] == 2

        second = auth_client.post(f"{BASE}/feeds/{feed.json()['id']}/sync")
        assert second.status_code == 200
        assert second.json()["created"] == 0
        assert second.json()["updated"] == 2

    listed = auth_client.get(f"{BASE}/indicators", params={"source": "stix-feed"})
    assert listed.json()["meta"]["total"] == 2


def test_taxii_feed_pagination(seeded, auth_client: TestClient, monkeypatch) -> None:
    objects = {
        "type": "bundle",
        "objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '198.51.100.120']", "confidence": 60}],
    }

    def handler(parsed) -> tuple[int, str, bytes]:  # type: ignore[no-untyped-def]
        query = parse_qs(parsed.query)
        if parsed.path.endswith("/collections/"):
            return 200, "application/taxii+json;version=2.1", json.dumps({"collections": [{"id": "col-1"}]})
        if parsed.path.endswith("/collections/col-1/objects/"):
            if "next" in query:
                return 200, "application/taxii+json;version=2.1", json.dumps(objects)
            page_one = {
                "type": "bundle",
                "objects": [
                    {"type": "indicator", "pattern": "[domain-name:value = 'taxii.example']", "confidence": 60}
                ],
            }
            return (
                200,
                "application/taxii+json;version=2.1",
                json.dumps({**page_one, "next": "page-2", "more": True}),
            )
        return 404, "application/json", b'{"error": "not found"}'

    monkeypatch.setattr(settings, "connector_allow_private_networks", True)
    with _http_server(handler) as port:
        feed = auth_client.post(
            f"{BASE}/feeds",
            json={
                "name": "Local TAXII",
                "kind": "taxii",
                "schedule_minutes": 30,
                "config": {"url": f"http://127.0.0.1:{port}/taxii2", "collection_id": "col-1"},
            },
        )
        assert feed.status_code == 201, feed.text
        synced = auth_client.post(f"{BASE}/feeds/{feed.json()['id']}/sync")
        assert synced.status_code == 200, synced.text
        assert synced.json()["created"] == 2
        assert synced.json()["objects_read"] == 2

    values = {item["value"] for item in auth_client.get(f"{BASE}/indicators").json()["items"]}
    assert {"taxii.example", "198.51.100.120"} <= values


def test_feed_sync_failure_records_error_state(seeded, auth_client: TestClient, monkeypatch) -> None:
    def handler(_parsed) -> tuple[int, str, bytes]:  # type: ignore[no-untyped-def]
        return 500, "application/json", b'{"error": "boom"}'

    monkeypatch.setattr(settings, "connector_allow_private_networks", True)
    with _http_server(handler) as port:
        feed = auth_client.post(
            f"{BASE}/feeds",
            json={
                "name": "Broken STIX",
                "kind": "stix",
                "config": {"url": f"http://127.0.0.1:{port}/bundle.json"},
            },
        )
        assert feed.status_code == 201
        failed = auth_client.post(f"{BASE}/feeds/{feed.json()['id']}/sync")
        assert failed.status_code == 503

    stored = auth_client.get(f"{BASE}/feeds/{feed.json()['id']}")
    assert stored.status_code == 200
    assert stored.json()["status"] == "error"
    assert stored.json()["last_error"]


def test_tenant_isolation_returns_404(seeded, auth_client: TestClient) -> None:
    created_indicator = _create_indicator(auth_client)
    other = auth_client.post(
        "/api/v1/organizations",
        json={"name": "Other Org", "slug": "other-org"},
    )
    assert other.status_code == 201, other.text
    other_id = other.json()["id"]

    auth_client.headers["X-Organization-Id"] = other_id
    foreign = _create_indicator(auth_client, value="192.0.2.44")
    foreign_actor = auth_client.post(f"{BASE}/actors", json={"name": "Foreign Actor"})
    assert foreign_actor.status_code == 201

    auth_client.headers.pop("X-Organization-Id", None)
    assert auth_client.get(f"{BASE}/indicators/{foreign['id']}").status_code == 404
    assert auth_client.get(f"{BASE}/actors/{foreign_actor.json()['id']}").status_code == 404
    assert auth_client.get(f"{BASE}/indicators/{created_indicator['id']}").status_code == 200


def test_rbac_viewer_cannot_write(seeded, auth_client: TestClient) -> None:
    member = auth_client.post(
        "/api/v1/organizations/current/members",
        json={
            "email": "viewer.ti@hispanshield.eu",
            "full_name": "Viewer TI",
            "role": "viewer",
            "password": "Viewer-Str0ng-Pass!9",
        },
    )
    assert member.status_code == 201, member.text
    login(auth_client, email="viewer.ti@hispanshield.eu", password="Viewer-Str0ng-Pass!9")

    assert auth_client.get(f"{BASE}/indicators").status_code == 200
    denied = auth_client.post(f"{BASE}/indicators", json={"indicator_type": "ip", "value": "198.51.100.9"})
    assert denied.status_code == 403
    assert auth_client.get(f"{BASE}/mitre/techniques").status_code == 200


@pytest.mark.parametrize(
    ("indicator_type", "value"),
    [
        ("domain", "Valid.Example"),
        ("url", "https://valid.example/path"),
        ("sha256", "b" * 64),
        ("email", "Analyst@Example.EU"),
    ],
)
def test_indicator_type_normalization(seeded, auth_client: TestClient, indicator_type: str, value: str) -> None:
    created = _create_indicator(auth_client, indicator_type=indicator_type, value=value)
    assert created["indicator_type"] == indicator_type
    expected = value if indicator_type == "url" else value.lower()
    assert created["value"] == expected


def test_expired_indicator_is_inactive_on_creation(seeded, auth_client: TestClient) -> None:
    expired = _create_indicator(
        auth_client,
        expires_at="2020-01-01T00:00:00",
    )
    assert expired["active"] is False
    listed = auth_client.get(f"{BASE}/indicators", params={"active": False})
    assert listed.json()["meta"]["total"] == 1
