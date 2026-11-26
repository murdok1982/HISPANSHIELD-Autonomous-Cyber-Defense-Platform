"""Event fabric integration: sources, ingestion, search, stats, retention, RBAC."""

from __future__ import annotations

import json

from sqlalchemy import select

from app.core.crypto import hmac_sha256_hex
from app.models.core import AuditRecord
from app.models.events import IngestSource, SecurityEvent
from app.models.ti import ThreatIndicator


def _create_source(client, **overrides):
    payload = {
        "name": "Integration source",
        "kind": "api",
        "parser": "auto",
        "enabled": True,
    }
    payload.update(overrides)
    response = client.post("/api/v1/ingest-sources", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _ingest(client, token, body: bytes, content_type: str = "application/json", headers=None):
    request_headers = {"Content-Type": content_type}
    if headers:
        request_headers.update(headers)
    return client.post(f"/api/v1/ingest/{token}", content=body, headers=request_headers)


def _create_org(client, slug: str) -> str:
    response = client.post("/api/v1/organizations", json={"name": f"Org {slug}", "slug": slug})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _login_as(client, email: str, password: str):
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    csrf = client.cookies.get("hs_csrf")
    assert csrf
    client.headers.update({"X-CSRF-Token": csrf})
    return client


def _add_member(client, *, email: str, role: str, password: str):
    response = client.post(
        "/api/v1/organizations/current/members",
        json={"email": email, "full_name": "Integration User", "role": role, "password": password},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_create_source_returns_token_once_and_hides_secrets(auth_client, seeded, db):
    created = _create_source(auth_client, name="Token once", generate_hmac_secret=True)
    assert created["token"].startswith("hs_ing_")
    assert created["hmac_secret"].startswith("hs_hmac_")
    assert created["has_token"] is True
    assert created["has_hmac_secret"] is True

    detail = auth_client.get(f"/api/v1/ingest-sources/{created['id']}")
    assert detail.status_code == 200
    body = detail.json()
    for forbidden in ("token", "hmac_secret", "token_hash", "hmac_secret_encrypted"):
        assert forbidden not in body
    assert body["has_token"] is True
    assert body["has_hmac_secret"] is True

    listing = auth_client.get("/api/v1/ingest-sources")
    assert listing.status_code == 200
    assert listing.json()["meta"]["total"] == 1
    listed = listing.json()["items"][0]
    for forbidden in ("token", "hmac_secret", "token_hash", "hmac_secret_encrypted"):
        assert forbidden not in listed

    source = db.get(IngestSource, created["id"])
    assert source is not None
    assert len(source.token_hash) == 64
    assert source.token_hash != created["token"]
    assert source.hmac_secret_encrypted != created["hmac_secret"]


def test_rotate_token_invalidates_previous_token(auth_client):
    created = _create_source(auth_client, name="Rotation")
    old_token = created["token"]
    rotated = auth_client.post(f"/api/v1/ingest-sources/{created['id']}/rotate-token")
    assert rotated.status_code == 200
    new_token = rotated.json()["token"]
    assert new_token != old_token

    body = b'{"message":"after rotation"}'
    assert _ingest(auth_client, old_token, body).status_code == 401
    assert _ingest(auth_client, new_token, body).status_code == 200


def test_hmac_signature_required_and_verified(auth_client):
    secret = "integration-hmac-secret-0123456789"
    created = _create_source(auth_client, name="Signed source", hmac_secret=secret)
    assert created["hmac_secret"] == secret
    token = created["token"]
    body = b'{"message":"signed event","severity":"medium"}'

    assert _ingest(auth_client, token, body).status_code == 401
    assert _ingest(auth_client, token, body, headers={"X-HISPA-Signature": "0" * 64}).status_code == 401

    signature = hmac_sha256_hex(secret, body)
    accepted = _ingest(auth_client, token, body, headers={"X-HISPA-Signature": signature})
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["accepted"] == 1


def test_public_ingest_json_updates_source_and_exposes_raw(auth_client):
    created = _create_source(auth_client, name="JSON source")
    token = created["token"]
    document = {
        "timestamp": "2026-03-04T05:06:07Z",
        "message": "vendor event",
        "severity": "high",
        "src_ip": "1.1.1.2",
        "vendor_field": {"nested": "preserved"},
    }
    response = _ingest(auth_client, token, json.dumps(document).encode())
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["accepted"] == 1
    assert payload["rejected"] == 0
    assert len(payload["event_ids"]) == 1

    detail = auth_client.get(f"/api/v1/events/{payload['event_ids'][0]}")
    assert detail.status_code == 200
    event = detail.json()
    assert event["raw"]["vendor_field"]["nested"] == "preserved"
    assert event["normalized"]["unmapped"]["vendor_field.nested"] == "preserved"
    assert event["raw_format"] == "json"
    assert event["schema_version"] == "1.1.0"

    source = auth_client.get(f"/api/v1/ingest-sources/{created['id']}").json()
    assert source["event_count"] == 1
    assert source["last_event_at"] is not None


def test_unknown_and_disabled_token_are_indistinguishable(auth_client):
    created = _create_source(auth_client, name="Disabled source")
    patched = auth_client.patch(f"/api/v1/ingest-sources/{created['id']}", json={"enabled": False})
    assert patched.status_code == 200
    assert patched.json()["enabled"] is False

    body = b'{"message":"nope"}'
    disabled = _ingest(auth_client, created["token"], body)
    unknown = _ingest(auth_client, "hs_ing_this_token_does_not_exist_123456", body)
    assert disabled.status_code == 401
    assert unknown.status_code == 401
    assert disabled.json()["error"]["code"] == unknown.json()["error"]["code"]
    assert disabled.json()["error"]["message"] == unknown.json()["error"]["message"]


def test_public_ingest_cef_and_malformed_rejected(auth_client):
    created = _create_source(auth_client, name="CEF source", parser="cef")
    token = created["token"]
    line = (
        b"CEF:0|Vendor|Product|1.0|100|Blocked traffic|10|src=2.2.2.2 dst=3.3.3.3 dpt=443 proto=TCP msg=Blocked traffic"
    )
    response = _ingest(auth_client, token, line, content_type="text/cef")
    assert response.status_code == 200, response.text
    event_id = response.json()["event_ids"][0]
    event = auth_client.get(f"/api/v1/events/{event_id}").json()
    assert event["raw_format"] == "cef"
    assert event["severity_id"] == 5
    assert event["src_ip"] == "2.2.2.2"

    malformed = _ingest(auth_client, token, b"CEF:0|broken", content_type="text/cef")
    assert malformed.status_code == 422
    assert malformed.json()["error"]["code"] == "validation_error"


def test_ingest_body_over_one_megabyte_rejected(auth_client):
    created = _create_source(auth_client, name="Large payload")
    response = _ingest(auth_client, created["token"], b"x" * 1_048_577, content_type="text/plain")
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"


def test_authenticated_bulk_ingest_enforces_500_and_stores_events(auth_client):
    created = _create_source(auth_client, name="Bulk source")
    too_many = {"events": [{"message": "event"} for _ in range(501)]}
    assert auth_client.post("/api/v1/events/ingest", json=too_many).status_code == 422

    payload = {
        "source_id": created["id"],
        "events": [
            {"message": "first bulk", "severity": "high", "src_ip": "4.4.4.4", "host_name": "bulk-1"},
            {"message": "second bulk", "severity": "low", "src_ip": "4.4.4.5", "host_name": "bulk-2"},
        ],
    }
    response = auth_client.post("/api/v1/events/ingest", json=payload)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["accepted"] == 2
    assert body["rejected"] == 0
    assert len(body["event_ids"]) == 2

    events = auth_client.get(f"/api/v1/events?source_id={created['id']}")
    assert events.status_code == 200
    assert events.json()["meta"]["total"] == 2


def test_events_search_filters_sort_and_cross_tenant(auth_client, seeded):
    created = _create_source(auth_client, name="Search source")
    response = auth_client.post(
        "/api/v1/events/ingest",
        json={
            "source_id": created["id"],
            "run_detection": False,
            "events": [
                {
                    "message": "suspicious beacon to command server",
                    "severity": "high",
                    "src_ip": "10.10.10.1",
                    "host_name": "web-01",
                    "user_name": "alice",
                },
                {
                    "message": "routine telemetry",
                    "severity": "low",
                    "src_ip": "10.10.10.2",
                    "host_name": "db-01",
                    "user_name": "bob",
                },
                {
                    "message": "another beacon",
                    "severity": "medium",
                    "src_ip": "10.10.10.1",
                    "host_name": "web-02",
                },
            ],
        },
    )
    assert response.status_code == 200, response.text

    assert auth_client.get("/api/v1/events?severity_id=4").json()["meta"]["total"] == 1
    assert auth_client.get("/api/v1/events?src_ip=10.10.10.1").json()["meta"]["total"] == 2
    assert auth_client.get("/api/v1/events?host_name=web").json()["meta"]["total"] == 2
    assert auth_client.get("/api/v1/events?user_name=alice").json()["meta"]["total"] == 1
    assert auth_client.get("/api/v1/events?q=beacon").json()["meta"]["total"] == 2
    paged = auth_client.get("/api/v1/events?page_size=1&sort=severity_id&order=asc").json()
    assert paged["meta"]["has_next"] is True
    assert paged["items"][0]["severity_id"] == 2

    assert auth_client.get("/api/v1/events?sort=message").status_code == 422
    assert (
        auth_client.get(
            "/api/v1/events?occurred_from=2026-02-01T00:00:00Z&occurred_to=2026-01-01T00:00:00Z"
        ).status_code
        == 422
    )

    other_org = _create_org(auth_client, "events-other")
    auth_client.headers["X-Organization-Id"] = other_org
    other_source = _create_source(auth_client, name="Other source")
    other_event = _ingest(auth_client, other_source["token"], b'{"message":"foreign event"}').json()["event_ids"][0]
    assert auth_client.get(f"/api/v1/events/{other_event}").status_code == 200

    auth_client.headers.pop("X-Organization-Id", None)
    assert auth_client.get(f"/api/v1/events/{other_event}").status_code == 404


def test_event_stats_shape(auth_client):
    created = _create_source(auth_client, name="Stats source")
    response = auth_client.post(
        "/api/v1/events/ingest",
        json={
            "source_id": created["id"],
            "run_detection": False,
            "events": [
                {"message": "stats one", "severity": "critical", "host_name": "h1"},
                {"message": "stats two", "severity": "medium", "host_name": "h1"},
            ],
        },
    )
    assert response.status_code == 200

    stats = auth_client.get("/api/v1/events/stats")
    assert stats.status_code == 200
    payload = stats.json()
    assert payload["window_hours"] == 24
    assert payload["total"] == 2
    assert payload["by_severity"]["5"] == 1
    assert payload["by_severity"]["3"] == 1
    assert payload["top_sources"][0]["source_id"] == created["id"]
    assert payload["top_hosts"][0]["host_name"] == "h1"
    assert len(payload["timeline"]) == 24
    assert payload["by_class"]


def test_retention_policy_and_bounded_purge(auth_client, db):
    created = _create_source(auth_client, name="Retention source")
    ingest = auth_client.post(
        "/api/v1/events/ingest",
        json={
            "source_id": created["id"],
            "run_detection": False,
            "events": [
                {"message": "old evidence", "occurred_at": "2020-01-01T00:00:00Z"},
                {"message": "fresh evidence"},
            ],
        },
    )
    assert ingest.status_code == 200

    update = auth_client.put(
        "/api/v1/events/retention",
        json={"hot_days": 1, "cold_days": 30, "batch_size": 100, "purge_enabled": True},
    )
    assert update.status_code == 200, update.text
    policy = update.json()
    assert policy["version"] == 1
    assert policy["source"] == "policy"
    assert policy["definition"]["hot_days"] == 1

    purge = auth_client.post("/api/v1/events/retention/purge")
    assert purge.status_code == 200, purge.text
    result = purge.json()
    assert result["deleted"] >= 1
    assert result["batches"] >= 1

    remaining = auth_client.get("/api/v1/events")
    assert remaining.status_code == 200
    assert remaining.json()["meta"]["total"] == 1
    assert remaining.json()["items"][0]["message"] == "fresh evidence"

    db.expire_all()
    audit = db.execute(select(AuditRecord).where(AuditRecord.action == "policy.retention.purge")).scalar_one_or_none()
    assert audit is not None
    assert audit.payload["deleted"] >= 1

    disabled = auth_client.put(
        "/api/v1/events/retention",
        json={"hot_days": 1, "cold_days": 30, "batch_size": 100, "purge_enabled": False},
    )
    assert disabled.status_code == 200
    assert disabled.json()["version"] == 2
    assert auth_client.post("/api/v1/events/retention/purge").status_code == 409


def test_ioc_enrichment_attaches_matches_and_mitre(auth_client, seeded, db):
    org = seeded["org"]
    indicator = ThreatIndicator(
        org_id=org.id,
        indicator_type="ip",
        value="6.6.6.6",
        confidence=90,
        severity="critical",
        source="integration-test",
        tags=["T1071", "c2"],
        active=True,
    )
    db.add(indicator)
    db.commit()

    created = _create_source(auth_client, name="IOC source")
    response = _ingest(
        auth_client,
        created["token"],
        b'{"message":"beacon from bad host","src_ip":"6.6.6.6","severity":"high"}',
    )
    assert response.status_code == 200
    event_id = response.json()["event_ids"][0]
    event = auth_client.get(f"/api/v1/events/{event_id}").json()
    assert len(event["ioc_matches"]) == 1
    assert event["ioc_matches"][0]["indicator_id"] == str(indicator.id)
    assert event["ioc_matches"][0]["confidence"] == 90
    assert "T1071" in event["mitre_techniques"]

    db.expire_all()
    refreshed = db.get(ThreatIndicator, indicator.id)
    assert refreshed is not None
    assert refreshed.last_seen is not None


def test_source_rbac_and_cross_tenant_isolation(auth_client, seeded):
    source = _create_source(auth_client, name="RBAC source")
    other_org = _create_org(auth_client, "events-rbac-other")
    auth_client.headers["X-Organization-Id"] = other_org
    foreign_source = _create_source(auth_client, name="Foreign source")
    auth_client.headers.pop("X-Organization-Id", None)

    assert auth_client.get(f"/api/v1/ingest-sources/{foreign_source['id']}").status_code == 404
    foreign_bulk = auth_client.post(
        "/api/v1/events/ingest",
        json={"source_id": foreign_source["id"], "events": [{"message": "cross tenant"}]},
    )
    assert foreign_bulk.status_code == 404

    _add_member(
        auth_client,
        email="rbacuser@example.eu",
        role="viewer",
        password="Str0ng-Test-Passw0rd!2026",
    )
    _login_as(auth_client, "rbacuser@example.eu", "Str0ng-Test-Passw0rd!2026")

    assert auth_client.get("/api/v1/ingest-sources").status_code == 200
    assert auth_client.get("/api/v1/events").status_code == 200
    assert auth_client.post("/api/v1/ingest-sources", json={"name": "Denied"}).status_code == 403
    assert auth_client.patch(f"/api/v1/ingest-sources/{source['id']}", json={"enabled": False}).status_code == 403
    assert auth_client.delete(f"/api/v1/ingest-sources/{source['id']}").status_code == 403
    assert auth_client.post("/api/v1/events/ingest", json={"events": [{"message": "denied"}]}).status_code == 403


def test_ingest_audit_uses_source_actor_and_never_stores_token(auth_client, seeded, db):
    created = _create_source(auth_client, name="Audited source")
    response = _ingest(
        auth_client,
        created["token"],
        b'{"message":"audited event","severity":"medium"}',
    )
    assert response.status_code == 200

    db.expire_all()
    records = list(
        db.execute(
            select(AuditRecord).where(AuditRecord.org_id == seeded["org"].id, AuditRecord.action == "event.ingest")
        ).scalars()
    )
    assert records
    record = records[-1]
    assert record.actor_type == "source"
    assert record.actor_id == created["id"]
    assert record.payload["accepted"] == 1
    assert created["token"] not in json.dumps(record.payload)
    assert "token" not in json.dumps(record.payload).lower()

    stored = db.execute(select(SecurityEvent).where(SecurityEvent.id == response.json()["event_ids"][0])).scalar_one()
    assert stored.org_id == seeded["org"].id
    assert stored.source_id is not None
