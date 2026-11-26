"""Security invariants of the ingestion boundary (tokens, HMAC, limits, isolation)."""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.crypto import hmac_sha256_hex, token_hash
from app.main import app
from app.models.core import AuditRecord
from app.models.events import IngestNonce, IngestSource, SecurityEvent
from tests.conftest import break_glass


def _v2_headers(
    secret: str,
    body: bytes,
    *,
    timestamp: int | None = None,
    nonce: str | None = None,
) -> dict[str, str]:
    stamp = str(int(datetime.now(UTC).timestamp())) if timestamp is None else str(timestamp)
    token = nonce or f"nonce-{uuid.uuid4().hex}"
    canonical = f"{stamp}.{token}.".encode() + body
    return {
        "X-HS-Timestamp": stamp,
        "X-HS-Nonce": token,
        "X-HS-Signature": hmac_sha256_hex(secret, canonical),
    }


def _create_source(client, **overrides):
    payload = {"name": "Security source", "kind": "api", "parser": "auto", "enabled": True}
    payload.update(overrides)
    response = client.post("/api/v1/ingest-sources", json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def _ingest(client, token: str, body: bytes, content_type: str = "application/json", headers=None):
    request_headers = {"Content-Type": content_type}
    if headers:
        request_headers.update(headers)
    return client.post(f"/api/v1/ingest/{token}", content=body, headers=request_headers)


def _create_org(client, slug: str) -> str:
    response = client.post("/api/v1/organizations", json={"name": f"Org {slug}", "slug": slug})
    assert response.status_code == 201, response.text
    return response.json()["id"]


def test_unknown_token_returns_generic_401(client):
    response = _ingest(client, "hs_ing_unknown_token_abcdefghijklmnop", b'{"message":"x"}')
    assert response.status_code == 401
    error = response.json()["error"]
    assert error["code"] == "unauthorized"
    assert error["message"] == "Invalid ingestion token"
    assert "details" not in error
    assert "not found" not in response.text.lower()
    assert "source" not in response.text.lower()


def test_invalid_token_shapes_are_rejected_without_lookup(client):
    for token in ("abc", "bad$token", "x" * 300, "hs_ing_" + "a" * 500):
        response = _ingest(client, token, b'{"message":"x"}')
        assert response.status_code == 401, token[:20]
        assert response.json()["error"]["message"] == "Invalid ingestion token"


def test_disabled_source_is_indistinguishable_from_unknown(auth_client):
    created = _create_source(auth_client, name="Disabled")
    patched = auth_client.patch(f"/api/v1/ingest-sources/{created['id']}", json={"enabled": False})
    assert patched.status_code == 200

    with TestClient(app) as anonymous:
        disabled = _ingest(anonymous, created["token"], b'{"message":"x"}')
        unknown = _ingest(anonymous, "hs_ing_unknown_token_abcdefghijklmnop", b'{"message":"x"}')

    assert disabled.status_code == unknown.status_code == 401
    assert disabled.json()["error"]["code"] == unknown.json()["error"]["code"]
    assert disabled.json()["error"]["message"] == unknown.json()["error"]["message"]


def test_ingestion_works_without_authentication_session(auth_client):
    created = _create_source(auth_client, name="Anonymous OK")
    with TestClient(app) as anonymous:
        response = _ingest(anonymous, created["token"], b'{"message":"machine to machine"}')
    assert response.status_code == 200, response.text
    assert response.json()["accepted"] == 1


def test_ingest_accepts_token_in_authorization_header(auth_client):
    created = _create_source(auth_client, name="Header auth")
    body = b'{"message":"header authenticated event"}'
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {created['token']}"}
    response = auth_client.post("/api/v1/ingest", content=body, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["accepted"] == 1

    missing = auth_client.post("/api/v1/ingest", content=body, headers={"Content-Type": "application/json"})
    assert missing.status_code == 401
    assert missing.json()["error"]["message"] == "Invalid ingestion token"


def test_hmac_failures_are_audited_and_store_nothing(auth_client, seeded, db):
    secret = "another-hmac-secret-0123456789"
    created = _create_source(auth_client, name="HMAC protected", hmac_secret=secret)
    body = b'{"message":"hmac protected event","severity":"high","timestamp":"2026-03-04T05:06:07Z"}'

    missing = _ingest(auth_client, created["token"], body)
    assert missing.status_code == 401
    assert missing.json()["error"]["message"] == "Invalid signature"

    bad = _ingest(auth_client, created["token"], body, headers={"X-HS-Signature": "f" * 64})
    assert bad.status_code == 401

    assert auth_client.get("/api/v1/events").json()["meta"]["total"] == 0

    good = _ingest(auth_client, created["token"], body, headers=_v2_headers(secret, body))
    assert good.status_code == 200
    assert good.json()["accepted"] == 1

    db.expire_all()
    failures = list(
        db.execute(
            select(AuditRecord).where(
                AuditRecord.org_id == seeded["org"].id,
                AuditRecord.action == "event.ingest",
                AuditRecord.outcome == "failure",
            )
        ).scalars()
    )
    assert len(failures) >= 2
    assert all(record.actor_type == "source" for record in failures)


def test_oversized_payload_is_rejected_before_parsing(auth_client):
    created = _create_source(auth_client, name="Too big")
    response = _ingest(auth_client, created["token"], b"{" + b"a" * 1_048_600, content_type="text/plain")
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "payload_too_large"
    assert auth_client.get("/api/v1/events").json()["meta"]["total"] == 0


def test_control_characters_are_stripped_from_message_and_raw(auth_client):
    created = _create_source(auth_client, name="Control chars")
    body = json.dumps(
        {
            "message": "start\x00middle\x07end\x1f",
            "src_ip": "1.2.3.4",
            "vendor": {"note": "bad\x00value"},
        }
    ).encode()
    response = _ingest(auth_client, created["token"], body)
    assert response.status_code == 200, response.text
    event = auth_client.get(f"/api/v1/events/{response.json()['event_ids'][0]}").json()
    assert "\x00" not in event["message"]
    assert "\x07" not in event["message"]
    assert event["message"] == "start middle end"
    serialized = json.dumps(event["raw"])
    assert "\\u0000" not in serialized
    assert "\\u0007" not in serialized


def test_cross_tenant_source_and_event_isolation(auth_client):
    other_org = _create_org(auth_client, "ingest-security-other")
    with break_glass(auth_client, other_org):
        foreign = _create_source(auth_client, name="Foreign source")

    assert auth_client.get(f"/api/v1/ingest-sources/{foreign['id']}").status_code == 404
    assert (
        auth_client.post(
            "/api/v1/events/ingest",
            json={"source_id": foreign["id"], "events": [{"message": "cross tenant"}]},
        ).status_code
        == 404
    )

    ingested = _ingest(auth_client, foreign["token"], b'{"message":"foreign event"}')
    assert ingested.status_code == 200
    foreign_event_id = ingested.json()["event_ids"][0]
    assert auth_client.get(f"/api/v1/events/{foreign_event_id}").status_code == 404
    assert auth_client.get("/api/v1/events").json()["meta"]["total"] == 0


def test_authenticated_bulk_validation_is_strict(auth_client):
    invalid_requests = [
        {"events": [{"message": "bad ip", "src_ip": "999.999.1.1"}]},
        {"events": [{"message": "bad hash", "file_hash_sha256": "zz"}]},
        {"events": [{"message": "bad severity", "severity": "apocalyptic"}]},
        {"events": [{"message": "extra field", "not_allowed": True}]},
        {"events": [{"message": "x" * 20001}]},
        {"events": []},
    ]
    for payload in invalid_requests:
        response = auth_client.post("/api/v1/events/ingest", json=payload)
        assert response.status_code == 422, response.text
        assert response.json()["error"]["code"] == "validation_error"

    assert auth_client.get("/api/v1/events").json()["meta"]["total"] == 0


def test_token_never_leaks_in_reads_or_audit(auth_client, seeded, db):
    created = _create_source(auth_client, name="No leak", generate_hmac_secret=True)
    token = created["token"]
    secret = created["hmac_secret"]

    detail = auth_client.get(f"/api/v1/ingest-sources/{created['id']}")
    assert detail.status_code == 200
    listing = auth_client.get("/api/v1/ingest-sources")
    for response in (detail, listing):
        text = response.text
        assert token not in text
        assert secret not in text
        assert "token_hash" not in text
        assert "hmac_secret_encrypted" not in text

    _ingest(
        auth_client,
        token,
        b'{"message":"audit leak check","timestamp":"2026-03-04T05:06:07Z"}',
        headers=_v2_headers(secret, b'{"message":"audit leak check","timestamp":"2026-03-04T05:06:07Z"}'),
    )

    db.expire_all()
    source = db.get(IngestSource, created["id"])
    assert source is not None
    assert source.token_hash == token_hash(token)
    assert source.hmac_secret_encrypted not in (None, secret)

    audits = list(
        db.execute(
            select(AuditRecord).where(
                AuditRecord.org_id == seeded["org"].id,
                AuditRecord.action.in_(("ingest_source.create", "event.ingest")),
            )
        ).scalars()
    )
    assert audits
    for record in audits:
        payload = json.dumps(record.payload)
        assert token not in payload
        assert secret not in payload


def test_malformed_json_from_valid_source_is_rejected_and_audited(auth_client, seeded, db):
    created = _create_source(auth_client, name="Malformed JSON")
    response = _ingest(auth_client, created["token"], b'{"message": ', content_type="application/json")
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert any("JSON" in item["message"] for item in response.json()["error"]["details"])

    db.expire_all()
    records = list(db.execute(select(SecurityEvent).where(SecurityEvent.org_id == seeded["org"].id)).scalars())
    assert records == []
    failure = db.execute(
        select(AuditRecord).where(
            AuditRecord.org_id == seeded["org"].id,
            AuditRecord.action == "event.ingest",
            AuditRecord.outcome == "failure",
        )
    ).scalar_one_or_none()
    assert failure is not None
    assert failure.payload["detail"]["error"] == "malformed_json"


# ---------------------------------------------------------------------------
# VULN-010: HMAC v2 replay protection and persistent dedupe
# ---------------------------------------------------------------------------


def test_exact_replay_is_persistently_deduplicated(auth_client, seeded, db):
    secret = "replay-hmac-secret-0123456789"
    created = _create_source(auth_client, name="Replay protected", hmac_secret=secret)
    body = json.dumps(
        {
            "message": "replayed firewall block",
            "severity": "high",
            "src_ip": "203.0.113.9",
            "timestamp": "2026-03-04T05:06:07Z",
        }
    ).encode()

    first = _ingest(auth_client, created["token"], body, headers=_v2_headers(secret, body))
    assert first.status_code == 200, first.text
    assert first.json()["accepted"] == 1
    assert first.json()["duplicates"] == 0
    assert first.json()["event_ids"]

    replay = _ingest(auth_client, created["token"], body, headers=_v2_headers(secret, body))
    assert replay.status_code == 200, replay.text
    assert replay.json()["accepted"] == 0
    assert replay.json()["duplicates"] == 1
    assert replay.json()["event_ids"] == []

    assert auth_client.get("/api/v1/events").json()["meta"]["total"] == 1

    db.expire_all()
    stored = list(db.execute(select(SecurityEvent).where(SecurityEvent.org_id == seeded["org"].id)).scalars())
    assert len(stored) == 1
    assert stored[0].dedupe_key is not None


def test_stale_timestamp_is_rejected(auth_client, db):
    secret = "stale-hmac-secret-0123456789"
    created = _create_source(auth_client, name="Stale window", hmac_secret=secret)
    body = b'{"message":"too old","timestamp":"2026-03-04T05:06:07Z"}'
    stale = int((datetime.now(UTC) - timedelta(seconds=600)).timestamp())

    response = _ingest(auth_client, created["token"], body, headers=_v2_headers(secret, body, timestamp=stale))
    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Invalid signature"

    future = int((datetime.now(UTC) + timedelta(seconds=600)).timestamp())
    future_response = _ingest(auth_client, created["token"], body, headers=_v2_headers(secret, body, timestamp=future))
    assert future_response.status_code == 401
    assert auth_client.get("/api/v1/events").json()["meta"]["total"] == 0


def test_reused_nonce_is_rejected_even_with_valid_signature(auth_client, db):
    secret = "nonce-hmac-secret-0123456789"
    created = _create_source(auth_client, name="Nonce replay", hmac_secret=secret)
    body = b'{"message":"nonce guarded","timestamp":"2026-03-04T05:06:07Z"}'
    timestamp = int(datetime.now(UTC).timestamp())
    nonce = "unique-nonce-abc123"

    headers = _v2_headers(secret, body, timestamp=timestamp, nonce=nonce)
    first = _ingest(auth_client, created["token"], body, headers=headers)
    assert first.status_code == 200, first.text

    reused = _ingest(
        auth_client, created["token"], body, headers=_v2_headers(secret, body, timestamp=timestamp, nonce=nonce)
    )
    assert reused.status_code == 401
    assert reused.json()["error"]["message"] == "Invalid signature"

    db.expire_all()
    nonces = list(db.execute(select(IngestNonce).where(IngestNonce.source_id == created["id"])).scalars())
    assert len(nonces) == 1


def test_invalid_v2_signature_is_unauthorized(auth_client):
    secret = "bad-signature-secret-0123456789"
    created = _create_source(auth_client, name="Bad signature", hmac_secret=secret)
    body = b'{"message":"honest","timestamp":"2026-03-04T05:06:07Z"}'
    headers = _v2_headers(secret, body)
    tampered = b'{"message":"tampered","timestamp":"2026-03-04T05:06:07Z"}'

    response = _ingest(auth_client, created["token"], tampered, headers=headers)
    assert response.status_code == 401
    assert auth_client.get("/api/v1/events").json()["meta"]["total"] == 0


def test_legacy_body_signature_requires_explicit_flag(auth_client):
    secret = "legacy-hmac-secret-0123456789"
    default_source = _create_source(auth_client, name="Legacy default", hmac_secret=secret)
    body = b'{"message":"legacy attempt","timestamp":"2026-03-04T05:06:07Z"}'
    legacy_headers = {"X-HISPA-Signature": hmac_sha256_hex(secret, body)}

    rejected = _ingest(auth_client, default_source["token"], body, headers=legacy_headers)
    assert rejected.status_code == 401

    opted_in = _create_source(
        auth_client,
        name="Legacy opt-in",
        hmac_secret=secret,
        config={"allow_legacy_hmac": True},
    )
    accepted = _ingest(auth_client, opted_in["token"], body, headers=legacy_headers)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["accepted"] == 1


def test_dedupe_unique_index_is_enforced_by_the_database(auth_client, seeded, db):
    created = _create_source(auth_client, name="Unique dedupe")
    body = b'{"message":"dedupe constraint","timestamp":"2026-03-04T05:06:07Z"}'
    assert _ingest(auth_client, created["token"], body).status_code == 200

    db.expire_all()
    original = db.execute(select(SecurityEvent).where(SecurityEvent.org_id == seeded["org"].id)).scalar_one()
    assert original.dedupe_key

    savepoint = db.begin_nested()
    db.add(
        SecurityEvent(
            org_id=seeded["org"].id,
            event_uid=str(uuid.uuid4()),
            occurred_at=datetime.now(UTC),
            class_name="Other",
            message="duplicate insert",
            dedupe_key=original.dedupe_key,
        )
    )
    with pytest.raises(IntegrityError):
        db.flush()
    savepoint.rollback()
    assert db.execute(select(SecurityEvent).where(SecurityEvent.org_id == seeded["org"].id)).scalars().all() != []


def test_bulk_batch_tolerates_duplicates_without_aborting(auth_client):
    created = _create_source(auth_client, name="Bulk dedupe")
    response = auth_client.post(
        "/api/v1/events/ingest",
        json={
            "source_id": created["id"],
            "run_detection": False,
            "events": [
                {"message": "duplicate bulk row", "host_name": "bulk-dupe"},
                {"message": "duplicate bulk row", "host_name": "bulk-dupe"},
                {"message": "unique bulk row", "host_name": "bulk-unique"},
            ],
        },
    )
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["accepted"] == 2
    assert payload["duplicates"] == 1
    assert len(payload["event_ids"]) == 2
    assert auth_client.get("/api/v1/events").json()["meta"]["total"] == 2
