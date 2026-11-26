"""Security invariants of the ingestion boundary (tokens, HMAC, limits, isolation)."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.crypto import hmac_sha256_hex, token_hash
from app.main import app
from app.models.core import AuditRecord
from app.models.events import IngestSource, SecurityEvent
from tests.conftest import break_glass


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


def test_hmac_failures_are_audited_and_store_nothing(auth_client, seeded, db):
    secret = "another-hmac-secret-0123456789"
    created = _create_source(auth_client, name="HMAC protected", hmac_secret=secret)
    body = b'{"message":"hmac protected event","severity":"high"}'

    missing = _ingest(auth_client, created["token"], body)
    assert missing.status_code == 401
    assert missing.json()["error"]["message"] == "Invalid signature"

    bad = _ingest(auth_client, created["token"], body, headers={"X-HISPA-Signature": "f" * 64})
    assert bad.status_code == 401

    assert auth_client.get("/api/v1/events").json()["meta"]["total"] == 0

    good = _ingest(
        auth_client,
        created["token"],
        body,
        headers={"X-HISPA-Signature": hmac_sha256_hex(secret, body)},
    )
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

    _ingest(auth_client, token, b'{"message":"audit leak check"}')

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
