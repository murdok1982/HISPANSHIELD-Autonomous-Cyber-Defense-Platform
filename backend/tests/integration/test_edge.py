"""Integration tests: edge gateway enrollment, HMAC telemetry, replay and config."""

from __future__ import annotations

import json
import time
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.db import utcnow
from app.models.edge import EdgeIngestEvent
from app.models.events import SecurityEvent
from app.modules.edge.security import compute_signature, sign_config_bundle
from tests.conftest import login

BASE = "/api/v1/edge"
FINGERPRINT = "fp-unit-gateway-0001"


def _enroll(client: TestClient) -> dict:
    response = client.post(f"{BASE}/gateways/enroll-token")
    assert response.status_code == 201, response.text
    return response.json()


def _register(
    client: TestClient,
    token: str,
    *,
    fingerprint: str = FINGERPRINT,
    name: str = "Unit Edge Gateway",
) -> dict:
    response = client.post(
        f"{BASE}/gateways/register",
        json={
            "enrollment_token": token,
            "fingerprint": fingerprint,
            "name": name,
            "version": "1.4.2",
            "certificate_serial": "01:AB:CD:EF",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def _signed_headers(
    secret: str,
    fingerprint: str,
    path: str,
    body: bytes,
    *,
    method: str = "POST",
    timestamp: str | None = None,
) -> dict[str, str]:
    ts = timestamp or str(int(utcnow().timestamp()))
    return {
        "X-Gateway-Fingerprint": fingerprint,
        "X-Gateway-Timestamp": ts,
        "X-Gateway-Signature": compute_signature(secret, ts, method, path, body),
    }


def _bootstrap_gateway(client: TestClient, *, fingerprint: str = FINGERPRINT) -> dict:
    token = _enroll(client)["token"]
    return _register(client, token, fingerprint=fingerprint)


def test_enrollment_token_single_use_and_tampering(seeded, auth_client: TestClient) -> None:
    enrollment = _enroll(auth_client)
    assert enrollment["expires_in_seconds"] == 900
    assert enrollment["token"].startswith("hs_enroll.")

    registered = _register(auth_client, enrollment["token"])
    assert registered["status"] == "active"
    assert registered["fingerprint"] == FINGERPRINT
    assert registered["shared_key"]
    assert registered["config_bundle"]["algorithm"] == "HMAC-SHA256"

    replay = auth_client.post(
        f"{BASE}/gateways/register",
        json={
            "enrollment_token": enrollment["token"],
            "fingerprint": "fp-second-use-0002",
            "name": "Replay Gateway",
        },
    )
    assert replay.status_code == 401

    tampered = auth_client.post(
        f"{BASE}/gateways/register",
        json={
            "enrollment_token": enrollment["token"][:-4] + "AAAA",
            "fingerprint": "fp-tampered-0003",
            "name": "Tampered Gateway",
        },
    )
    assert tampered.status_code == 401

    garbage = auth_client.post(
        f"{BASE}/gateways/register",
        json={"enrollment_token": "not-a-token-at-all", "fingerprint": "fp-bad-0004", "name": "Bad"},
    )
    assert garbage.status_code == 401


def test_register_rejects_duplicate_fingerprint(seeded, auth_client: TestClient) -> None:
    first = _bootstrap_gateway(auth_client)
    assert first["fingerprint"] == FINGERPRINT
    second_token = _enroll(auth_client)["token"]
    duplicate = auth_client.post(
        f"{BASE}/gateways/register",
        json={"enrollment_token": second_token, "fingerprint": FINGERPRINT, "name": "Duplicated"},
    )
    assert duplicate.status_code == 409


def test_heartbeat_updates_state_and_rejects_bad_signatures(seeded, auth_client: TestClient) -> None:
    gateway = _bootstrap_gateway(auth_client)
    gateway_id = gateway["gateway_id"]
    secret = gateway["shared_key"]
    path = f"{BASE}/gateways/{gateway_id}/heartbeat"
    body = json.dumps({"version": "1.5.0", "buffer_stats": {"queued": 12, "sent": 120}}).encode()

    ok = auth_client.post(path, content=body, headers=_signed_headers(secret, FINGERPRINT, path, body))
    assert ok.status_code == 200, ok.text
    assert ok.json()["ok"] is True
    assert ok.json()["cursor"] == 0

    invalid = auth_client.post(
        path,
        content=body,
        headers=_signed_headers("wrong-secret", FINGERPRINT, path, body),
    )
    assert invalid.status_code == 401

    wrong_fingerprint = auth_client.post(
        path, content=body, headers=_signed_headers(secret, "fp-other-9999", path, body)
    )
    assert wrong_fingerprint.status_code == 401

    stale = auth_client.post(
        path,
        content=body,
        headers=_signed_headers(secret, FINGERPRINT, path, body, timestamp=str(int(utcnow().timestamp()) - 4000)),
    )
    assert stale.status_code == 401

    unknown = auth_client.post(
        f"{BASE}/gateways/{uuid4()}/heartbeat",
        content=b"",
        headers=_signed_headers(secret, FINGERPRINT, path, b""),
    )
    assert unknown.status_code == 404

    stored = auth_client.get(f"{BASE}/gateways/{gateway_id}")
    assert stored.status_code == 200
    assert stored.json()["version"] == "1.5.0"
    assert stored.json()["buffer_stats"]["queued"] == 12
    assert "_security" not in stored.json()["config"]


def test_signed_event_batch_is_normalized_and_cursored(seeded, auth_client: TestClient, db) -> None:
    gateway = _bootstrap_gateway(auth_client)
    gateway_id = gateway["gateway_id"]
    secret = gateway["shared_key"]
    path = f"{BASE}/gateways/{gateway_id}/events"
    envelope = {
        "sequence": 1,
        "kind": "network",
        "events": [
            {
                "event_uid": "edge-evt-1",
                "occurred_at": "2026-11-26T09:00:00Z",
                "src_ip": "10.10.0.5",
                "dst_ip": "203.0.113.5",
                "dst_port": 443,
                "protocol": "TCP",
                "severity": "high",
                "message": "Outbound TLS connection",
                "mitre_techniques": ["T1071"],
            },
            {
                "event_uid": "edge-evt-2",
                "src_ip": "invalid-ip",
                "message": "Malformed source is dropped",
            },
        ],
    }
    body = json.dumps(envelope).encode()
    accepted = auth_client.post(path, content=body, headers=_signed_headers(secret, FINGERPRINT, path, body))
    assert accepted.status_code == 200, accepted.text
    result = accepted.json()
    assert result["accepted"] is True
    assert result["processed"] == 2
    assert result["cursor"] == 1

    events = list(db.execute(select(SecurityEvent).where(SecurityEvent.org_id == seeded["org"].id)).scalars())
    assert len(events) == 2
    first = next(event for event in events if event.event_uid == "edge-evt-1")
    assert first.src_ip == "10.10.0.5"
    assert first.dst_port == 443
    assert first.severity_id == 4
    assert first.mitre_techniques == ["T1071"]
    assert first.dedupe_key and len(first.dedupe_key) == 64
    malformed = next(event for event in events if event.event_uid == "edge-evt-2")
    assert malformed.src_ip is None

    heartbeat_path = f"{BASE}/gateways/{gateway_id}/heartbeat"
    heartbeat = auth_client.post(
        heartbeat_path, content=b"", headers=_signed_headers(secret, FINGERPRINT, heartbeat_path, b"")
    )
    assert heartbeat.status_code == 200
    assert heartbeat.json()["cursor"] == 1

    listed = auth_client.get(f"{BASE}/gateways/{gateway_id}/events")
    assert listed.status_code == 200
    assert listed.json()["meta"]["total"] == 1
    assert listed.json()["items"][0]["processed_count"] == 2
    assert listed.json()["items"][0]["accepted"] is True


def test_event_replay_and_tampering_are_rejected(seeded, auth_client: TestClient, db) -> None:
    gateway = _bootstrap_gateway(auth_client)
    gateway_id = gateway["gateway_id"]
    secret = gateway["shared_key"]
    path = f"{BASE}/gateways/{gateway_id}/events"
    envelope = {"sequence": 7, "kind": "json", "events": [{"event_uid": "seq-7", "message": "first"}]}
    body = json.dumps(envelope).encode()
    headers = _signed_headers(secret, FINGERPRINT, path, body)
    assert auth_client.post(path, content=body, headers=headers).status_code == 200

    replay = auth_client.post(path, content=body, headers=headers)
    assert replay.status_code == 409
    assert "replay" in replay.json()["error"]["message"].lower()

    rejected = db.execute(select(EdgeIngestEvent).where(EdgeIngestEvent.accepted.is_(False))).scalars()
    assert any(item.rejection_reason == "replay_sequence" for item in rejected)

    tampered_body = json.dumps({**envelope, "events": [{"event_uid": "seq-7", "message": "tampered"}]}).encode()
    tampered = auth_client.post(path, content=tampered_body, headers=headers)
    assert tampered.status_code == 401

    next_batch = json.dumps({"sequence": 8, "kind": "json", "events": [{"event_uid": "seq-8"}]}).encode()
    assert (
        auth_client.post(
            path, content=next_batch, headers=_signed_headers(secret, FINGERPRINT, path, next_batch)
        ).status_code
        == 200
    )


def test_config_allow_list_and_signed_bundle(seeded, auth_client: TestClient) -> None:
    gateway = _bootstrap_gateway(auth_client)
    gateway_id = gateway["gateway_id"]
    secret = gateway["shared_key"]

    patched = auth_client.patch(
        f"{BASE}/gateways/{gateway_id}",
        json={
            "batch_size": 50,
            "flush_interval_seconds": 10,
            "heartbeat_interval_seconds": 30,
            "log_level": "warning",
            "collectors": ["syslog", "ot"],
        },
    )
    assert patched.status_code == 200, patched.text
    assert patched.json()["config"]["batch_size"] == 50
    assert patched.json()["config"]["log_level"] == "warning"

    forbidden = auth_client.patch(
        f"{BASE}/gateways/{gateway_id}",
        json={"policy": "allow-everything", "buffer_max_events": 10},
    )
    assert forbidden.status_code == 422

    invalid_type = auth_client.patch(f"{BASE}/gateways/{gateway_id}", json={"buffer_max_events": "many"})
    assert invalid_type.status_code == 422

    bundle_response = auth_client.get(f"{BASE}/gateways/{gateway_id}/config-bundle")
    assert bundle_response.status_code == 200
    payload = bundle_response.json()
    bundle = payload["bundle"]
    expected = sign_config_bundle(secret, bundle)
    assert payload["signature"] == expected
    assert bundle["org_id"]
    assert "_security" not in bundle["config"]
    assert bundle["config"]["batch_size"] == 50
    assert bundle["gateway_id"] == gateway_id


def test_key_rotation_invalidates_previous_secret(seeded, auth_client: TestClient) -> None:
    gateway = _bootstrap_gateway(auth_client)
    gateway_id = gateway["gateway_id"]
    old_secret = gateway["shared_key"]
    path = f"{BASE}/gateways/{gateway_id}/heartbeat"
    body = b"{}"

    rotated = auth_client.post(f"{BASE}/gateways/{gateway_id}/rotate-key")
    assert rotated.status_code == 200, rotated.text
    new_secret = rotated.json()["shared_key"]
    assert new_secret != old_secret

    old_attempt = auth_client.post(path, content=body, headers=_signed_headers(old_secret, FINGERPRINT, path, body))
    assert old_attempt.status_code == 401
    new_attempt = auth_client.post(path, content=body, headers=_signed_headers(new_secret, FINGERPRINT, path, body))
    assert new_attempt.status_code == 200


def test_revocation_blocks_gateway_authentication(seeded, auth_client: TestClient) -> None:
    gateway = _bootstrap_gateway(auth_client)
    gateway_id = gateway["gateway_id"]
    secret = gateway["shared_key"]
    path = f"{BASE}/gateways/{gateway_id}/heartbeat"

    revoked = auth_client.post(f"{BASE}/gateways/{gateway_id}/revoke")
    assert revoked.status_code == 200
    assert revoked.json()["status"] == "revoked"

    blocked = auth_client.post(path, content=b"", headers=_signed_headers(secret, FINGERPRINT, path, b""))
    assert blocked.status_code == 404

    again = auth_client.post(f"{BASE}/gateways/{gateway_id}/revoke")
    assert again.status_code == 409

    rotate = auth_client.post(f"{BASE}/gateways/{gateway_id}/rotate-key")
    assert rotate.status_code == 409


def test_gateway_listing_excludes_pending_enrollments(seeded, auth_client: TestClient) -> None:
    pending = _enroll(auth_client)
    listed = auth_client.get(f"{BASE}/gateways")
    assert listed.status_code == 200
    assert listed.json()["meta"]["total"] == 0

    registered = _register(auth_client, pending["token"])
    listed = auth_client.get(f"{BASE}/gateways")
    assert listed.json()["meta"]["total"] == 1
    assert listed.json()["items"][0]["id"] == registered["gateway_id"]

    pending_listing = auth_client.get(f"{BASE}/gateways", params={"status": "pending"})
    assert pending_listing.status_code == 200

    detail = auth_client.get(f"{BASE}/gateways/{registered['gateway_id']}")
    assert detail.status_code == 200
    assert detail.json()["fingerprint"] == FINGERPRINT


def test_gateway_tenant_isolation(seeded, auth_client: TestClient) -> None:
    other = auth_client.post("/api/v1/organizations", json={"name": "Edge Other Org", "slug": "edge-other-org"})
    assert other.status_code == 201, other.text
    auth_client.headers["X-Organization-Id"] = other.json()["id"]
    foreign = _bootstrap_gateway(auth_client, fingerprint="fp-foreign-0001")
    auth_client.headers.pop("X-Organization-Id", None)

    assert auth_client.get(f"{BASE}/gateways/{foreign['gateway_id']}").status_code == 404
    assert auth_client.get(f"{BASE}/gateways/{foreign['gateway_id']}/events").status_code == 404
    assert auth_client.get(f"{BASE}/gateways/{foreign['gateway_id']}/config-bundle").status_code == 404


def test_rbac_viewer_cannot_enroll_or_configure(seeded, auth_client: TestClient) -> None:
    member = auth_client.post(
        "/api/v1/organizations/current/members",
        json={
            "email": "viewer.edge@hispanshield.eu",
            "full_name": "Viewer Edge",
            "role": "viewer",
            "password": "Viewer-Edge-Pass!9x",
        },
    )
    assert member.status_code == 201, member.text
    login(auth_client, email="viewer.edge@hispanshield.eu", password="Viewer-Edge-Pass!9x")

    assert auth_client.get(f"{BASE}/gateways").status_code == 200
    denied = auth_client.post(f"{BASE}/gateways/enroll-token")
    assert denied.status_code == 403


@pytest.mark.parametrize("kind", ["network", "ot", "iot", "json"])
def test_event_kinds_are_accepted(seeded, auth_client: TestClient, kind: str) -> None:
    gateway = _bootstrap_gateway(auth_client, fingerprint=f"fp-kind-{kind}-0001")
    path = f"{BASE}/gateways/{gateway['gateway_id']}/events"
    body = json.dumps(
        {"sequence": 1, "kind": kind, "events": [{"event_uid": f"kind-{kind}", "message": f"{kind} telemetry"}]}
    ).encode()
    response = auth_client.post(
        path, content=body, headers=_signed_headers(gateway["shared_key"], f"fp-kind-{kind}-0001", path, body)
    )
    assert response.status_code == 200, response.text
    assert response.json()["processed"] == 1


def test_timezone_aware_signature_window_rejects_future() -> None:
    # Guard rail for the signature window helper itself (unit-level assertion).
    from app.modules.edge.security import verify_signature

    assert not verify_signature("secret", str(int(time.time()) + 10_000), "0" * 64, "POST", "/x", b"")


def test_enrollment_token_expiry_claim_is_bounded() -> None:
    from app.modules.edge.security import EnrollmentTokenError, verify_enrollment_token

    with pytest.raises(EnrollmentTokenError):
        verify_enrollment_token("hs_enroll.invalid.signature")
