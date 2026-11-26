"""HTTP hardening, rate limiting, MFA and SSRF regression tests."""

from __future__ import annotations

import time

import pyotp
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.crypto import token_hash, verify_password, hash_password
from app.core.ssrf import SSRFError, validate_outbound_url
from tests.conftest import ADMIN_EMAIL, ADMIN_PASSWORD, login


def test_security_headers_on_api_and_spa(client: TestClient) -> None:
    response = client.get("/healthz")
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.headers["Referrer-Policy"] == "strict-origin-when-cross-origin"
    assert response.headers["Server"] == "HISPANSHIELD"
    assert response.headers["X-Request-ID"]


def test_api_responses_are_not_cached(seeded, auth_client: TestClient) -> None:
    response = auth_client.get("/api/v1/auth/me")
    assert response.status_code == 200
    assert response.headers["Cache-Control"] == "no-store"


def test_login_rate_limit_returns_retry_after(seeded, client: TestClient, monkeypatch) -> None:
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    monkeypatch.setattr(settings, "login_rate_limit_per_minute", 3)
    last = None
    for _ in range(4):
        last = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": "wrong-password"})
    assert last is not None
    assert last.status_code == 429
    assert int(last.headers["Retry-After"]) >= 1
    assert last.json()["error"]["code"] == "rate_limited"


def test_rate_limit_resets_after_window(seeded, client: TestClient, monkeypatch) -> None:
    # Regression: rejected requests must not roll back their own bucket counter.
    monkeypatch.setattr(settings, "rate_limit_enabled", True)
    monkeypatch.setattr(settings, "login_rate_limit_per_minute", 1)
    first = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": "wrong-password"})
    second = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": "wrong-password"})
    assert first.status_code == 401
    assert second.status_code == 429


def test_mfa_enrollment_login_and_replay_protection(seeded, client: TestClient) -> None:
    login(client)
    enrollment = client.post("/api/v1/auth/mfa/enroll")
    assert enrollment.status_code == 200, enrollment.text
    secret = enrollment.json()["secret"]
    totp = pyotp.TOTP(secret)

    activated = client.post("/api/v1/auth/mfa/activate", json={"code": totp.now()})
    assert activated.status_code == 200, activated.text
    client.post("/api/v1/auth/logout")
    client.cookies.clear()
    client.headers.clear()

    login_response = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert login_response.status_code == 200
    body = login_response.json()
    assert body.get("mfa_required") is True
    challenge = body["challenge_token"]

    bad = client.post("/api/v1/auth/mfa/verify", json={"challenge_token": challenge, "code": "000000"})
    assert bad.status_code == 401

    # Use the next time step: the activation code's counter is already consumed.
    next_code = totp.at(time.time() + 30)
    verified = client.post("/api/v1/auth/mfa/verify", json={"challenge_token": challenge, "code": next_code})
    assert verified.status_code == 200, verified.text
    assert client.cookies.get("hs_session")

    # Replaying the same time step in a new challenge must be rejected.
    client.cookies.clear()
    client.headers.clear()
    challenge_again = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}).json()
    replay = client.post(
        "/api/v1/auth/mfa/verify",
        json={"challenge_token": challenge_again["challenge_token"], "code": next_code},
    )
    assert replay.status_code == 401


def test_tampered_mfa_challenge_is_rejected(client: TestClient, seeded) -> None:
    response = client.post(
        "/api/v1/auth/mfa/verify",
        json={"challenge_token": "ZmFrZQ." + "a" * 64, "code": "123456"},
    )
    assert response.status_code == 401


def test_outbound_ssrf_blocks_metadata_and_private_ranges() -> None:
    for url in (
        "http://127.0.0.1:8080/",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/",
        "http://[::1]/",
        "file:///etc/passwd",
        "http://user:pass@example.com/",
    ):
        try:
            validate_outbound_url(url, allow_private=False)
        except SSRFError:
            continue
        raise AssertionError(f"URL should have been blocked: {url}")


def test_security_primitives_are_not_plaintext_hashes() -> None:
    digest = hash_password("A-Str0ng-Password!2026")
    assert digest.startswith("$argon2id$")
    assert verify_password("A-Str0ng-Password!2026", digest)
    assert not verify_password("wrong", digest)
    assert len(token_hash("token")) == 64
