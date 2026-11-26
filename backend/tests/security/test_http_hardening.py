"""HTTP hardening, rate limiting, MFA and SSRF regression tests."""

from __future__ import annotations

import time

import pyotp
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.crypto import hash_password, token_hash, verify_password
from app.core.logging import BodySizeLimitMiddleware
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
    no_password = client.post("/api/v1/auth/mfa/enroll")
    assert no_password.status_code == 422
    enrollment = client.post("/api/v1/auth/mfa/enroll", json={"password": ADMIN_PASSWORD})
    assert enrollment.status_code == 200, enrollment.text
    secret = enrollment.json()["secret"]
    totp = pyotp.TOTP(secret)

    activated = client.post("/api/v1/auth/mfa/activate", json={"code": totp.now(), "password": ADMIN_PASSWORD})
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


def test_mfa_recovery_codes_are_single_use_and_regeneration_invalidates_them(seeded, client: TestClient) -> None:
    login(client)
    enrollment = client.post("/api/v1/auth/mfa/enroll", json={"password": ADMIN_PASSWORD})
    secret = enrollment.json()["secret"]
    activated = client.post(
        "/api/v1/auth/mfa/activate", json={"code": pyotp.TOTP(secret).now(), "password": ADMIN_PASSWORD}
    )
    assert activated.status_code == 200, activated.text
    codes = activated.json()["recovery_codes"]
    assert len(codes) == 10
    assert all(len(code) == 14 for code in codes)

    client.post("/api/v1/auth/logout")
    client.cookies.clear()
    client.headers.clear()
    login_response = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
    assert login_response.json()["mfa_required"] is True
    challenge = login_response.json()["challenge_token"]

    recovered = client.post(
        "/api/v1/auth/mfa/recovery",
        json={"challenge_token": challenge, "recovery_code": codes[0]},
    )
    assert recovered.status_code == 200, recovered.text
    assert client.cookies.get("hs_session")

    # Replay of the consumed code must fail even with a fresh challenge.
    client.headers.update({"X-CSRF-Token": client.cookies.get("hs_csrf", "")})
    client.post("/api/v1/auth/logout")
    client.cookies.clear()
    client.headers.clear()
    replay_challenge = client.post(
        "/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}
    ).json()["challenge_token"]
    replay = client.post(
        "/api/v1/auth/mfa/recovery",
        json={"challenge_token": replay_challenge, "recovery_code": codes[0]},
    )
    assert replay.status_code == 401

    # A TOTP challenge still works (next time step; the activation step is spent),
    # then regenerating codes invalidates the old set.
    totp = pyotp.TOTP(secret)
    next_code = totp.generate_otp(int(time.time() // 30) + 1)
    totp_login = client.post(
        "/api/v1/auth/mfa/verify",
        json={"challenge_token": replay_challenge, "code": next_code},
    )
    assert totp_login.status_code == 200, totp_login.text
    client.headers.update({"X-CSRF-Token": client.cookies.get("hs_csrf", "")})
    denied = client.post("/api/v1/auth/mfa/recovery-codes", json={"password": "wrong-password"})
    assert denied.status_code == 401
    regenerated = client.post("/api/v1/auth/mfa/recovery-codes", json={"password": ADMIN_PASSWORD})
    assert regenerated.status_code == 200
    new_codes = regenerated.json()["recovery_codes"]
    assert set(new_codes).isdisjoint(set(codes))

    client.post("/api/v1/auth/logout")
    client.cookies.clear()
    client.headers.clear()
    new_challenge = client.post("/api/v1/auth/login", json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}).json()[
        "challenge_token"
    ]
    old_code = client.post(
        "/api/v1/auth/mfa/recovery",
        json={"challenge_token": new_challenge, "recovery_code": codes[1]},
    )
    assert old_code.status_code == 401


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


def test_body_limit_counts_streamed_chunks_without_content_length() -> None:
    """Regression VULN-018: chunked bodies must not bypass the 30 MB guard."""
    from starlette.applications import Starlette
    from starlette.responses import PlainTextResponse
    from starlette.routing import Route

    async def echo(request):  # type: ignore[no-untyped-def]
        body = await request.body()
        return PlainTextResponse(str(len(body)))

    inner = Starlette(routes=[Route("/echo", echo, methods=["POST"])])
    app = BodySizeLimitMiddleware(inner, max_bytes=16)
    with TestClient(app) as limited:
        within = limited.post("/echo", content=b"x" * 16)
        assert within.status_code == 200
        declared = limited.post("/echo", content=b"x" * 32)
        assert declared.status_code == 413
        assert declared.json()["error"]["code"] == "payload_too_large"
        # No Content-Length: httpx streams chunks and the middleware must count
        # the bytes actually read by the application.
        chunked = limited.post("/echo", content=iter([b"x" * 8, b"y" * 20]))
        assert chunked.status_code == 413
        assert chunked.json()["error"]["code"] == "payload_too_large"
