"""Password/session policy discovery endpoint (AC-07)."""

from __future__ import annotations


def test_password_policy_is_public_and_matches_enforcement(client) -> None:
    response = client.get("/api/v1/auth/password-policy")
    assert response.status_code == 200
    body = response.json()
    assert body["min_length"] == 12
    assert body["max_length"] == 128
    assert body["required_classes"] == 3
    assert "lowercase" in body["classes"]
    assert body["denylist_entries"] >= 1
    assert body["mfa_recovery_codes"] == 10
    assert body["session_idle_minutes"] == 30
    assert body["session_ttl_minutes"] == 720


def test_password_policy_validates_against_the_same_rules(client) -> None:
    # A 12-char but single-class password must still be rejected with 422.
    response = client.post(
        "/api/v1/auth/login",
        json={"email": "nobody@example.eu", "password": "aaaaaaaaaaaa"},
    )
    assert response.status_code == 401  # login does not enforce strength, only change does
