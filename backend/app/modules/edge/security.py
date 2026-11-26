"""Edge gateway cryptography: enrollment tokens and payload HMAC signing.

Design notes (security-sensitive):

* Enrollment tokens are HMAC-SHA256 signed with a key derived from the platform
  ``HS_SECRET_KEY`` and carry ``org_id``, an expiry and a random ``jti``. The
  per-gateway record stores only a SHA-256 hash of the token, so a database
  disclosure cannot mint new gateways.
* Gateway event signatures cover the HTTP method, exact path, timestamp and
  SHA-256 of the raw body. Timestamps outside a small window are rejected, which
  bounds replay even before the monotonic sequence check runs.
* All comparisons use :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from datetime import datetime, timedelta
from typing import Any
from uuid import UUID

from app.core.config import settings
from app.core.db import utcnow

ENROLLMENT_TTL_SECONDS = 15 * 60
SIGNATURE_MAX_SKEW_SECONDS = 300
TOKEN_PREFIX = "hs_enroll"
TOKEN_MAX_LENGTH = 2048
_INTERNAL_CONFIG_KEY = "_security"
_ENROLLMENT_KEY = "_enrollment"


class EnrollmentTokenError(ValueError):
    """Raised when an enrollment token cannot be trusted."""


def _enrollment_key() -> bytes:
    return hashlib.sha256(f"{settings.secret_key}:edge-enrollment:v1".encode()).digest()


def _b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def issue_enrollment_token(org_id: UUID) -> tuple[str, str, datetime]:
    """Return ``(token, token_sha256, expires_at)`` for a one-time enrollment."""
    jti = secrets.token_hex(16)
    expires_at = utcnow() + timedelta(seconds=ENROLLMENT_TTL_SECONDS)
    payload = {
        "purpose": "edge-enroll",
        "v": 1,
        "org_id": str(org_id),
        "jti": jti,
        "exp": int(expires_at.timestamp()),
    }
    encoded = _b64encode(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    signature = _b64encode(hmac.new(_enrollment_key(), encoded.encode(), hashlib.sha256).digest())
    token = f"{TOKEN_PREFIX}.{encoded}.{signature}"
    return token, hashlib.sha256(token.encode()).hexdigest(), expires_at


def verify_enrollment_token(token: str) -> dict[str, Any]:
    if not isinstance(token, str) or not token or len(token) > TOKEN_MAX_LENGTH:
        raise EnrollmentTokenError("Enrollment token is missing or too large")
    parts = token.split(".")
    if len(parts) != 3 or parts[0] != TOKEN_PREFIX:
        raise EnrollmentTokenError("Enrollment token has an invalid format")
    encoded, signature = parts[1], parts[2]
    expected = _b64encode(hmac.new(_enrollment_key(), encoded.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(signature.encode(), expected.encode()):
        raise EnrollmentTokenError("Enrollment token signature is invalid")
    try:
        payload = json.loads(_b64decode(encoded))
    except (ValueError, json.JSONDecodeError) as exc:
        raise EnrollmentTokenError("Enrollment token payload is invalid") from exc
    if not isinstance(payload, dict) or payload.get("purpose") != "edge-enroll" or payload.get("v") != 1:
        raise EnrollmentTokenError("Enrollment token purpose is invalid")
    org_id = payload.get("org_id")
    jti = payload.get("jti")
    exp = payload.get("exp")
    if not isinstance(org_id, str) or not isinstance(jti, str) or not isinstance(exp, int):
        raise EnrollmentTokenError("Enrollment token claims are invalid")
    try:
        UUID(org_id)
    except ValueError as exc:
        raise EnrollmentTokenError("Enrollment token organization is invalid") from exc
    if exp <= int(utcnow().timestamp()):
        raise EnrollmentTokenError("Enrollment token has expired")
    return {"org_id": UUID(org_id), "jti": jti, "exp": exp}


def generate_gateway_secret() -> str:
    return secrets.token_urlsafe(32)


def token_sha256(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def build_signature_message(timestamp: str, method: str, path: str, body: bytes) -> bytes:
    digest = hashlib.sha256(body).hexdigest()
    return f"{timestamp}\n{method.upper()}\n{path}\n{digest}".encode()


def compute_signature(secret: str, timestamp: str, method: str, path: str, body: bytes) -> str:
    return hmac.new(secret.encode(), build_signature_message(timestamp, method, path, body), hashlib.sha256).hexdigest()


def verify_signature(
    secret: str,
    timestamp: str | None,
    signature: str | None,
    method: str,
    path: str,
    body: bytes,
) -> bool:
    if not secret or not timestamp or not signature:
        return False
    if not timestamp.isdigit() or len(timestamp) > 20:
        return False
    skew = abs(int(utcnow().timestamp()) - int(timestamp))
    if skew > SIGNATURE_MAX_SKEW_SECONDS:
        return False
    normalized = signature.strip()
    if normalized.lower().startswith("sha256="):
        normalized = normalized.split("=", 1)[1]
    if len(normalized) != 64:
        return False
    expected = compute_signature(secret, timestamp, method, path, body)
    return hmac.compare_digest(normalized.lower().encode(), expected.encode())


def sign_config_bundle(secret: str, bundle: dict[str, Any]) -> str:
    return hmac.new(secret.encode(), canonical_json(bundle), hashlib.sha256).hexdigest()


def sanitize_config(config: dict[str, Any] | None) -> dict[str, Any]:
    """Strip internal secret material before any client-facing serialization."""
    if not isinstance(config, dict):
        return {}
    return {key: value for key, value in config.items() if not str(key).startswith("_")}


def attach_secret(config: dict[str, Any], encrypted_secret: str) -> dict[str, Any]:
    updated = dict(config or {})
    updated[_INTERNAL_CONFIG_KEY] = {"hmac_secret_encrypted": encrypted_secret}
    return updated


def gateway_secret_ciphertext(config: dict[str, Any] | None) -> str | None:
    if not isinstance(config, dict):
        return None
    internal = config.get(_INTERNAL_CONFIG_KEY)
    if not isinstance(internal, dict):
        return None
    ciphertext = internal.get("hmac_secret_encrypted")
    return ciphertext if isinstance(ciphertext, str) and ciphertext else None


def enrollment_blob(token_hash: str, jti: str, expires_at: datetime) -> dict[str, Any]:
    return {_ENROLLMENT_KEY: {"token_hash": token_hash, "jti": jti, "expires_at": expires_at.isoformat()}}


def read_enrollment(gateway_config: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(gateway_config, dict):
        return None
    blob = gateway_config.get(_ENROLLMENT_KEY)
    return blob if isinstance(blob, dict) else None


DEFAULT_GATEWAY_CONFIG: dict[str, Any] = {
    "buffer_max_events": 50_000,
    "batch_size": 200,
    "flush_interval_seconds": 30,
    "heartbeat_interval_seconds": 60,
    "log_level": "info",
    "collectors": ["syslog", "network", "ot", "iot"],
    "store_forward": True,
    "allow_remote_config": True,
    "tags": [],
}


__all__ = [
    "DEFAULT_GATEWAY_CONFIG",
    "ENROLLMENT_TTL_SECONDS",
    "SIGNATURE_MAX_SKEW_SECONDS",
    "EnrollmentTokenError",
    "attach_secret",
    "build_signature_message",
    "canonical_json",
    "compute_signature",
    "enrollment_blob",
    "gateway_secret_ciphertext",
    "generate_gateway_secret",
    "issue_enrollment_token",
    "read_enrollment",
    "sanitize_config",
    "sign_config_bundle",
    "token_sha256",
    "verify_enrollment_token",
    "verify_signature",
]
