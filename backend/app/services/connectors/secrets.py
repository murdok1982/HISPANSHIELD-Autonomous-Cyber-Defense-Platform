"""Connector secret handling helpers (redaction, readiness, error scrubbing).

Plaintext credentials exist only inside an adapter instance for the duration of a
call. This module centralises the operations needed to keep them out of API
responses, audit payloads, run records and error messages.
"""

from __future__ import annotations

from typing import Any

from app.models.connectors import Connector

_REDACT_KEYS = (
    "secret",
    "password",
    "passwd",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "client_secret",
    "private_key",
    "hmac",
    "credential",
    "cookie",
    "session_key",
)

REDACTED = "[redacted]"


def _is_sensitive(key: Any) -> bool:
    lowered = str(key).lower()
    return any(marker in lowered for marker in _REDACT_KEYS)


def redact_config(value: Any, *, depth: int = 0) -> Any:
    """Recursively redact secret-bearing configuration keys before serialization."""
    if depth > 6:
        return "[truncated]"
    if isinstance(value, dict):
        return {
            str(key): REDACTED if _is_sensitive(key) else redact_config(item, depth=depth + 1)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_config(item, depth=depth + 1) for item in value[:100]]
    if isinstance(value, str) and len(value) > 2000:
        return value[:2000] + "…"
    return value


def has_secret(connector: Connector) -> bool:
    return bool(connector.secret_encrypted)


def scrub_secret(text: str | None, *candidates: str | None) -> str | None:
    """Remove any known plaintext credential from an error/log string."""
    if not text:
        return None
    scrubbed = text
    for candidate in candidates:
        if candidate and len(candidate) >= 3:
            scrubbed = scrubbed.replace(candidate, REDACTED)
    return scrubbed[:2000] or None


def auth_is_configured(auth_type: str, secret_present: bool, config: dict[str, Any]) -> bool:
    """Whether enough credential material exists to attempt an authenticated call."""
    if auth_type in {"none"}:
        return True
    if auth_type == "hmac":
        return secret_present
    if auth_type in {"basic", "bearer", "api_key", "api_key_header", "token_header", "client_credentials", "password"}:
        return secret_present or bool(config.get("username"))
    return secret_present


def config_secret_values(config: dict[str, Any] | None) -> list[str]:
    """Return plaintext values stored under sensitive config keys (for scrubbing)."""
    values: list[str] = []
    if not isinstance(config, dict):
        return values
    for key, item in config.items():
        if _is_sensitive(key) and isinstance(item, str) and len(item) >= 3:
            values.append(item)
    return values


__all__ = [
    "REDACTED",
    "auth_is_configured",
    "config_secret_values",
    "has_secret",
    "redact_config",
    "scrub_secret",
]
