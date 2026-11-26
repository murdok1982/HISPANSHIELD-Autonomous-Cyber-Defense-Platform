"""Connector runtime: secret decryption, adapter instantiation and circuit breaking."""

from __future__ import annotations

import threading
import time
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.crypto import decrypt_secret
from app.core.errors import ServiceUnavailable
from app.models.connectors import Connector
from app.services.connectors.base import (
    ConnectorAdapter,
    connector_types_with_capability,
    get_adapter_class,
)

_FAILURE_THRESHOLD = 5
_COOLDOWN_SECONDS = 120


class CircuitBreaker:
    """Per-process circuit breaker. Durable health is persisted on the connector."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._failures: dict[str, int] = {}
        self._opened_at: dict[str, float] = {}

    def check(self, key: str) -> None:
        with self._lock:
            opened = self._opened_at.get(key)
            if opened and time.time() - opened < _COOLDOWN_SECONDS:
                raise ServiceUnavailable("Connector circuit breaker is open; retry later")
            if opened:
                self._opened_at.pop(key, None)
                self._failures[key] = 0

    def record_success(self, key: str) -> None:
        with self._lock:
            self._failures.pop(key, None)
            self._opened_at.pop(key, None)

    def record_failure(self, key: str) -> None:
        with self._lock:
            failures = self._failures.get(key, 0) + 1
            self._failures[key] = failures
            if failures >= _FAILURE_THRESHOLD:
                self._opened_at[key] = time.time()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "failures": dict(self._failures),
                "open": sorted(self._opened_at.keys()),
                "cooldown_seconds": _COOLDOWN_SECONDS,
                "threshold": _FAILURE_THRESHOLD,
            }


circuit_breaker = CircuitBreaker()


def connector_secret(connector: Connector) -> str | None:
    if not connector.secret_encrypted:
        return None
    try:
        return decrypt_secret(connector.secret_encrypted)
    except ValueError as exc:
        raise ServiceUnavailable("Connector credentials cannot be decrypted; re-enter them") from exc


def instantiate_adapter(connector: Connector) -> ConnectorAdapter:
    adapter_class = get_adapter_class(connector.connector_type)
    if adapter_class is None:
        raise ServiceUnavailable(f"No adapter installed for connector type: {connector.connector_type}")
    if not connector.enabled:
        raise ServiceUnavailable("Connector is disabled")
    return adapter_class(connector, connector_secret(connector))


def select_connector(
    db: Session,
    org_id,
    capability: str,
    *,
    connector_id=None,  # type: ignore[no-untyped-def]
) -> Connector:
    if connector_id is not None:
        connector = db.get(Connector, connector_id)
        if connector is None or connector.org_id != org_id:
            raise ServiceUnavailable("Requested connector is not available in this organization")
        if not connector.enabled or connector.status == "disabled":
            raise ServiceUnavailable("Requested connector is disabled")
        adapter_class = get_adapter_class(connector.connector_type)
        if adapter_class is None or not any(spec.name == capability for spec in adapter_class.capabilities):
            raise ServiceUnavailable("Requested connector does not support this capability")
        return connector

    types = connector_types_with_capability(capability)
    if not types:
        raise ServiceUnavailable("No installed connector adapter supports this capability")
    candidates = list(
        db.execute(
            select(Connector).where(
                Connector.org_id == org_id,
                Connector.enabled.is_(True),
                Connector.connector_type.in_(types),
            )
        ).scalars()
    )
    if not candidates:
        raise ServiceUnavailable("No configured connector supports this capability")
    healthy = [c for c in candidates if c.status == "healthy"]
    return (healthy or candidates)[0]


__all__ = ["CircuitBreaker", "circuit_breaker", "connector_secret", "instantiate_adapter", "select_connector"]
