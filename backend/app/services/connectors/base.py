"""Universal connector framework contracts and registry.

A connector declares capabilities; write capabilities are never implied by the
existence of a read integration. Adapters are stateless classes instantiated per
call with decrypted credentials.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, ClassVar

from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.models.connectors import Connector, ConnectorRun

READ = "read"
WRITE = "write"
ADMIN = "admin"
DESTRUCTIVE = "destructive"


@dataclass(frozen=True)
class CapabilitySpec:
    name: str
    direction: str
    description: str
    risk: str = "low"
    requires_approval: bool = False
    data_formats: tuple[str, ...] = ("json",)


@dataclass
class AdapterResult:
    ok: bool
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    status_code: int | None = None
    external_id: str | None = None
    latency_ms: int = 0
    metrics: dict[str, Any] = field(default_factory=dict)


class ConnectorError(Exception):
    def __init__(self, message: str, *, retryable: bool = False, status_code: int | None = None) -> None:
        super().__init__(message)
        self.retryable = retryable
        self.status_code = status_code


class ConnectorAdapter(ABC):
    connector_type: ClassVar[str] = ""
    display_name: ClassVar[str] = ""
    vendor: ClassVar[str] = ""
    product: ClassVar[str] = ""
    version: ClassVar[str] = "1.0.0"
    auth_methods: ClassVar[tuple[str, ...]] = ("api_key",)
    capabilities: ClassVar[tuple[CapabilitySpec, ...]] = ()
    data_formats: ClassVar[tuple[str, ...]] = ("json",)
    security_profile: ClassVar[str] = "tls-required"

    def __init__(self, connector: Connector, secret: str | None) -> None:
        self.connector = connector
        self.secret = secret
        self.config: dict[str, Any] = connector.config or {}
        self.base_url: str = (connector.base_url or "").rstrip("/")

    @abstractmethod
    def health_check(self) -> AdapterResult:
        """Prove reachability and authentication with a cheap read-only call."""

    @abstractmethod
    def invoke(self, capability: str, params: dict[str, Any]) -> AdapterResult:
        """Perform a declared capability. Must raise ConnectorError on failure."""

    def verify(self, capability: str, params: dict[str, Any], result: AdapterResult) -> AdapterResult:
        """Confirm the intended effect, when the target exposes a read-back."""
        return AdapterResult(ok=True, data={"verified": True, "method": "adapter-acknowledged"})

    def rollback(self, capability: str, params: dict[str, Any], result: AdapterResult) -> AdapterResult:
        return AdapterResult(ok=False, error="Rollback is not implemented for this connector capability")

    def describe(self) -> dict[str, Any]:
        return {
            "connector_id": self.connector_type,
            "vendor": self.vendor,
            "product": self.product,
            "version": self.version,
            "protocol": "https",
            "auth_methods": list(self.auth_methods),
            "read_capabilities": [c.name for c in self.capabilities if c.direction == READ],
            "write_capabilities": [c.name for c in self.capabilities if c.direction in {WRITE, ADMIN, DESTRUCTIVE}],
            "data_formats": list(self.data_formats),
            "security_profile": self.security_profile,
            "capabilities": [
                {
                    "name": c.name,
                    "direction": c.direction,
                    "description": c.description,
                    "risk": c.risk,
                    "requires_approval": c.requires_approval,
                    "data_formats": list(c.data_formats),
                }
                for c in self.capabilities
            ],
        }


_REGISTRY: dict[str, type[ConnectorAdapter]] = {}


def register_adapter(cls: type[ConnectorAdapter]) -> type[ConnectorAdapter]:
    if not cls.connector_type:
        raise ValueError("Connector adapter must declare connector_type")
    if cls.connector_type in _REGISTRY and _REGISTRY[cls.connector_type] is not cls:
        raise ValueError(f"Duplicate connector_type registration: {cls.connector_type}")
    _REGISTRY[cls.connector_type] = cls
    return cls


def get_adapter_class(connector_type: str) -> type[ConnectorAdapter] | None:
    return _REGISTRY.get(connector_type)


def adapter_catalog() -> list[dict[str, Any]]:
    connectors = []
    for connector_type, cls in sorted(_REGISTRY.items()):
        connectors.append(
            {
                "connector_id": connector_type,
                "vendor": cls.vendor,
                "product": cls.product,
                "version": cls.version,
                "display_name": cls.display_name,
                "auth_methods": list(cls.auth_methods),
                "capabilities": [
                    {
                        "name": c.name,
                        "direction": c.direction,
                        "description": c.description,
                        "risk": c.risk,
                        "requires_approval": c.requires_approval,
                        "data_formats": list(c.data_formats),
                    }
                    for c in cls.capabilities
                ],
                "data_formats": list(cls.data_formats),
                "security_profile": cls.security_profile,
            }
        )
    return connectors


def connector_types_with_capability(capability: str) -> list[str]:
    return [
        connector_type
        for connector_type, cls in _REGISTRY.items()
        if any(spec.name == capability for spec in cls.capabilities)
    ]


def record_connector_run(
    db: Session,
    connector: Connector,
    *,
    operation: str,
    direction: str,
    status: str,
    latency_ms: int,
    error: str | None = None,
    detail: dict[str, Any] | None = None,
    request_id: str | None = None,
) -> ConnectorRun:
    run = ConnectorRun(
        connector_id=connector.id,
        org_id=connector.org_id,
        operation=operation,
        direction=direction,
        status=status,
        latency_ms=latency_ms,
        error=(error or "")[:2000] or None,
        detail=detail or {},
        request_id=request_id,
    )
    db.add(run)
    connector.last_health_at = utcnow()
    if status in {"success", "healthy"}:
        connector.last_success_at = utcnow()
        connector.last_error = None
        if connector.status in {"unconfigured", "unhealthy", "degraded"}:
            connector.status = "healthy"
    elif status in {"error", "failed", "unhealthy"}:
        connector.last_error = (error or "unknown error")[:2000]
    db.flush()
    return run


def timed(callable_):  # type: ignore[no-untyped-def]
    started = time.perf_counter()
    result = callable_()
    result.latency_ms = int((time.perf_counter() - started) * 1000)
    return result
