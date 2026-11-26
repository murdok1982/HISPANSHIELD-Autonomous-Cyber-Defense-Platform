"""Connector registry domain services: manifests, validation, probing and health."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from time import perf_counter
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import utcnow
from app.core.errors import NotFound, ServiceUnavailable, ValidationFailure
from app.core.ssrf import SSRFError, validate_outbound_url
from app.models.connectors import Connector, ConnectorRun
from app.modules.connectors.schemas import (
    CapabilityOut,
    CatalogAdapterOut,
    ConnectorCatalogOut,
    ConnectorHealthOut,
    ConnectorHealthResultOut,
    ConnectorHealthSummaryOut,
    ConnectorInvokeResultOut,
    ConnectorOut,
)
from app.services.connectors.adapters import ADAPTER_MODULES  # noqa: F401  (ensures registration)
from app.services.connectors.base import (
    READ,
    AdapterResult,
    ConnectorAdapter,
    ConnectorError,
    adapter_catalog,
    get_adapter_class,
    record_connector_run,
)
from app.services.connectors.runtime import circuit_breaker, instantiate_adapter
from app.services.connectors.secrets import config_secret_values, redact_config, scrub_secret

STALE_AFTER_MINUTES = 60
MAX_ERROR_LENGTH = 2000
MAX_RESULT_ITEMS = 200


def get_connector(db: Session, org_id: UUID, connector_id: UUID) -> Connector:
    connector = db.get(Connector, connector_id)
    if connector is None or connector.org_id != org_id:
        # Cross-tenant identifiers are indistinguishable from missing rows.
        raise NotFound("Connector")
    return connector


def is_stale(connector: Connector, *, now: datetime | None = None) -> bool:
    if not connector.enabled:
        return False
    reference = now or utcnow()
    last_health = connector.last_health_at
    if last_health is None:
        return True
    if last_health.tzinfo is None:
        last_health = last_health.replace(tzinfo=UTC)
    return last_health < reference - timedelta(minutes=STALE_AFTER_MINUTES)


def circuit_open(connector_id: UUID) -> bool:
    return f"connector:{connector_id}" in circuit_breaker.snapshot()["open"]


def capability_manifest(adapter_class: type[ConnectorAdapter]) -> dict[str, Any]:
    """Copy the adapter's declaration into the connector row at creation time."""
    capabilities = tuple(adapter_class.capabilities)
    return {
        "items": [
            {
                "name": spec.name,
                "direction": spec.direction,
                "description": spec.description,
                "risk": spec.risk,
                "requires_approval": spec.requires_approval,
                "data_formats": list(spec.data_formats),
            }
            for spec in capabilities
        ],
        "read": [spec.name for spec in capabilities if spec.direction == READ],
        "write": [spec.name for spec in capabilities if spec.direction != READ],
        "auth_methods": list(adapter_class.auth_methods),
        "data_formats": list(adapter_class.data_formats),
        "security_profile": adapter_class.security_profile,
        "version": adapter_class.version,
    }


def serialize_connector(connector: Connector) -> ConnectorOut:
    state = connector.status
    if not connector.enabled:
        state = "disabled"
    return ConnectorOut(
        id=connector.id,
        name=connector.name,
        connector_type=connector.connector_type,
        version=connector.version,
        base_url=connector.base_url,
        auth_type=connector.auth_type,
        has_secret=bool(connector.secret_encrypted),
        config=redact_config(connector.config or {}),
        capabilities=connector.capabilities or {},
        status=state,
        enabled=connector.enabled,
        verify_tls=connector.verify_tls,
        rate_limit_per_minute=connector.rate_limit_per_minute,
        last_health_at=connector.last_health_at,
        last_success_at=connector.last_success_at,
        last_error=scrub_secret(connector.last_error, *config_secret_values(connector.config)),
        created_by=connector.created_by,
        created_at=connector.created_at,
        updated_at=connector.updated_at,
        health=ConnectorHealthOut(
            state=state,
            stale=is_stale(connector),
            circuit_open=circuit_open(connector.id),
            last_health_at=connector.last_health_at,
            last_success_at=connector.last_success_at,
            last_error=scrub_secret(connector.last_error, *config_secret_values(connector.config)),
        ),
    )


def _validation_error(field: str, message: str) -> ValidationFailure:
    return ValidationFailure([{"field": field, "message": message}])


def validate_configuration(
    adapter_class: type[ConnectorAdapter],
    *,
    base_url: str | None,
    auth_type: str,
    config: dict[str, Any],
    verify_tls: bool,
) -> None:
    requires_base_url = bool(getattr(adapter_class, "requires_base_url", True))
    file_based = bool(getattr(adapter_class, "file_based", False))
    if not verify_tls and settings.env not in {"development", "test"}:
        raise _validation_error("verify_tls", "TLS verification can only be disabled in development or test")
    if file_based:
        if base_url:
            raise _validation_error("base_url", "File-based connectors must not define a network base URL")
    elif requires_base_url and not base_url:
        raise _validation_error("base_url", "This connector type requires a base URL")
    if base_url:
        try:
            validate_outbound_url(base_url)
        except SSRFError as exc:
            raise _validation_error("base_url", str(exc)) from exc
        if settings.is_production and not base_url.lower().startswith("https://"):
            raise _validation_error("base_url", "Connectors must use HTTPS in production")
    if auth_type not in adapter_class.auth_methods:
        raise _validation_error(
            "auth_type",
            f"Adapter '{adapter_class.connector_type}' supports: {', '.join(adapter_class.auth_methods)}",
        )
    try:
        adapter_class.validate_config(config)  # type: ignore[attr-defined]
    except ConnectorError as exc:
        raise _validation_error("config", str(exc)) from exc


def initial_status(
    adapter_class: type[ConnectorAdapter], *, auth_type: str, has_secret: bool, config: dict[str, Any], enabled: bool
) -> str:
    if not enabled:
        return "disabled"
    needs_secret = auth_type not in {"none"} and not has_secret and not config.get("username")
    return "unconfigured" if needs_secret else "unknown"


def _known_secrets(connector: Connector, adapter: ConnectorAdapter) -> list[str]:
    values = [getattr(adapter, "secret", None), *config_secret_values(connector.config)]
    return [value for value in values if value]


def bounded_result_data(data: dict[str, Any] | None) -> dict[str, Any]:
    """Cap adapter output before it reaches the API or a run record."""
    if not isinstance(data, dict):
        return {}

    def _bound(value: Any, depth: int = 0) -> Any:
        if depth > 5:
            return "[truncated]"
        if isinstance(value, dict):
            return {str(key)[:80]: _bound(item, depth + 1) for key, item in list(value.items())[:100]}
        if isinstance(value, list):
            return [_bound(item, depth + 1) for item in value[:MAX_RESULT_ITEMS]]
        if isinstance(value, str):
            return value[:4000]
        if isinstance(value, int | float | bool) or value is None:
            return value
        return str(value)[:1000]

    bounded = _bound(data)
    return bounded if isinstance(bounded, dict) else {"items": bounded}


def run_health(db: Session, connector: Connector, *, request_id: str | None = None) -> ConnectorHealthResultOut:
    breaker_key = f"connector:{connector.id}"
    circuit_breaker.check(breaker_key)
    started = perf_counter()
    adapter: ConnectorAdapter | None = None
    try:
        adapter = instantiate_adapter(connector)
        result = adapter.health_check()
    except ConnectorError as exc:
        latency = int((perf_counter() - started) * 1000)
        circuit_breaker.record_failure(breaker_key)
        secret_values = (
            _known_secrets(connector, adapter) if adapter is not None else config_secret_values(connector.config)
        )
        error = scrub_secret(str(exc), *secret_values) or "Health check failed"
        connector.status = "unhealthy"
        run = record_connector_run(
            db,
            connector,
            operation="health_check",
            direction="read",
            status="failed",
            latency_ms=latency,
            error=error,
            detail={"capability": "health"},
            request_id=request_id,
        )
        return ConnectorHealthResultOut(
            connector_id=connector.id,
            status="unhealthy",
            ok=False,
            latency_ms=latency,
            detail={},
            error=error,
            run_id=run.id,
            last_health_at=connector.last_health_at,
        )

    latency = int((perf_counter() - started) * 1000)
    if result.ok:
        circuit_breaker.record_success(breaker_key)
        connector.status = "healthy"
        run_status = "success"
    else:
        circuit_breaker.record_failure(breaker_key)
        connector.status = "degraded"
        run_status = "failed"
    scrubbed_error = scrub_secret(result.error, *_known_secrets(connector, adapter))
    run = record_connector_run(
        db,
        connector,
        operation="health_check",
        direction="read",
        status=run_status,
        latency_ms=latency,
        error=scrubbed_error,
        detail={"capability": "health", "result": bounded_result_data(result.data)},
        request_id=request_id,
    )
    if not result.ok:
        connector.status = "degraded"
    return ConnectorHealthResultOut(
        connector_id=connector.id,
        status=connector.status,
        ok=result.ok,
        latency_ms=latency,
        detail=bounded_result_data(result.data),
        error=scrubbed_error,
        run_id=run.id,
        last_health_at=connector.last_health_at,
    )


def run_invoke(
    db: Session,
    connector: Connector,
    *,
    capability: str,
    params: dict[str, Any],
    request_id: str | None = None,
) -> ConnectorInvokeResultOut:
    breaker_key = f"connector:{connector.id}"
    circuit_breaker.check(breaker_key)
    started = perf_counter()
    adapter = instantiate_adapter(connector)
    try:
        result: AdapterResult = adapter.invoke(capability, params)
    except ConnectorError as exc:
        latency = int((perf_counter() - started) * 1000)
        circuit_breaker.record_failure(breaker_key)
        error = scrub_secret(str(exc), *_known_secrets(connector, adapter)) or "Connector invocation failed"
        connector.status = "degraded"
        record_connector_run(
            db,
            connector,
            operation=capability,
            direction="read",
            status="failed",
            latency_ms=latency,
            error=error,
            detail={"capability": capability},
            request_id=request_id,
        )
        db.commit()
        raise ServiceUnavailable("The connector invocation failed; see the connector audit log") from exc

    latency = int((perf_counter() - started) * 1000)
    if result.ok:
        circuit_breaker.record_success(breaker_key)
        connector.status = "healthy"
    else:
        circuit_breaker.record_failure(breaker_key)
        connector.status = "degraded"
    scrubbed_error = scrub_secret(result.error, *_known_secrets(connector, adapter))
    run = record_connector_run(
        db,
        connector,
        operation=capability,
        direction="read",
        status="success" if result.ok else "failed",
        latency_ms=latency,
        error=scrubbed_error,
        detail={"capability": capability, "status_code": result.status_code},
        request_id=request_id,
    )
    return ConnectorInvokeResultOut(
        connector_id=connector.id,
        capability=capability,
        ok=result.ok,
        status_code=result.status_code,
        data=bounded_result_data(result.data),
        error=scrubbed_error,
        latency_ms=latency,
        run_id=run.id,
    )


def build_catalog(db: Session, org_id: UUID) -> ConnectorCatalogOut:
    counts = {
        str(connector_type): int(count)
        for connector_type, count in db.execute(
            select(Connector.connector_type, func.count())
            .where(Connector.org_id == org_id)
            .group_by(Connector.connector_type)
        ).all()
    }
    adapters: list[CatalogAdapterOut] = []
    for entry in adapter_catalog():
        adapter_class = get_adapter_class(entry["connector_id"])
        if adapter_class is None:
            continue
        count = counts.get(entry["connector_id"], 0)
        adapters.append(
            CatalogAdapterOut(
                connector_id=entry["connector_id"],
                display_name=entry["display_name"],
                vendor=entry["vendor"],
                product=entry["product"],
                version=entry["version"],
                auth_methods=list(entry["auth_methods"]),
                capabilities=[CapabilityOut(**capability) for capability in entry["capabilities"]],
                data_formats=list(entry["data_formats"]),
                security_profile=entry["security_profile"],
                requires_base_url=bool(getattr(adapter_class, "requires_base_url", True)),
                file_based=bool(getattr(adapter_class, "file_based", False)),
                configured=count > 0,
                connector_count=count,
            )
        )
    configured = [adapter.connector_id for adapter in adapters if adapter.configured]
    missing = [adapter.connector_id for adapter in adapters if not adapter.configured]
    return ConnectorCatalogOut(
        adapters=adapters,
        configured=configured,
        missing=missing,
        unconfigured=missing,
        generated_at=utcnow(),
    )


def build_health_summary(db: Session, org_id: UUID) -> ConnectorHealthSummaryOut:
    connectors = list(
        db.execute(select(Connector).where(Connector.org_id == org_id).order_by(Connector.name.asc())).scalars()
    )
    by_status: dict[str, int] = {}
    for connector in connectors:
        state = connector.status if connector.enabled else "disabled"
        by_status[state] = by_status.get(state, 0) + 1
    now = utcnow()
    stale = [
        {
            "id": str(connector.id),
            "name": connector.name,
            "connector_type": connector.connector_type,
            "status": connector.status,
            "last_health_at": connector.last_health_at,
        }
        for connector in connectors
        if is_stale(connector, now=now)
    ]
    errors = [
        {
            "id": str(connector.id),
            "name": connector.name,
            "connector_type": connector.connector_type,
            "status": connector.status,
            "last_error": scrub_secret(connector.last_error, *config_secret_values(connector.config)),
            "last_health_at": connector.last_health_at,
        }
        for connector in connectors
        if connector.last_error
    ][:20]
    return ConnectorHealthSummaryOut(
        generated_at=now,
        total=len(connectors),
        enabled=sum(1 for connector in connectors if connector.enabled),
        by_status=by_status,
        stale_count=len(stale),
        stale=stale[:50],
        errors=errors,
        catalog_size=len(adapter_catalog()),
    )


def list_runs(
    db: Session,
    connector: Connector,
    *,
    page: int,
    page_size: int,
    operation: str | None = None,
    status: str | None = None,
) -> tuple[list[ConnectorRun], int]:
    stmt = select(ConnectorRun).where(
        ConnectorRun.connector_id == connector.id, ConnectorRun.org_id == connector.org_id
    )
    if operation:
        stmt = stmt.where(ConnectorRun.operation == operation)
    if status:
        stmt = stmt.where(ConnectorRun.status == status)
    total = db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(
        db.execute(
            stmt.order_by(ConnectorRun.created_at.desc()).offset((page - 1) * page_size).limit(page_size)
        ).scalars()
    )
    return rows, int(total)


__all__ = [
    "STALE_AFTER_MINUTES",
    "bounded_result_data",
    "build_catalog",
    "build_health_summary",
    "capability_manifest",
    "circuit_open",
    "get_connector",
    "initial_status",
    "is_stale",
    "list_runs",
    "run_health",
    "run_invoke",
    "serialize_connector",
    "validate_configuration",
]
