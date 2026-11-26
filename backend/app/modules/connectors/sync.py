"""Idempotent read-synchronisation from connectors into the event/indicator fabric."""

from __future__ import annotations

from datetime import UTC, datetime
from time import perf_counter
from typing import Any

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.core.errors import ServiceUnavailable, ValidationFailure
from app.models.connectors import Connector
from app.models.events import SecurityEvent
from app.models.ti import ThreatIndicator
from app.modules.connectors.schemas import ConnectorSyncResultOut
from app.services.connectors.base import ConnectorAdapter, ConnectorError, record_connector_run
from app.services.connectors.normalize import normalize_alert, normalize_indicator, sanitize_mapping
from app.services.connectors.runtime import circuit_breaker, instantiate_adapter
from app.services.connectors.secrets import config_secret_values, scrub_secret

READ_ALERT_CAPABILITIES = ("read_alerts", "read_events")


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _adapter_notes(adapter: ConnectorAdapter, connector: Connector) -> list[str]:
    values = [getattr(adapter, "secret", None), *config_secret_values(connector.config)]
    return [value for value in values if isinstance(value, str) and len(value) >= 3]


def _existing_event_keys(db: Session, connector: Connector, keys: set[str]) -> set[str]:
    if not keys:
        return set()
    rows = db.execute(
        select(SecurityEvent.dedupe_key).where(
            SecurityEvent.org_id == connector.org_id, SecurityEvent.dedupe_key.in_(keys)
        )
    ).scalars()
    return {str(key) for key in rows if key}


def _merge_indicator(existing: ThreatIndicator, data: dict[str, Any]) -> None:
    new_last_seen = _aware(data.get("last_seen")) or utcnow()
    current_last_seen = _aware(existing.last_seen) or new_last_seen
    existing.last_seen = max(current_last_seen, new_last_seen)
    new_first_seen = _aware(data.get("first_seen")) or new_last_seen
    current_first_seen = _aware(existing.first_seen) or new_first_seen
    existing.first_seen = min(current_first_seen, new_first_seen)
    existing.confidence = max(existing.confidence or 0, int(data.get("confidence") or 0))
    existing.severity = data.get("severity") or existing.severity
    existing.active = bool(data.get("active", existing.active))
    if data.get("description"):
        existing.description = data["description"]
    tags = list(existing.tags or [])
    for tag in data.get("tags") or []:
        if tag not in tags:
            tags.append(tag)
    existing.tags = tags[:20]
    expires_at = _aware(data.get("expires_at"))
    if expires_at is not None:
        existing.expires_at = expires_at
    if data.get("stix"):
        existing.stix = data["stix"]


def _persist_indicators(db: Session, connector: Connector, indicators: list[dict[str, Any]]) -> tuple[int, int]:
    created = 0
    updated = 0
    for data in indicators:
        indicator_type = data["indicator_type"]
        value = data["value"]
        existing = db.execute(
            select(ThreatIndicator).where(
                ThreatIndicator.org_id == connector.org_id,
                ThreatIndicator.indicator_type == indicator_type,
                ThreatIndicator.value == value,
            )
        ).scalar_one_or_none()
        if existing is not None:
            _merge_indicator(existing, data)
            updated += 1
            continue
        record = ThreatIndicator(org_id=connector.org_id, **data)
        try:
            with db.begin_nested():
                db.add(record)
            created += 1
        except IntegrityError:
            # A concurrent sync inserted the same natural key first; merge instead.
            if record in db:
                db.expunge(record)
            existing = db.execute(
                select(ThreatIndicator).where(
                    ThreatIndicator.org_id == connector.org_id,
                    ThreatIndicator.indicator_type == indicator_type,
                    ThreatIndicator.value == value,
                )
            ).scalar_one_or_none()
            if existing is not None:
                _merge_indicator(existing, data)
                updated += 1
    return created, updated


def run_sync(
    db: Session,
    connector: Connector,
    *,
    limit: int,
    request_id: str | None = None,
) -> ConnectorSyncResultOut:
    """Poll a read-only connector and upsert normalized events/indicators.

    Dedupe is deterministic (vendor identifier + timestamp + signal), so running
    the sync twice produces zero new rows. On failure the run is recorded and
    committed before the error is surfaced, so the UI always sees the failure.
    """
    if not 1 <= limit <= 200:
        raise ValidationFailure([{"field": "limit", "message": "limit must be between 1 and 200"}])

    breaker_key = f"connector:{connector.id}"
    circuit_breaker.check(breaker_key)
    adapter = instantiate_adapter(connector)
    declared = {spec.name for spec in adapter.capabilities}
    alert_capability = next((name for name in READ_ALERT_CAPABILITIES if name in declared), None)
    supports_indicators = "read_indicators" in declared
    if alert_capability is None and not supports_indicators:
        raise ValidationFailure(
            [{"field": "connector_type", "message": "This connector exposes no readable event or indicator capability"}]
        )

    started = perf_counter()
    capabilities_used: list[str] = []
    try:
        event_records: list[dict[str, Any]] = []
        indicator_records: list[dict[str, Any]] = []
        if alert_capability:
            result = adapter.invoke(alert_capability, {"limit": limit})
            if not result.ok:
                raise ConnectorError(result.error or "The connector did not return alerts")
            capabilities_used.append(alert_capability)
            for item in (result.data.get("items") or [])[:limit]:
                if not isinstance(item, dict):
                    continue
                event = normalize_alert(connector.connector_type, item, connector_name=connector.name)
                if event is not None:
                    event_records.append(event)
        if supports_indicators:
            result = adapter.invoke("read_indicators", {"limit": limit})
            if not result.ok:
                raise ConnectorError(result.error or "The connector did not return indicators")
            capabilities_used.append("read_indicators")
            for item in (result.data.get("items") or [])[:limit]:
                if not isinstance(item, dict):
                    continue
                indicator = normalize_indicator(connector.connector_type, item, connector_name=connector.name)
                if indicator is not None:
                    indicator_records.append(indicator)
    except ConnectorError as exc:
        latency = int((perf_counter() - started) * 1000)
        circuit_breaker.record_failure(breaker_key)
        error = scrub_secret(str(exc), *_adapter_notes(adapter, connector)) or "Connector synchronisation failed"
        connector.status = "degraded"
        record_connector_run(
            db,
            connector,
            operation="sync",
            direction="read",
            status="failed",
            latency_ms=latency,
            error=error,
            detail={"capabilities": capabilities_used, "limit": limit},
            request_id=request_id,
        )
        db.commit()
        raise ServiceUnavailable("The connector synchronisation failed; see the connector audit log") from exc

    existing_keys = _existing_event_keys(db, connector, {event["dedupe_key"] for event in event_records})
    events_created = 0
    events_duplicate = 0
    for event in event_records:
        if event["dedupe_key"] in existing_keys:
            events_duplicate += 1
            continue
        db.add(SecurityEvent(org_id=connector.org_id, source_id=None, **event))
        existing_keys.add(event["dedupe_key"])
        events_created += 1
    indicators_created, indicators_updated = _persist_indicators(db, connector, indicator_records)

    latency = int((perf_counter() - started) * 1000)
    circuit_breaker.record_success(breaker_key)
    connector.status = "healthy"
    detail = {
        "capabilities": capabilities_used,
        "events_created": events_created,
        "events_duplicate": events_duplicate,
        "indicators_created": indicators_created,
        "indicators_updated": indicators_updated,
        "alerts_read": len(event_records),
        "limit": limit,
    }
    run = record_connector_run(
        db,
        connector,
        operation="sync",
        direction="read",
        status="success",
        latency_ms=latency,
        detail=sanitize_mapping(detail),
        request_id=request_id,
    )
    return ConnectorSyncResultOut(
        connector_id=connector.id,
        status="success",
        events_created=events_created,
        events_duplicate=events_duplicate,
        indicators_created=indicators_created,
        indicators_updated=indicators_updated,
        alerts_read=len(event_records),
        capabilities=capabilities_used,
        latency_ms=latency,
        run_id=run.id,
        detail={
            "events_created": events_created,
            "events_duplicate": events_duplicate,
            "indicators_created": indicators_created,
            "indicators_updated": indicators_updated,
            "capabilities": capabilities_used,
        },
    )


__all__ = ["READ_ALERT_CAPABILITIES", "run_sync"]
