"""Connector worker: idempotent health probes and read synchronisation.

Designed to be run by cron/systemd-timer or invoked manually. Every outcome is
persisted in ``connector_runs`` and the audit chain, so a crashed process loses
nothing: the next invocation re-checks health and re-runs a deduplicated sync.

Usage::

    python scripts/connector_worker.py --once
    python scripts/connector_worker.py --loop --interval 300
    python scripts/connector_worker.py --once --connector-id <uuid> --health-only
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

BACKEND_ROOT = Path(__file__).resolve().parents[1]
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from sqlalchemy import select  # noqa: E402

from app.core.audit import append_audit  # noqa: E402
from app.core.db import SessionLocal  # noqa: E402
from app.core.errors import AppError  # noqa: E402
from app.core.logging import configure_logging, get_logger  # noqa: E402
from app.models.connectors import Connector  # noqa: E402
from app.modules.connectors.service import run_health  # noqa: E402
from app.modules.connectors.sync import run_sync  # noqa: E402
from app.services.connectors.base import get_adapter_class  # noqa: E402
from app.services.connectors.runtime import circuit_breaker  # noqa: E402

logger = get_logger("hispanshield.connector_worker")

SYSTEM_ACTOR = "connector-worker"


def _audit(db, connector: Connector, action: str, outcome: str, payload: dict[str, Any], request_id: str) -> None:  # type: ignore[no-untyped-def]
    append_audit(
        db,
        org_id=connector.org_id,
        action=action,
        resource_type="connector",
        resource_id=str(connector.id),
        actor_type="system",
        actor_id=SYSTEM_ACTOR,
        outcome=outcome,
        payload=payload,
        request_id=request_id,
    )


def _can_sync(connector: Connector) -> bool:
    adapter_class = get_adapter_class(connector.connector_type)
    if adapter_class is None:
        return False
    names = {spec.name for spec in adapter_class.capabilities}
    return bool(names & {"read_alerts", "read_events", "read_indicators"})


def process_connector(db, connector: Connector, *, limit: int, health_only: bool, request_id: str) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    outcome: dict[str, Any] = {
        "connector_id": str(connector.id),
        "name": connector.name,
        "connector_type": connector.connector_type,
        "health": None,
        "sync": None,
        "ok": True,
    }
    try:
        health = run_health(db, connector, request_id=request_id)
    except AppError as exc:
        db.rollback()
        outcome["ok"] = False
        outcome["health"] = {"status": "skipped", "error": exc.message}
        _audit(
            db,
            connector,
            "connector.health",
            "failure",
            {"status": "skipped", "error": exc.message[:500]},
            request_id,
        )
        db.commit()
        return outcome
    outcome["health"] = {"status": health.status, "ok": health.ok, "latency_ms": health.latency_ms}
    _audit(
        db,
        connector,
        "connector.health",
        "success" if health.ok else "failure",
        {"status": health.status, "latency_ms": health.latency_ms, "error": health.error},
        request_id,
    )
    db.commit()
    if not health.ok:
        outcome["ok"] = False
    if health_only or not _can_sync(connector):
        return outcome

    try:
        sync_result = run_sync(db, connector, limit=limit, request_id=request_id)
    except AppError as exc:
        db.rollback()
        outcome["ok"] = False
        outcome["sync"] = {"status": "failed", "error": exc.message}
        _audit(
            db,
            connector,
            "connector.sync",
            "failure",
            {"error": exc.message[:500], "limit": limit},
            request_id,
        )
        db.commit()
        return outcome
    outcome["sync"] = {
        "status": sync_result.status,
        "events_created": sync_result.events_created,
        "events_duplicate": sync_result.events_duplicate,
        "indicators_created": sync_result.indicators_created,
        "indicators_updated": sync_result.indicators_updated,
    }
    _audit(
        db,
        connector,
        "connector.sync",
        "success",
        {
            "events_created": sync_result.events_created,
            "events_duplicate": sync_result.events_duplicate,
            "indicators_created": sync_result.indicators_created,
            "indicators_updated": sync_result.indicators_updated,
            "capabilities": sync_result.capabilities,
        },
        request_id,
    )
    db.commit()
    return outcome


def run_once(
    *,
    org_id: UUID | None,
    connector_id: UUID | None,
    limit: int,
    health_only: bool,
) -> list[dict[str, Any]]:
    request_id = f"worker:{uuid4()}"
    results: list[dict[str, Any]] = []
    with SessionLocal() as db:
        stmt = select(Connector).where(Connector.enabled.is_(True), Connector.status != "disabled")
        if org_id is not None:
            stmt = stmt.where(Connector.org_id == org_id)
        if connector_id is not None:
            stmt = stmt.where(Connector.id == connector_id)
        connectors = list(db.execute(stmt.order_by(Connector.name.asc())).scalars())
        for connector in connectors:
            try:
                results.append(
                    process_connector(
                        db, connector, limit=limit, health_only=health_only, request_id=request_id
                    )
                )
            except Exception as exc:  # pragma: no cover - last-resort worker isolation
                db.rollback()
                logger.exception("connector_worker_unhandled", extra={"extra_fields": {"connector": str(connector.id)}})
                results.append(
                    {
                        "connector_id": str(connector.id),
                        "name": connector.name,
                        "connector_type": connector.connector_type,
                        "health": None,
                        "sync": None,
                        "ok": False,
                        "error": exc.__class__.__name__,
                    }
                )
    return results


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="HISPANSHIELD connector worker")
    parser.add_argument("--once", action="store_true", help="Run a single pass (default)")
    parser.add_argument("--loop", action="store_true", help="Run continuously")
    parser.add_argument("--interval", type=int, default=300, help="Seconds between passes in loop mode")
    parser.add_argument("--org-id", type=UUID, default=None, help="Restrict to one organization")
    parser.add_argument("--connector-id", type=UUID, default=None, help="Restrict to one connector")
    parser.add_argument("--limit", type=int, default=100, help="Maximum records per read (1-200)")
    parser.add_argument("--health-only", action="store_true", help="Skip synchronisation")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    if not 1 <= args.limit <= 200:
        logger.error("invalid_limit", extra={"extra_fields": {"limit": args.limit}})
        return 2
    configure_logging()
    failed = False
    while True:
        results = run_once(
            org_id=args.org_id,
            connector_id=args.connector_id,
            limit=args.limit,
            health_only=args.health_only,
        )
        failed = any(not item["ok"] for item in results)
        logger.info(
            "connector_pass_complete",
            extra={
                "extra_fields": {
                    "connectors": len(results),
                    "failed": sum(1 for item in results if not item["ok"]),
                    "circuit_open": circuit_breaker.snapshot()["open"],
                }
            },
        )
        for item in results:
            logger.info("connector_result", extra={"extra_fields": item})
        if not args.loop:
            break
        time.sleep(max(10, args.interval))
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
