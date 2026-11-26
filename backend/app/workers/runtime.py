"""Durable background worker runtime.

Runs the parts of the platform that must not depend on an HTTP request:

* the playbook engine (durable executions, lease-safe claiming);
* the connector scheduler (read-only polling with deterministic dedupe).

The process is deliberately small and signal-aware so it can run as a separate
container/deployment. ``--once`` executes a single pass and exits, which is used
by integration tests and by cron-style deployments.
"""

from __future__ import annotations

import argparse
import signal
import threading
import time
from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import SessionLocal, utcnow
from app.core.idempotency import purge_expired_records
from app.core.logging import configure_logging, get_logger
from app.models.connectors import Connector
from app.modules.connectors.sync import run_sync
from app.services.outbox import dispatch_once as dispatch_outbox_once
from app.services.playbook_engine import worker_run_once

logger = get_logger("hispanshield.worker")

PLAYBOOK_INTERVAL_SECONDS = 2.0
OUTBOX_INTERVAL_SECONDS = 1.0
SCHEDULER_INTERVAL_SECONDS = 30.0
DEFAULT_SYNC_INTERVAL_MINUTES = 15
DEFAULT_SYNC_LIMIT = 100
MAX_CONNECTORS_PER_PASS = 20


@dataclass
class WorkerStats:
    playbook_passes: int = 0
    playbook_processed: int = 0
    playbook_failed: int = 0
    connector_passes: int = 0
    connector_synced: int = 0
    connector_failed: int = 0
    outbox_passes: int = 0
    outbox_processed: int = 0
    outbox_failed: int = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "playbook_passes": self.playbook_passes,
            "playbook_processed": self.playbook_processed,
            "playbook_failed": self.playbook_failed,
            "connector_passes": self.connector_passes,
            "connector_synced": self.connector_synced,
            "connector_failed": self.connector_failed,
            "outbox_passes": self.outbox_passes,
            "outbox_processed": self.outbox_processed,
            "outbox_failed": self.outbox_failed,
        }


class StopFlag:
    def __init__(self) -> None:
        self._event = threading.Event()

    def request(self, *_args: Any) -> None:  # type: ignore[no-untyped-def]
        self._event.set()

    @property
    def stopped(self) -> bool:
        return self._event.is_set()

    def wait(self, seconds: float) -> bool:
        return self._event.wait(seconds)


def run_playbooks_once(db: Session, *, limit: int = 20) -> dict[str, Any]:
    result = worker_run_once(db, limit=limit)
    db.commit()
    return result


def _sync_interval(connector: Connector) -> timedelta:
    config = connector.config if isinstance(connector.config, dict) else {}
    raw = config.get("sync_interval_minutes", DEFAULT_SYNC_INTERVAL_MINUTES)
    try:
        minutes = int(raw)
    except (TypeError, ValueError):
        minutes = DEFAULT_SYNC_INTERVAL_MINUTES
    minutes = max(1, min(minutes, 24 * 60))
    return timedelta(minutes=minutes)


def due_connectors(db: Session, *, now=None, limit: int = MAX_CONNECTORS_PER_PASS) -> list[Connector]:
    """Select enabled connectors whose last successful sync is older than their interval."""
    moment = now or utcnow()
    rows = list(
        db.execute(
            select(Connector)
            .where(
                Connector.enabled.is_(True),
                Connector.status != "unconfigured",
                or_(Connector.last_success_at.is_(None), Connector.last_success_at < moment),
            )
            .order_by(Connector.last_success_at.asc().nullsfirst())
            .limit(max(1, limit * 4))
        ).scalars()
    )
    due: list[Connector] = []
    for connector in rows:
        if connector.last_success_at is None or connector.last_success_at <= moment - _sync_interval(connector):
            due.append(connector)
            if len(due) >= limit:
                break
    return due


def sync_connectors_once(db: Session, *, now=None, limit: int = MAX_CONNECTORS_PER_PASS) -> dict[str, Any]:
    synced = 0
    failed = 0
    for connector in due_connectors(db, now=now, limit=limit):
        config = connector.config if isinstance(connector.config, dict) else {}
        try:
            batch = int(config.get("sync_limit", DEFAULT_SYNC_LIMIT))
        except (TypeError, ValueError):
            batch = DEFAULT_SYNC_LIMIT
        batch = max(1, min(batch, 200))
        try:
            run_sync(db, connector, limit=batch, request_id="worker:connector-sync")
            synced += 1
        except Exception as exc:  # noqa: BLE001 - one broken connector must not stop the pass
            db.rollback()
            failed += 1
            logger.warning(
                "connector_sync_failed",
                extra={"extra_fields": {"connector_id": str(connector.id), "error": str(exc)[:300]}},
            )
    return {"synced": synced, "failed": failed}


def run_outbox_once(db: Session, *, limit: int = 100) -> dict[str, int]:
    result = dispatch_outbox_once(db, limit=limit, worker_id="worker:outbox")
    purge_expired_records(db)
    return {key: int(value) for key, value in result.items()}


def run_forever(stop: StopFlag, stats: WorkerStats, *, role: str = "all") -> None:
    next_playbooks = 0.0
    next_scheduler = 0.0
    next_outbox = 0.0
    while not stop.stopped:
        now = time.monotonic()
        if role in {"all", "playbooks"} and now >= next_playbooks:
            try:
                with SessionLocal() as db:
                    result = run_playbooks_once(db)
                stats.playbook_passes += 1
                stats.playbook_processed += int(result.get("processed", 0))
                stats.playbook_failed += int(result.get("failed", 0))
            except Exception as exc:  # noqa: BLE001 - loop must survive transient DB errors
                logger.error("playbook_pass_failed", extra={"extra_fields": {"error": str(exc)[:300]}})
            next_playbooks = time.monotonic() + PLAYBOOK_INTERVAL_SECONDS

        if role in {"all", "outbox"} and now >= next_outbox:
            try:
                with SessionLocal() as db:
                    result = run_outbox_once(db)
                stats.outbox_passes += 1
                stats.outbox_processed += int(result.get("processed", 0))
                stats.outbox_failed += int(result.get("retried", 0)) + int(result.get("dead_lettered", 0))
            except Exception as exc:  # noqa: BLE001 - loop must survive transient DB errors
                logger.error("outbox_pass_failed", extra={"extra_fields": {"error": str(exc)[:300]}})
            next_outbox = time.monotonic() + OUTBOX_INTERVAL_SECONDS

        if role in {"all", "connectors"} and now >= next_scheduler:
            try:
                with SessionLocal() as db:
                    result = sync_connectors_once(db)
                stats.connector_passes += 1
                stats.connector_synced += int(result.get("synced", 0))
                stats.connector_failed += int(result.get("failed", 0))
            except Exception as exc:  # noqa: BLE001
                logger.error("connector_pass_failed", extra={"extra_fields": {"error": str(exc)[:300]}})
            next_scheduler = time.monotonic() + SCHEDULER_INTERVAL_SECONDS

        stop.wait(0.5)

    logger.info("worker_stopped", extra={"extra_fields": stats.as_dict()})


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="HISPANSHIELD durable worker")
    parser.add_argument("--role", choices=["all", "playbooks", "connectors", "outbox"], default="all")
    parser.add_argument("--once", action="store_true", help="run a single pass and exit")
    args = parser.parse_args(argv)

    configure_logging(settings.log_level)
    stop = StopFlag()
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, stop.request)

    if args.once:
        stats = WorkerStats()
        with SessionLocal() as db:
            if args.role in {"all", "playbooks"}:
                result = run_playbooks_once(db)
                stats.playbook_passes += 1
                stats.playbook_processed += int(result.get("processed", 0))
                stats.playbook_failed += int(result.get("failed", 0))
            if args.role in {"all", "outbox"}:
                result = run_outbox_once(db)
                stats.outbox_passes += 1
                stats.outbox_processed += int(result.get("processed", 0))
                stats.outbox_failed += int(result.get("retried", 0)) + int(result.get("dead_lettered", 0))
            if args.role in {"all", "connectors"}:
                result = sync_connectors_once(db)
                stats.connector_passes += 1
                stats.connector_synced += int(result.get("synced", 0))
                stats.connector_failed += int(result.get("failed", 0))
        logger.info("worker_once", extra={"extra_fields": stats.as_dict()})
        return 0

    logger.info("worker_started", extra={"extra_fields": {"role": args.role}})
    run_forever(stop, WorkerStats(), role=args.role)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
