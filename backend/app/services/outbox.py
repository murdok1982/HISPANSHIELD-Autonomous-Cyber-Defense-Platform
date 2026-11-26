"""Transactional outbox: atomic enqueue, leased dispatch, retries and DLQ.

Guarantees
----------
* **Atomic enqueue.** ``enqueue`` only adds a row; the caller commits it in the
  same database transaction as the domain change. There is no window where the
  domain state exists without its event (or vice versa).
* **At-least-once dispatch.** A worker claims rows with ``FOR UPDATE SKIP
  LOCKED`` and a lease. If it crashes, the lease expires and another worker
  reclaims the row.
* **Idempotent consumers.** The built-in notification consumer records the
  outbox row id in ``notifications.source_event_id`` and ignores duplicates.
* **Bounded failure.** After ``max_attempts`` the row moves to ``dead_letter``
  with the last error, so a poison event cannot block the queue forever.

External side effects of future handlers must be idempotent: this module cannot
make an arbitrary HTTP call exactly-once.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.core.logging import get_logger
from app.models.core import Notification, Organization
from app.models.operations import (
    OUTBOX_DEAD_LETTER,
    OUTBOX_PENDING,
    OUTBOX_PROCESSED,
    OUTBOX_PROCESSING,
    OutboxEvent,
)

logger = get_logger("hispanshield.outbox")

LEASE_SECONDS = 60
DEFAULT_MAX_ATTEMPTS = 8


class UnhandledEventType(RuntimeError):
    """An event type reached the dispatcher without a registered consumer."""


def enqueue(
    db: Session,
    *,
    org_id: uuid.UUID,
    event_type: str,
    aggregate_type: str,
    aggregate_id: str | None = None,
    payload: dict[str, Any] | None = None,
    dedupe_key: str | None = None,
    available_at: datetime | None = None,
) -> int | None:
    """Insert an outbox row in the caller's transaction.

    Returns the event id, or ``None`` when ``dedupe_key`` already exists for the
    organization. The caller must commit for the row to become visible.
    """
    values = {
        "org_id": org_id,
        "event_type": event_type[:80],
        "aggregate_type": aggregate_type[:60],
        "aggregate_id": (str(aggregate_id)[:80] if aggregate_id else None),
        "payload": payload or {},
        "dedupe_key": (dedupe_key[:160] if dedupe_key else None),
        "status": OUTBOX_PENDING,
        "attempts": 0,
        "max_attempts": DEFAULT_MAX_ATTEMPTS,
        "available_at": available_at or utcnow(),
        "created_at": utcnow(),
    }
    if dedupe_key:
        statement = (
            pg_insert(OutboxEvent)
            .values(**values)
            .on_conflict_do_nothing(
                index_elements=["org_id", "dedupe_key"],
                index_where=text("dedupe_key IS NOT NULL"),
            )
            .returning(OutboxEvent.id)
        )
        event_id = db.execute(statement).scalar_one_or_none()
        db.flush()
        return int(event_id) if event_id is not None else None
    event = OutboxEvent(**values)
    db.add(event)
    db.flush()
    return int(event.id)


def _notification_title(event: OutboxEvent) -> str:
    payload = event.payload if isinstance(event.payload, dict) else {}
    if payload.get("title"):
        return str(payload["title"])[:240]
    return event.event_type.replace(".", " ").replace("_", " ").capitalize()[:240]


def _notification_body(event: OutboxEvent) -> str | None:
    payload = event.payload if isinstance(event.payload, dict) else {}
    for key in ("body", "summary", "message", "detail"):
        if payload.get(key):
            return str(payload[key])[:2000]
    return None


def _handle_notification(db: Session, event: OutboxEvent) -> None:
    source = str(event.id)
    exists = db.execute(
        select(Notification.id).where(
            Notification.org_id == event.org_id,
            Notification.source_event_id == source,
        )
    ).first()
    if exists is not None:
        return
    db.add(
        Notification(
            org_id=event.org_id,
            user_id=None,
            kind=event.event_type.split(".")[0][:40],
            title=_notification_title(event),
            body=_notification_body(event),
            resource_type=event.aggregate_type[:80],
            resource_id=event.aggregate_id,
            source_event_id=source,
            created_at=utcnow(),
        )
    )
    db.flush()


HANDLERS: dict[str, Callable[[Session, OutboxEvent], None]] = {
    "alert.created": _handle_notification,
    "incident.created": _handle_notification,
    "soar.execution.failed": _handle_notification,
    "soar.execution.completed": _handle_notification,
    "audit.integrity_failed": _handle_notification,
}


def _backoff_seconds(attempts: int) -> int:
    # 5s, 10s, 20s ... capped at one hour. Jitter is intentionally omitted:
    # deterministic tests are more valuable than thundering-herd smoothing for
    # a single PostgreSQL queue; workers poll with their own interval.
    return min(3600, 5 * (2 ** max(0, attempts - 1)))


def claim_events(db: Session, *, limit: int = 50, worker_id: str, now: datetime | None = None) -> list[int]:
    """Claim due rows with a lease. Returns their ids after committing the claim."""
    moment = now or utcnow()
    stmt = (
        select(OutboxEvent)
        .where(
            or_(
                (OutboxEvent.status == OUTBOX_PENDING) & (OutboxEvent.available_at <= moment),
                (OutboxEvent.status == OUTBOX_PROCESSING) & (OutboxEvent.locked_until < moment),
            )
        )
        .order_by(OutboxEvent.id.asc())
        .limit(max(1, min(limit, 200)))
        .with_for_update(skip_locked=True)
    )
    rows = list(db.execute(stmt).scalars())
    ids: list[int] = []
    for row in rows:
        row.status = OUTBOX_PROCESSING
        row.locked_until = moment + timedelta(seconds=LEASE_SECONDS)
        row.locked_by = worker_id[:80]
        row.attempts = int(row.attempts or 0) + 1
        ids.append(int(row.id))
    db.commit()
    return ids


def dispatch_once(
    db: Session,
    *,
    limit: int = 50,
    worker_id: str = "outbox:worker",
    now: datetime | None = None,
) -> dict[str, int]:
    """Dispatch one batch. Safe to call from multiple workers concurrently."""
    ids = claim_events(db, limit=limit, worker_id=worker_id, now=now)
    processed = 0
    failed = 0
    dead = 0
    for event_id in ids:
        event = db.get(OutboxEvent, event_id)
        if event is None or event.status != OUTBOX_PROCESSING:
            continue
        handler = HANDLERS.get(event.event_type)
        try:
            if handler is None:
                raise UnhandledEventType(event.event_type)
            with db.begin_nested():
                handler(db, event)
            event.status = OUTBOX_PROCESSED
            event.processed_at = utcnow()
            event.locked_until = None
            event.locked_by = None
            event.last_error = None
            db.commit()
            processed += 1
        except Exception as exc:  # noqa: BLE001 - a poison row must not stop the batch
            db.rollback()
            event = db.get(OutboxEvent, event_id)
            if event is None:
                continue
            message = f"{type(exc).__name__}: {str(exc)[:1200]}"
            event.last_error = message
            event.locked_until = None
            event.locked_by = None
            if isinstance(exc, UnhandledEventType) or int(event.attempts or 0) >= int(
                event.max_attempts or DEFAULT_MAX_ATTEMPTS
            ):
                event.status = OUTBOX_DEAD_LETTER
                dead += 1
                logger.error(
                    "outbox_dead_letter",
                    extra={"extra_fields": {"event_id": int(event.id), "type": event.event_type, "error": message}},
                )
            else:
                event.status = OUTBOX_PENDING
                event.available_at = utcnow() + timedelta(seconds=_backoff_seconds(int(event.attempts or 1)))
                failed += 1
            db.commit()
    return {"claimed": len(ids), "processed": processed, "retried": failed, "dead_lettered": dead}


def outbox_stats(db: Session, *, org_id: uuid.UUID | None = None) -> dict[str, Any]:
    stmt = select(OutboxEvent.status, func.count()).group_by(OutboxEvent.status)
    if org_id is not None:
        stmt = stmt.where(OutboxEvent.org_id == org_id)
    counts = {status: int(count) for status, count in db.execute(stmt).all()}
    oldest = db.execute(
        select(func.min(OutboxEvent.created_at)).where(OutboxEvent.status.in_([OUTBOX_PENDING, OUTBOX_PROCESSING]))
    ).scalar()
    return {
        "pending": counts.get(OUTBOX_PENDING, 0),
        "processing": counts.get(OUTBOX_PROCESSING, 0),
        "processed": counts.get(OUTBOX_PROCESSED, 0),
        "dead_letter": counts.get(OUTBOX_DEAD_LETTER, 0),
        "oldest_unprocessed_at": oldest.isoformat() if oldest else None,
    }


def ensure_org(db: Session, org_id: uuid.UUID) -> Organization | None:
    """Small helper for handlers that need the tenant; returns None if deleted."""
    org = db.get(Organization, org_id)
    if org is None or org.deleted_at is not None:
        return None
    return org


__all__ = [
    "HANDLERS",
    "UnhandledEventType",
    "claim_events",
    "dispatch_once",
    "enqueue",
    "outbox_stats",
]
