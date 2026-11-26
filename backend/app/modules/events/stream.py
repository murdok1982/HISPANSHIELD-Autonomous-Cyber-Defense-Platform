"""Server-Sent Events for the security-event firehose.

The stream is backed by ``security_events.id`` (a monotonic BIGSERIAL). Each
poll opens its own short-lived session, so a slow client never pins a database
connection for the lifetime of the stream. ``Last-Event-ID`` resumes exactly
after the last delivered row; a client without a cursor starts at the current
head, which avoids replaying the whole history by accident.
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Generator, Iterator
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.core.db import SessionLocal
from app.models.events import SecurityEvent

DEFAULT_POLL_SECONDS = 2.0
DEFAULT_HEARTBEAT_SECONDS = 15.0
BATCH_SIZE = 100


def serialize_event(event: SecurityEvent) -> dict[str, Any]:
    occurred = event.occurred_at
    if occurred.tzinfo is None:
        occurred = occurred.replace(tzinfo=UTC)
    return {
        "id": int(event.id),
        "event_uid": event.event_uid,
        "message": event.message[:500],
        "severity_id": event.severity_id,
        "class_uid": event.class_uid,
        "class_name": event.class_name,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "host_name": event.host_name,
        "user_name": event.user_name,
        "occurred_at": occurred.astimezone(UTC).isoformat(),
        "received_at": event.received_at.astimezone(UTC).isoformat() if event.received_at else None,
        "mitre_techniques": (event.mitre_techniques or [])[:20],
        "ioc_matches": len(event.ioc_matches or []),
    }


def current_head(db: Session, org_id: uuid.UUID) -> int:
    value = db.execute(select(func.max(SecurityEvent.id)).where(SecurityEvent.org_id == org_id)).scalar()
    return int(value or 0)


def fetch_after(db: Session, org_id: uuid.UUID, cursor: int, *, limit: int = BATCH_SIZE) -> list[SecurityEvent]:
    return list(
        db.execute(
            select(SecurityEvent)
            .where(SecurityEvent.org_id == org_id, SecurityEvent.id > cursor)
            .order_by(SecurityEvent.id.asc())
            .limit(limit)
        ).scalars()
    )


def iter_events(
    org_id: uuid.UUID,
    *,
    cursor: int | None = None,
    session_factory: sessionmaker[Session] = SessionLocal,
    poll_seconds: float = DEFAULT_POLL_SECONDS,
    heartbeat_seconds: float = DEFAULT_HEARTBEAT_SECONDS,
    max_events: int | None = None,
    sleep=time.sleep,
) -> Iterator[tuple[int, dict[str, Any]] | None]:
    """Yield ``(event_id, payload)`` tuples; ``None`` means "send a heartbeat".

    ``max_events`` exists for deterministic tests and operator probes; the HTTP
    endpoint leaves it unset so the stream runs until the client disconnects.
    """
    delivered = 0
    if cursor is None:
        with session_factory() as db:
            cursor = current_head(db, org_id)
    last_heartbeat = time.monotonic()
    while True:
        with session_factory() as db:
            rows = fetch_after(db, org_id, cursor)
        if rows:
            for event in rows:
                cursor = int(event.id)
                yield cursor, serialize_event(event)
                delivered += 1
                if max_events is not None and delivered >= max_events:
                    return
            last_heartbeat = time.monotonic()
            continue
        if time.monotonic() - last_heartbeat >= heartbeat_seconds:
            last_heartbeat = time.monotonic()
            yield None
        if poll_seconds > 0:
            sleep(poll_seconds)


def format_sse(event_id: int | None, payload: dict[str, Any] | None, *, event_name: str = "security_event") -> str:
    if payload is None:
        return ": heartbeat\n\n"
    data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
    return f"id: {event_id}\nevent: {event_name}\ndata: {data}\n\n"


def sse_stream(
    org_id: uuid.UUID,
    *,
    cursor: int | None,
    poll_seconds: float = DEFAULT_POLL_SECONDS,
) -> Generator[str, None, None]:
    for item in iter_events(org_id, cursor=cursor, poll_seconds=poll_seconds):
        if item is None:
            yield format_sse(None, None)
        else:
            yield format_sse(item[0], item[1])


def parse_last_event_id(value: str | None) -> int | None:
    if not value:
        return None
    try:
        parsed = int(value.strip())
    except ValueError:
        return None
    return parsed if parsed >= 0 else None


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


__all__ = [
    "current_head",
    "fetch_after",
    "format_sse",
    "iter_events",
    "parse_last_event_id",
    "serialize_event",
    "sse_stream",
]
