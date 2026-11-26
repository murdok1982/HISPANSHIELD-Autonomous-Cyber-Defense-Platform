"""Durable SQLite queue with monotonic sequence assignment.

Invariants (the reason this file exists):

1. A batch sequence is allocated **in the same transaction as its insert**, so a
   sequence can never be reused for different data, even across crashes.
2. Pending batches live on disk only; no in-memory buffer is required for
   correctness (WAL + ``synchronous=FULL``).
3. ``mark_sent`` persists the server cursor, so a restart resumes from the
   server's acknowledged position and the backend replay check protects us from
   the one ambiguous case (response lost after commit).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger("hispanshield_edge.queue")

VALID_KINDS = frozenset({"network", "ot", "iot", "json"})
MAX_EVENTS_PER_ENVELOPE = 500
_SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS envelope (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sequence INTEGER NOT NULL UNIQUE,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at REAL NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_error TEXT,
    sent_at REAL
);
CREATE INDEX IF NOT EXISTS idx_envelope_pending ON envelope(sequence) WHERE sent_at IS NULL;
CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class QueueError(RuntimeError):
    """Raised when the durable queue cannot satisfy an invariant."""


class QueueCorruptionError(QueueError):
    """Raised when a stored payload is not a JSON list of objects."""


@dataclass(frozen=True, slots=True)
class Envelope:
    id: int
    sequence: int
    kind: str
    events: list[dict[str, Any]]
    created_at: float
    attempts: int
    last_error: str | None

    @property
    def age_seconds(self) -> float:
        return max(0.0, time.time() - self.created_at)


def _validate_batch(kind: str, events: Any) -> list[dict[str, Any]]:
    if kind not in VALID_KINDS:
        raise QueueError(f"unsupported event kind: {kind!r}")
    if not isinstance(events, list) or not events:
        raise QueueError("events must be a non-empty list")
    if len(events) > MAX_EVENTS_PER_ENVELOPE:
        raise QueueError(f"events must contain at most {MAX_EVENTS_PER_ENVELOPE} items")
    for item in events:
        if not isinstance(item, dict):
            raise QueueError("every event must be a JSON object")
    return events


class DurableQueue:
    """One connection per instance; safe across threads and processes (WAL)."""

    def __init__(self, path: Path | str, *, busy_timeout_ms: int = 10_000) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()
        if str(self.path.parent) not in {"", "."}:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(
            str(self.path),
            timeout=busy_timeout_ms / 1000,
            isolation_level=None,
            check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        self._closed = False
        self._configure(busy_timeout_ms)
        self._initialize()

    # ------------------------------------------------------------------ #
    # Setup
    # ------------------------------------------------------------------ #
    def _configure(self, busy_timeout_ms: int) -> None:
        cur = self._conn
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute(f"PRAGMA busy_timeout={int(busy_timeout_ms)}")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA synchronous=FULL")
        cur.execute("PRAGMA wal_autocheckpoint=1000")

    def _initialize(self) -> None:
        with self._lock:
            version = int(self._conn.execute("PRAGMA user_version").fetchone()[0])
            if version > _SCHEMA_VERSION:
                raise QueueError(f"queue schema version {version} is newer than supported {_SCHEMA_VERSION}")
            self._conn.executescript(_SCHEMA)
            if version < _SCHEMA_VERSION:
                self._conn.execute(f"PRAGMA user_version={_SCHEMA_VERSION}")

    @contextmanager
    def _write(self) -> Iterator[sqlite3.Connection]:
        if self._closed:
            raise QueueError("queue is closed")
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                yield self._conn
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise
            else:
                self._conn.execute("COMMIT")

    # ------------------------------------------------------------------ #
    # Write path
    # ------------------------------------------------------------------ #
    def enqueue(self, kind: str, events: list[dict[str, Any]]) -> int:
        """Persist one envelope and return its freshly allocated sequence."""
        payload = _validate_batch(kind, events)
        payload_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=False, default=str)
        created = time.time()
        with self._write() as conn:
            row = conn.execute("SELECT value FROM kv WHERE key='next_sequence'").fetchone()
            sequence = int(row["value"]) if row else 1
            conn.execute(
                "INSERT INTO envelope (sequence, kind, payload_json, created_at) VALUES (?, ?, ?, ?)",
                (sequence, kind, payload_json, created),
            )
            conn.execute(
                "INSERT INTO kv (key, value) VALUES ('next_sequence', ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(sequence + 1),),
            )
        return sequence

    def mark_sent(self, sequence: int, cursor: int) -> bool:
        """Mark a batch delivered and advance the persisted server cursor."""
        now = time.time()
        with self._write() as conn:
            updated = conn.execute(
                "UPDATE envelope SET sent_at=?, last_error=NULL WHERE sequence=? AND sent_at IS NULL",
                (now, int(sequence)),
            ).rowcount
            current = conn.execute("SELECT value FROM kv WHERE key='cursor'").fetchone()
            cursor_value = max(int(cursor), int(current["value"]) if current else 0)
            conn.execute(
                "INSERT INTO kv (key, value) VALUES ('cursor', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(cursor_value),),
            )
        return bool(updated)

    def mark_failed(self, sequence: int, error: str) -> int:
        """Increment attempts and record a bounded error string; returns attempts."""
        message = str(error)[:500]
        with self._write() as conn:
            conn.execute(
                "UPDATE envelope SET attempts=attempts+1, last_error=? WHERE sequence=? AND sent_at IS NULL",
                (message, int(sequence)),
            )
            row = conn.execute("SELECT attempts FROM envelope WHERE sequence=?", (int(sequence),)).fetchone()
        return int(row["attempts"]) if row else 0

    def drop(self, sequence: int) -> bool:
        """Explicit operator action: delete one pending envelope. Logged loudly."""
        with self._write() as conn:
            deleted = conn.execute(
                "DELETE FROM envelope WHERE sequence=? AND sent_at IS NULL", (int(sequence),)
            ).rowcount
        if deleted:
            logger.warning("operator dropped pending envelope sequence=%s", sequence)
        return bool(deleted)

    def trim(self, max_events: int) -> int:
        """Drop the oldest *unsent* events when the backlog exceeds the limit.

        This is the last-resort disk guard. It is intentionally loud: silent
        trimming would turn a bounded-disk policy into invisible data loss.
        """
        if max_events < 1:
            raise QueueError("max_events must be >= 1")
        with self._write() as conn:
            pending = int(conn.execute("SELECT COUNT(*) FROM envelope WHERE sent_at IS NULL").fetchone()[0])
            if pending <= max_events:
                return 0
            overflow = pending - max_events
            rows = conn.execute(
                "SELECT sequence FROM envelope WHERE sent_at IS NULL ORDER BY sequence ASC LIMIT ?", (overflow,)
            ).fetchall()
            sequences = [int(row["sequence"]) for row in rows]
            conn.executemany("DELETE FROM envelope WHERE sequence=?", [(seq,) for seq in sequences])
        logger.error(
            "queue backlog exceeded buffer_max_events: dropped_oldest_unsent=%d sequences=%s..%s max_events=%d",
            len(sequences),
            sequences[0] if sequences else None,
            sequences[-1] if sequences else None,
            max_events,
        )
        return len(sequences)

    # ------------------------------------------------------------------ #
    # Read path
    # ------------------------------------------------------------------ #
    def _decode(self, row: sqlite3.Row) -> Envelope:
        try:
            events = json.loads(row["payload_json"])
        except json.JSONDecodeError as exc:
            raise QueueCorruptionError(f"sequence {row['sequence']} has invalid JSON payload") from exc
        if not isinstance(events, list) or not all(isinstance(item, dict) for item in events):
            raise QueueCorruptionError(f"sequence {row['sequence']} payload is not a list of objects")
        return Envelope(
            id=int(row["id"]),
            sequence=int(row["sequence"]),
            kind=str(row["kind"]),
            events=events,
            created_at=float(row["created_at"]),
            attempts=int(row["attempts"]),
            last_error=row["last_error"],
        )

    def pending(self, limit: int = 50) -> list[Envelope]:
        if limit < 1:
            raise QueueError("limit must be >= 1")
        with self._lock:
            rows = self._conn.execute(
                "SELECT id, sequence, kind, payload_json, created_at, attempts, last_error "
                "FROM envelope WHERE sent_at IS NULL ORDER BY sequence ASC LIMIT ?",
                (int(limit),),
            ).fetchall()
        return [self._decode(row) for row in rows]

    def get(self, sequence: int) -> Envelope | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT id, sequence, kind, payload_json, created_at, attempts, last_error "
                "FROM envelope WHERE sequence=?",
                (int(sequence),),
            ).fetchone()
        return self._decode(row) if row else None

    def cursor(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT value FROM kv WHERE key='cursor'").fetchone()
        return int(row["value"]) if row else 0

    def next_sequence(self) -> int:
        with self._lock:
            row = self._conn.execute("SELECT value FROM kv WHERE key='next_sequence'").fetchone()
        return int(row["value"]) if row else 1

    def stats(self) -> dict[str, Any]:
        with self._lock:
            pending_row = self._conn.execute(
                "SELECT COUNT(*) AS count, COALESCE(SUM(LENGTH(payload_json)), 0) AS bytes, "
                "MIN(created_at) AS oldest, MAX(attempts) AS max_attempts "
                "FROM envelope WHERE sent_at IS NULL"
            ).fetchone()
            sent_row = self._conn.execute(
                "SELECT COUNT(*) AS count, COALESCE(SUM(LENGTH(payload_json)), 0) AS bytes "
                "FROM envelope WHERE sent_at IS NOT NULL"
            ).fetchone()
            last_error_row = self._conn.execute(
                "SELECT sequence, last_error FROM envelope WHERE sent_at IS NULL AND last_error IS NOT NULL "
                "ORDER BY sequence ASC LIMIT 1"
            ).fetchone()
        now = time.time()
        oldest = pending_row["oldest"]
        return {
            "path": str(self.path),
            "pending_envelopes": int(pending_row["count"]),
            "pending_bytes": int(pending_row["bytes"]),
            "oldest_age_s": round(max(0.0, now - float(oldest)), 3) if oldest is not None else 0.0,
            "max_attempts": int(pending_row["max_attempts"] or 0),
            "sent_envelopes": int(sent_row["count"]),
            "sent_bytes": int(sent_row["bytes"]),
            "cursor": self.cursor(),
            "next_sequence": self.next_sequence(),
            "blocking_error": (
                {"sequence": int(last_error_row["sequence"]), "error": last_error_row["last_error"]}
                if last_error_row
                else None
            ),
        }

    def checkpoint(self) -> None:
        with self._lock:
            if not self._closed:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            except sqlite3.Error:  # pragma: no cover - best effort on close
                pass
            self._conn.close()
            self._closed = True

    def __enter__(self) -> DurableQueue:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()


__all__ = [
    "MAX_EVENTS_PER_ENVELOPE",
    "VALID_KINDS",
    "DurableQueue",
    "Envelope",
    "QueueCorruptionError",
    "QueueError",
]
