"""Low-latency outbox wake-up based on PostgreSQL ``LISTEN/NOTIFY``.

Design constraints
------------------
* Notifications are **advisory**. They can be lost (connection drop, restart,
  full queue), so the dispatcher keeps its polling loop and lease reclamation.
  Missing a notification only adds latency; it never loses an event.
* The connection must not share a SQLAlchemy session: ``LISTEN`` binds to a
  connection and must stay idle while notifications arrive.
* The thread is a daemon and reconnects with bounded exponential backoff. It
  never raises into the worker loop.
"""

from __future__ import annotations

import threading
from typing import Any

from sqlalchemy.engine import make_url

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger("hispanshield.outbox.listener")

CHANNEL = "hispanshield_outbox"


def postgres_dsn() -> str:
    """Render the configured SQLAlchemy URL as a libpq/psycopg DSN."""
    url = make_url(settings.database_url)
    return url.set(drivername="postgresql").render_as_string(hide_password=False)


class OutboxListener:
    """Background LISTEN connection that sets ``wake`` on every notification."""

    def __init__(
        self,
        *,
        wake: threading.Event,
        stop: threading.Event,
        dsn: str | None = None,
        notify_timeout: float = 1.0,
    ) -> None:
        self._wake = wake
        self._stop = stop
        self._dsn = dsn or postgres_dsn()
        self._notify_timeout = notify_timeout
        self.ready = threading.Event()
        self._thread = threading.Thread(target=self._run, name="outbox-listener", daemon=True)

    def start(self) -> OutboxListener:
        self._thread.start()
        return self

    def join(self, timeout: float | None = None) -> None:
        self._thread.join(timeout)

    def _run(self) -> None:
        try:
            import psycopg
        except ImportError:  # pragma: no cover - psycopg is a hard dependency
            logger.error("outbox_listener_unavailable", extra={"extra_fields": {"error": "psycopg missing"}})
            return

        backoff = 1.0
        while not self._stop.is_set():
            try:
                with psycopg.connect(self._dsn, autocommit=True, connect_timeout=5) as connection:
                    connection.execute(f"LISTEN {CHANNEL}")
                    self.ready.set()
                    backoff = 1.0
                    logger.info("outbox_listener_ready", extra={"extra_fields": {"channel": CHANNEL}})
                    while not self._stop.is_set():
                        for _notification in connection.notifies(timeout=self._notify_timeout):
                            self._wake.set()
            except Exception as exc:  # noqa: BLE001 - the listener must never kill the worker
                self.ready.clear()
                logger.warning(
                    "outbox_listener_reconnect",
                    extra={"extra_fields": {"error": f"{type(exc).__name__}: {str(exc)[:300]}"}},
                )
                self._stop.wait(backoff)
                backoff = min(30.0, backoff * 2)

    def stats(self) -> dict[str, Any]:  # pragma: no cover - diagnostics helper
        return {"alive": self._thread.is_alive(), "ready": self.ready.is_set(), "channel": CHANNEL}


__all__ = ["CHANNEL", "OutboxListener", "postgres_dsn"]
