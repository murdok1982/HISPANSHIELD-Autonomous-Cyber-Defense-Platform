"""Gateway orchestration: collect, ship in order, heartbeat, survive offline.

The loop is deliberately boring and synchronous:

1. Collect into SQLite first (ingestion never waits on the network).
2. Ship the oldest pending envelope only, so sequence order is strict.
3. Heartbeat on the interval negotiated with the core.
4. Trim only as a last-resort disk guard, loudly.
5. Persist cursor and status atomically.

A 401 is fatal (re-enrollment required); everything else backs off and retries
with jitter. Nothing in this module logs the shared key or enrollment token.
"""

from __future__ import annotations

import json
import logging
import signal
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hispanshield_edge import AGENT_VERSION
from hispanshield_edge.client import (
    CLOCK_WARNING_SECONDS,
    ConfigFetchUnavailable,
    EdgeClient,
    FatalAuthError,
    InvalidBundleError,
    PermanentHTTPError,
    ReplayError,
    RetryableHTTPError,
    TransportError,
)
from hispanshield_edge.collectors import (
    CollectorError,
    OtSpoolCollector,
    SpoolCollector,
    SyslogUDPCollector,
)
from hispanshield_edge.config import (
    ConfigError,
    GatewayConfig,
    save_config,
    write_private_json,
)
from hispanshield_edge.queue import MAX_EVENTS_PER_ENVELOPE, DurableQueue, QueueCorruptionError

logger = logging.getLogger("hispanshield_edge.agent")

CONFIG_REFRESH_SECONDS = 6 * 3600
TRIM_INTERVAL_SECONDS = 60
MIN_HEARTBEAT_SECONDS = 15
MAX_HEARTBEAT_SECONDS = 3600


# --------------------------------------------------------------------------- #
# Structured JSON logging
# --------------------------------------------------------------------------- #
class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": record.getMessage(),
        }
        fields = getattr(record, "fields", None)
        if isinstance(fields, dict):
            payload.update(fields)
        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = record.stack_info
        return json.dumps(payload, default=str, separators=(",", ":"))


def configure_logging(level: str = "info", stream: Any = None) -> None:
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    handler = logging.StreamHandler(stream or sys.stderr)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    # Never let transport internals dump headers (they contain signatures).
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)


def log_event(level: int, event: str, **fields: Any) -> None:
    logger.log(level, event, extra={"fields": fields})


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime | None = None) -> str | None:
    return (value or _utc_now()).isoformat(timespec="seconds")


class AgentBlockedError(RuntimeError):
    """The head of the queue cannot be delivered; operator action is required."""


class GatewayAgent:
    def __init__(
        self,
        config: GatewayConfig,
        queue: DurableQueue,
        *,
        client: EdgeClient | None = None,
        spool_dir: Path | str | None = None,
        ot_spool_dir: Path | str | None = None,
        syslog_port: int | None = None,
        syslog_bind: str = "127.0.0.1",
        data_dir: Path | str | None = None,
        config_path: Path | str | None = None,
        max_batches_per_cycle: int = 10,
        sleep: Any = time.sleep,
    ) -> None:
        self.config = config
        self.queue = queue
        self._client = client
        self._client_owned = client is None
        self.max_batches_per_cycle = max(1, max_batches_per_cycle)
        self.sleep = sleep
        self.config_path = Path(config_path) if config_path else None
        self.data_dir = Path(data_dir) if data_dir else Path("edge-data")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.status_path = self.data_dir / "status.json"
        self.spool_dir = Path(spool_dir) if spool_dir else self.data_dir / "spool"
        self.ot_spool_dir = Path(ot_spool_dir) if ot_spool_dir else None
        self.syslog_port = syslog_port
        self.syslog_bind = syslog_bind

        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._started_monotonic = time.monotonic()
        self._last_heartbeat_monotonic = 0.0
        self._last_trim_monotonic = 0.0
        self._last_config_refresh_monotonic = 0.0
        self._next_heartbeat_seconds = int(config.config.get("heartbeat_interval_seconds", 60))
        self._counters: dict[str, Any] = {
            "started_at": _iso(),
            "cycles": 0,
            "sent_batches": 0,
            "sent_events": 0,
            "replays": 0,
            "heartbeats": 0,
            "collected_events": 0,
            "trimmed_events": 0,
            "config_refreshes": 0,
            "errors": 0,
            "last_error": None,
            "last_error_at": None,
            "last_flush_at": None,
            "last_heartbeat_at": None,
            "last_collect_at": None,
            "server_time_skew_seconds": None,
            "clock_warning": False,
        }

        self.spool: SpoolCollector | None = None
        self.ot_spool: OtSpoolCollector | None = None
        self.syslog: SyslogUDPCollector | None = None

    # ------------------------------------------------------------------ #
    # Lazily built resources
    # ------------------------------------------------------------------ #
    @property
    def client(self) -> EdgeClient:
        if self._client is None:
            self._client = EdgeClient(self.config, sleep=self.sleep)
        return self._client

    def _build_collectors(self) -> None:
        self.spool = SpoolCollector(self.queue, self.spool_dir)
        if self.ot_spool_dir is not None:
            self.ot_spool = OtSpoolCollector(
                self.queue,
                self.ot_spool_dir,
                self.data_dir / "ot-offsets.json",
            )
        if self.syslog_port is not None:
            self.syslog = SyslogUDPCollector(self.queue, host=self.syslog_bind, port=self.syslog_port)

    def start_collectors(self) -> None:
        if self.spool is None:
            self._build_collectors()
        assert self.spool is not None
        self.spool.start()
        try:
            if self.ot_spool is not None:
                self.ot_spool.start()
            if self.syslog is not None:
                self.syslog.start()
        except Exception:
            self.stop_collectors()
            raise

    def stop_collectors(self) -> None:
        for collector in (self.syslog, self.ot_spool, self.spool):
            if collector is not None:
                try:
                    collector.stop()
                except Exception as exc:  # noqa: BLE001 - shutdown must not throw
                    logger.error("collector stop failed: %s", exc)

    # ------------------------------------------------------------------ #
    # Counters and status
    # ------------------------------------------------------------------ #
    def counters(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._counters)

    def stats(self) -> dict[str, Any]:
        return {
            "version": AGENT_VERSION,
            "uptime_seconds": round(time.monotonic() - self._started_monotonic, 1),
            "gateway": self.config.describe(),
            "queue": self.queue.stats(),
            "counters": self.counters(),
            "collectors": {
                "spool": self.spool.stats() if self.spool else None,
                "ot": self.ot_spool.stats() if self.ot_spool else None,
                "syslog": self.syslog.stats() if self.syslog else None,
            },
            "next_heartbeat_seconds": self._next_heartbeat_seconds,
        }

    def write_status(self, *, state: str = "running") -> None:
        payload = self.stats()
        payload["state"] = state
        payload["status_written_at"] = _iso()
        try:
            write_private_json(self.status_path, payload, mode=0o600)
        except OSError as exc:
            logger.error("cannot write status file %s: %s", self.status_path, exc)

    def _record_error(self, message: str) -> None:
        with self._lock:
            self._counters["errors"] += 1
            self._counters["last_error"] = message[:300]
            self._counters["last_error_at"] = _iso()
        log_event(logging.WARNING, "agent.error", error=message[:300])

    # ------------------------------------------------------------------ #
    # Collection
    # ------------------------------------------------------------------ #
    def collect_once(self) -> int:
        collected = 0
        for collector in (self.spool, self.ot_spool):
            if collector is None:
                continue
            try:
                collected += collector.poll()
            except Exception as exc:  # noqa: BLE001 - one bad file must not stop the agent
                self._record_error(f"{collector.name} poll failed: {exc}")
        if self.syslog is not None:
            collected += self.syslog.flush()
        if collected:
            with self._lock:
                self._counters["collected_events"] += collected
                self._counters["last_collect_at"] = _iso()
            log_event(logging.INFO, "collector.ingested", events=collected)
        return collected

    # ------------------------------------------------------------------ #
    # Shipping
    # ------------------------------------------------------------------ #
    def _batch_size(self) -> int:
        value = int(self.config.config.get("batch_size", 200))
        return max(1, min(value, MAX_EVENTS_PER_ENVELOPE))

    def flush_pending(self, *, max_batches: int | None = None) -> dict[str, Any]:
        """Ship pending envelopes oldest-first. Never sends out of order."""
        limit = self.max_batches_per_cycle if max_batches is None else max(1, max_batches)
        result = {"sent_batches": 0, "sent_events": 0, "replays": 0, "blocked": False, "error": None}
        for _ in range(limit):
            try:
                head = self.queue.pending(1)
            except QueueCorruptionError as exc:
                self._record_error(f"queue corruption: {exc}")
                result["blocked"] = True
                result["error"] = str(exc)
                return result
            if not head:
                break
            envelope = head[0]
            try:
                accepted = self.client.send_batch(
                    sequence=envelope.sequence,
                    kind=envelope.kind,
                    events=envelope.events,
                )
            except ReplayError:
                # The backend already has this sequence: safe to mark delivered.
                self.queue.mark_sent(envelope.sequence, envelope.sequence)
                result["replays"] += 1
                with self._lock:
                    self._counters["replays"] += 1
                log_event(
                    logging.WARNING,
                    "ship.replay",
                    sequence=envelope.sequence,
                    note="backend cursor already at or beyond this sequence",
                )
                continue
            except FatalAuthError:
                raise
            except (RetryableHTTPError, TransportError) as exc:
                attempts = self.queue.mark_failed(envelope.sequence, str(exc))
                self._record_error(f"ship deferred sequence={envelope.sequence} attempts={attempts}: {exc}")
                result["error"] = str(exc)
                return result
            except PermanentHTTPError as exc:
                attempts = self.queue.mark_failed(envelope.sequence, str(exc))
                self._record_error(
                    f"ship rejected sequence={envelope.sequence} status={exc.status} attempts={attempts}: {exc}"
                )
                result["blocked"] = True
                result["error"] = str(exc)
                return result
            except Exception as exc:  # noqa: BLE001 - a bug must not silently drop data
                self.queue.mark_failed(envelope.sequence, str(exc))
                self._record_error(f"ship failed sequence={envelope.sequence}: {exc}")
                result["blocked"] = True
                result["error"] = str(exc)
                return result
            self.queue.mark_sent(envelope.sequence, accepted.cursor)
            result["sent_batches"] += 1
            result["sent_events"] += len(envelope.events)
            with self._lock:
                self._counters["sent_batches"] += 1
                self._counters["sent_events"] += len(envelope.events)
                self._counters["last_flush_at"] = _iso()
            log_event(
                logging.INFO,
                "ship.batch",
                sequence=envelope.sequence,
                kind=envelope.kind,
                events=len(envelope.events),
                cursor=accepted.cursor,
            )
        return result

    # ------------------------------------------------------------------ #
    # Heartbeat and config
    # ------------------------------------------------------------------ #
    def heartbeat_due(self) -> bool:
        elapsed = time.monotonic() - self._last_heartbeat_monotonic
        return self._last_heartbeat_monotonic == 0.0 or elapsed >= self._next_heartbeat_seconds

    def heartbeat_once(self) -> dict[str, Any]:
        queue_stats = self.queue.stats()
        buffer_stats = {
            "pending": queue_stats["pending_envelopes"],
            "pending_bytes": queue_stats["pending_bytes"],
            "oldest_age_s": queue_stats["oldest_age_s"],
            "sent": queue_stats["sent_envelopes"],
            "version": AGENT_VERSION,
        }
        status = "healthy"
        with self._lock:
            if self._counters["last_error"]:
                status = "degraded"
        response = self.client.heartbeat(buffer_stats=buffer_stats, status=status)
        self._last_heartbeat_monotonic = time.monotonic()
        self._next_heartbeat_seconds = max(
            MIN_HEARTBEAT_SECONDS, min(int(response.next_heartbeat_seconds), MAX_HEARTBEAT_SECONDS)
        )
        now = _utc_now()
        skew = (response.server_time - now).total_seconds()
        warning = abs(skew) > CLOCK_WARNING_SECONDS
        with self._lock:
            already_warned = bool(self._counters["clock_warning"])
            self._counters["heartbeats"] += 1
            self._counters["last_heartbeat_at"] = _iso()
            self._counters["server_time_skew_seconds"] = round(skew, 1)
            self._counters["clock_warning"] = warning
        if warning and not already_warned:
            log_event(
                logging.WARNING,
                "clock.skew",
                server_time=response.server_time.isoformat(),
                local_time=now.isoformat(),
                skew_seconds=round(skew, 1),
                note="HMAC timestamps are rejected beyond 300s; fix the gateway clock",
            )
        if response.config_version and response.config_version != self.config.config_version:
            self.config.config_version = response.config_version
            if self.config_path is not None:
                try:
                    save_config(self.config, self.config_path)
                except (OSError, ConfigError) as exc:
                    logger.warning("cannot persist config_version: %s", exc)
        log_event(
            logging.INFO,
            "heartbeat.ok",
            cursor=response.cursor,
            next_heartbeat_seconds=self._next_heartbeat_seconds,
        )
        return {
            "ok": response.ok,
            "cursor": response.cursor,
            "next_heartbeat_seconds": self._next_heartbeat_seconds,
            "config_version": response.config_version,
            "skew_seconds": round(skew, 1),
        }

    def refresh_config_if_due(self, *, force: bool = False) -> bool:
        if not bool(self.config.config.get("allow_remote_config", True)):
            return False
        elapsed = time.monotonic() - self._last_config_refresh_monotonic
        if not force and self._last_config_refresh_monotonic != 0.0 and elapsed < CONFIG_REFRESH_SECONDS:
            return False
        self._last_config_refresh_monotonic = time.monotonic()
        try:
            verified = self.client.fetch_config_bundle()
        except ConfigFetchUnavailable as exc:
            logger.debug("remote config unavailable: %s", exc)
            return False
        except InvalidBundleError as exc:
            log_event(logging.CRITICAL, "config.rejected", error=str(exc))
            raise
        except (RetryableHTTPError, TransportError) as exc:
            logger.info("remote config deferred: %s", exc)
            return False
        ignored = self.config.update_runtime_config(verified.config)
        self._next_heartbeat_seconds = max(
            MIN_HEARTBEAT_SECONDS,
            min(int(self.config.config.get("heartbeat_interval_seconds", 60)), MAX_HEARTBEAT_SECONDS),
        )
        if self.config_path is not None:
            try:
                save_config(self.config, self.config_path)
            except (OSError, ConfigError) as exc:
                logger.error("config verified but could not be persisted: %s", exc)
        with self._lock:
            self._counters["config_refreshes"] += 1
        log_event(
            logging.INFO,
            "config.updated",
            ignored_keys=ignored,
            config_version=self.config.config_version,
        )
        return True

    # ------------------------------------------------------------------ #
    # Maintenance
    # ------------------------------------------------------------------ #
    def trim_if_due(self) -> int:
        elapsed = time.monotonic() - self._last_trim_monotonic
        if self._last_trim_monotonic != 0.0 and elapsed < TRIM_INTERVAL_SECONDS:
            return 0
        max_events = int(self.config.config.get("buffer_max_events", 50_000))
        dropped = self.queue.trim(max_events)
        self._last_trim_monotonic = time.monotonic()
        if dropped:
            with self._lock:
                self._counters["trimmed_events"] += dropped
                self._counters["last_error"] = f"backlog trim dropped {dropped} oldest unsent events"
            log_event(logging.ERROR, "queue.trim", dropped=dropped, max_events=max_events)
        return dropped

    # ------------------------------------------------------------------ #
    # Single cycle / long running loop
    # ------------------------------------------------------------------ #
    def once(self, *, collect: bool = True, heartbeat: bool = True) -> dict[str, Any]:
        """Run one cycle without blocking forever. Used by tests and ``--once``."""
        summary: dict[str, Any] = {
            "collected": 0,
            "sent_batches": 0,
            "sent_events": 0,
            "replays": 0,
            "heartbeat": None,
            "error": None,
            "blocked": False,
        }
        if collect:
            summary["collected"] = self.collect_once()
        shipped = self.flush_pending()
        summary.update(
            {
                "sent_batches": shipped["sent_batches"],
                "sent_events": shipped["sent_events"],
                "replays": shipped["replays"],
                "blocked": shipped["blocked"],
            }
        )
        if shipped["error"]:
            summary["error"] = shipped["error"]
        if heartbeat and not shipped["blocked"]:
            try:
                summary["heartbeat"] = self.heartbeat_once()
            except FatalAuthError:
                raise
            except (RetryableHTTPError, TransportError) as exc:
                self._record_error(f"heartbeat deferred: {exc}")
                summary["error"] = summary["error"] or str(exc)
            except Exception as exc:  # noqa: BLE001 - heartbeat failure must not lose data
                self._record_error(f"heartbeat failed: {exc}")
                summary["error"] = summary["error"] or str(exc)
        try:
            self.refresh_config_if_due()
        except InvalidBundleError:
            raise
        except (RetryableHTTPError, TransportError, ConfigFetchUnavailable) as exc:
            logger.debug("config refresh skipped: %s", exc)
        self.trim_if_due()
        with self._lock:
            self._counters["cycles"] += 1
        self.write_status()
        logger.debug("cycle complete", extra={"fields": {"summary": summary}})
        return summary

    def _cycle_interval(self) -> float:
        flush_interval = int(self.config.config.get("flush_interval_seconds", 30))
        heartbeat_remaining = self._next_heartbeat_seconds - (time.monotonic() - self._last_heartbeat_monotonic)
        return float(max(1, min(flush_interval, max(1.0, heartbeat_remaining), 60)))

    def _handle_signal(self, signum: int, _frame: Any) -> None:
        log_event(logging.INFO, "agent.signal", signal=signum, action="graceful_shutdown")
        self._stop.set()

    def run(self) -> int:
        """Foreground loop. Returns a process exit code."""
        self.config.require_enrolled()
        exit_code = 0
        previous_handlers: dict[int, Any] = {}
        if threading.current_thread() is threading.main_thread():
            for signum in (signal.SIGTERM, signal.SIGINT):
                previous_handlers[signum] = signal.getsignal(signum)
                signal.signal(signum, self._handle_signal)
        log_event(
            logging.INFO,
            "agent.start",
            gateway_id=self.config.gateway_id,
            version=AGENT_VERSION,
            spool_dir=str(self.spool_dir),
            ot_spool=str(self.ot_spool_dir) if self.ot_spool_dir else None,
            syslog_port=self.syslog_port,
        )
        try:
            self.start_collectors()
            self.write_status(state="starting")
            try:
                self.heartbeat_once()
            except FatalAuthError:
                raise
            except (RetryableHTTPError, TransportError) as exc:
                self._record_error(f"initial heartbeat deferred (offline start): {exc}")
            except Exception as exc:  # noqa: BLE001
                self._record_error(f"initial heartbeat failed: {exc}")
            try:
                self.refresh_config_if_due(force=True)
            except (InvalidBundleError, FatalAuthError):
                raise
            except (RetryableHTTPError, TransportError, ConfigFetchUnavailable) as exc:
                logger.info("config refresh at start skipped: %s", exc)

            backoff = 1.0
            while not self._stop.is_set():
                try:
                    summary = self.once()
                    if summary["error"]:
                        backoff = min(backoff * 2, 60.0)
                    else:
                        backoff = 1.0
                except FatalAuthError as exc:
                    log_event(
                        logging.CRITICAL,
                        "agent.fatal_auth",
                        error=str(exc),
                        action="re-enrollment required; agent stopped",
                    )
                    exit_code = 3
                    self._stop.set()
                    break
                except InvalidBundleError as exc:
                    log_event(logging.CRITICAL, "agent.invalid_bundle", error=str(exc))
                    exit_code = 5
                    self._stop.set()
                    break
                except CollectorError as exc:
                    self._record_error(f"collector failure: {exc}")
                    exit_code = 2
                    self._stop.set()
                    break
                except Exception as exc:  # noqa: BLE001 - keep collecting, never crash mid-batch
                    self._record_error(f"cycle failure: {exc}")
                delay = max(self._cycle_interval(), min(backoff, 30.0))
                self._stop.wait(delay)
            self.write_status(state="stopped")
        finally:
            self.stop_collectors()
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
            log_event(logging.INFO, "agent.stop", exit_code=exit_code)
        return exit_code

    def stop(self) -> None:
        self._stop.set()

    def close(self) -> None:
        self.stop_collectors()
        if self._client_owned and self._client is not None:
            self._client.close()


__all__ = [
    "CONFIG_REFRESH_SECONDS",
    "AgentBlockedError",
    "GatewayAgent",
    "JsonFormatter",
    "configure_logging",
    "log_event",
]
