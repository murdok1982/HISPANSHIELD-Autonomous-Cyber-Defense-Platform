"""Passive collectors: file spool, syslog listener and read-only OT spool.

Hard rules:

* No active scanning, probing or polling of any OT/IT device. The syslog
  collector only receives datagrams; the OT collector only reads a local,
  operator-provided spool of observations.
* Every event is written to the durable queue before the source file is
  archived, so a crash between collection and upload cannot lose data.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from hispanshield_edge.config import write_private_json
from hispanshield_edge.queue import MAX_EVENTS_PER_ENVELOPE, DurableQueue

logger = logging.getLogger("hispanshield_edge.collectors")

MAX_OBJECT_BYTES = 256 * 1024
MAX_SPOOL_FILE_BYTES = 8 * 1024 * 1024
MAX_SYSLOG_DATAGRAM_BYTES = 64 * 1024
MAX_SYSLOG_MESSAGE_CHARS = 60_000
_PRI_RE = re.compile(r"^<(?P<pri>\d{1,3})>")
_RFC5424_RE = re.compile(r"^1\s+(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+(?P<proc>\S+)\s+(?P<msgid>\S+)\s(?P<rest>.*)$")
_RFC3164_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<app>[^\s:\[]+)(?:\[(?P<proc>\d+)\])?:\s?(?P<msg>.*)$"
)


class CollectorError(RuntimeError):
    """Raised when a collector cannot start or is misconfigured."""


def _now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _serialized_size(value: dict[str, Any]) -> int:
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False, default=str).encode("utf-8"))


def _validate_event(event: Any, *, origin: str) -> dict[str, Any]:
    if not isinstance(event, dict):
        raise CollectorError(f"{origin}: event is not a JSON object")
    size = _serialized_size(event)
    if size > MAX_OBJECT_BYTES:
        raise CollectorError(f"{origin}: event is {size} bytes, limit is {MAX_OBJECT_BYTES}")
    return event


# --------------------------------------------------------------------------- #
# JSON file spool
# --------------------------------------------------------------------------- #
class SpoolCollector:
    """Consume ``*.json``/``*.jsonl`` files dropped by local forwarders.

    Files are atomically claimed with ``os.replace`` into ``processing/`` so two
    agents (or a restart) can never ingest the same object twice; after the
    durable enqueue they are moved to ``archive/`` (or ``failed/``).
    """

    name = "spool"

    def __init__(
        self,
        queue: DurableQueue,
        directory: Path | str,
        *,
        max_object_bytes: int = MAX_OBJECT_BYTES,
        max_file_bytes: int = MAX_SPOOL_FILE_BYTES,
        batch_size: int = MAX_EVENTS_PER_ENVELOPE,
    ) -> None:
        self.queue = queue
        self.directory = Path(directory)
        self.processing_dir = self.directory / "processing"
        self.archive_dir = self.directory / "archive"
        self.failed_dir = self.directory / "failed"
        self.max_object_bytes = max_object_bytes
        self.max_file_bytes = max_file_bytes
        self.batch_size = max(1, min(batch_size, MAX_EVENTS_PER_ENVELOPE))
        self._running = False
        self._lock = threading.Lock()
        self._stats = {
            "files_processed": 0,
            "files_failed": 0,
            "events_enqueued": 0,
            "batches": 0,
            "last_scan_at": None,
            "last_error": None,
            "running": False,
        }

    def start(self) -> None:
        for directory in (self.directory, self.processing_dir, self.archive_dir, self.failed_dir):
            directory.mkdir(parents=True, exist_ok=True)
        self._recover_claimed()
        with self._lock:
            self._running = True
            self._stats["running"] = True
        logger.info("spool collector started directory=%s", self.directory)

    def _recover_claimed(self) -> None:
        for claimed in sorted(self.processing_dir.iterdir()) if self.processing_dir.exists() else []:
            if not claimed.is_file():
                continue
            destination = self.directory / claimed.name
            if destination.exists():
                destination = self.directory / f"{claimed.stem}.{int(time.time())}{claimed.suffix}"
            try:
                claimed.replace(destination)
                logger.warning("requeued claimed spool file after restart: %s", destination.name)
            except OSError as exc:
                logger.error("cannot recover claimed spool file %s: %s", claimed, exc)

    def stop(self) -> None:
        with self._lock:
            self._running = False
            self._stats["running"] = False
        logger.info("spool collector stopped")

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._stats)

    def poll(self) -> int:
        if not self._running:
            return 0
        enqueued = 0
        try:
            files = sorted(
                path
                for path in self.directory.iterdir()
                if path.is_file() and path.suffix.lower() in {".json", ".jsonl"} and not path.name.startswith(".")
            )
        except OSError as exc:
            self._record_error(f"cannot list spool: {exc}")
            return 0
        for path in files:
            enqueued += self._consume(path)
        with self._lock:
            self._stats["last_scan_at"] = _now_iso()
        return enqueued

    def _claim(self, path: Path) -> Path | None:
        target = self.processing_dir / path.name
        try:
            path.replace(target)
            return target
        except FileNotFoundError:
            return None
        except OSError as exc:
            self._record_error(f"cannot claim {path.name}: {exc}")
            return None

    def _consume(self, path: Path) -> int:
        try:
            size = path.stat().st_size
        except OSError as exc:
            self._record_error(f"cannot stat {path.name}: {exc}")
            return 0
        if size > self.max_file_bytes:
            self._fail(path, f"file is {size} bytes, limit is {self.max_file_bytes}")
            return 0
        claimed = self._claim(path)
        if claimed is None:
            return 0
        try:
            events = self._parse_file(claimed)
        except (OSError, ValueError, CollectorError, json.JSONDecodeError) as exc:
            self._fail(claimed, str(exc))
            return 0
        enqueued = 0
        try:
            for start in range(0, len(events), self.batch_size):
                chunk = events[start : start + self.batch_size]
                self.queue.enqueue("json", chunk)
                enqueued += len(chunk)
                with self._lock:
                    self._stats["batches"] += 1
        except Exception as exc:
            self._record_error(f"queue enqueue failed for {claimed.name}: {exc}")
            logger.error("spool file %s left in processing/ after enqueue failure", claimed.name)
            return enqueued
        self._archive(claimed)
        with self._lock:
            self._stats["files_processed"] += 1
            self._stats["events_enqueued"] += enqueued
        return enqueued

    def _parse_file(self, path: Path) -> list[dict[str, Any]]:
        raw = path.read_text(encoding="utf-8-sig")
        events: list[Any]
        if path.suffix.lower() == ".jsonl":
            events = []
            for number, line in enumerate(raw.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError as exc:
                    raise CollectorError(f"{path.name}:{number}: invalid JSON: {exc.msg}") from exc
        else:
            document = json.loads(raw)
            events = document if isinstance(document, list) else [document]
        if not events:
            raise CollectorError(f"{path.name}: no events found")
        validated = [_validate_event(event, origin=path.name) for event in events]
        for event in validated:
            if _serialized_size(event) > self.max_object_bytes:
                raise CollectorError(f"{path.name}: event exceeds {self.max_object_bytes} bytes")
        return validated

    def _archive(self, claimed: Path) -> None:
        stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        destination = self.archive_dir / f"{stamp}-{claimed.name}"
        counter = 1
        while destination.exists():
            destination = self.archive_dir / f"{stamp}-{counter}-{claimed.name}"
            counter += 1
        try:
            claimed.replace(destination)
        except OSError as exc:
            self._record_error(f"cannot archive {claimed.name}: {exc}")

    def _fail(self, path: Path, reason: str) -> None:
        try:
            if path.parent != self.failed_dir:
                destination = self.failed_dir / f"{int(time.time())}-{path.name}"
                path.replace(destination)
            else:
                destination = path
            destination.with_suffix(f"{destination.suffix}.error").write_text(reason[:2000], encoding="utf-8")
        except OSError as exc:
            self._record_error(f"cannot quarantine {path.name}: {exc}")
        with self._lock:
            self._stats["files_failed"] += 1
            self._stats["last_error"] = reason[:300]
        logger.error("spool file rejected name=%s reason=%s", path.name, reason[:300])

    def _record_error(self, message: str) -> None:
        with self._lock:
            self._stats["last_error"] = message[:300]
        logger.error("%s", message)


# --------------------------------------------------------------------------- #
# Syslog UDP
# --------------------------------------------------------------------------- #
def _strip_structured_data(rest: str) -> str:
    if rest.startswith("-"):
        return rest[1:].lstrip()
    if not rest.startswith("["):
        return rest
    depth = 0
    escaped = False
    for index, char in enumerate(rest):
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == "[":
            depth += 1
        elif char == "]":
            depth -= 1
            if depth == 0:
                return rest[index + 1 :].lstrip()
    return rest


def parse_syslog(data: bytes) -> dict[str, Any] | None:
    """Parse RFC3164/RFC5424 without trusting any field."""
    text = data.decode("utf-8", errors="replace").replace("\x00", "").rstrip("\r\n")
    if not text:
        return None
    if len(text) > MAX_SYSLOG_MESSAGE_CHARS:
        text = text[:MAX_SYSLOG_MESSAGE_CHARS]
    facility: int | None = None
    severity: int | None = None
    priority: int | None = None
    match = _PRI_RE.match(text)
    if match:
        priority = int(match.group("pri"))
        if priority > 191:
            priority = None
        else:
            facility = priority // 8
            severity = priority % 8
        text = text[match.end() :]
    event: dict[str, Any] = {
        "message": text,
        "raw_format": "syslog",
        "syslog_format": "unknown",
    }
    if priority is not None:
        event["priority"] = priority
        event["facility"] = facility
        event["severity"] = severity
    rfc5424 = _RFC5424_RE.match(text)
    if rfc5424:
        event.update(
            {
                "syslog_format": "rfc5424",
                "timestamp": rfc5424.group("ts"),
                "host": rfc5424.group("host"),
                "app": rfc5424.group("app"),
                "procid": rfc5424.group("proc"),
                "msgid": rfc5424.group("msgid"),
                "message": _strip_structured_data(rfc5424.group("rest"))[:MAX_SYSLOG_MESSAGE_CHARS],
            }
        )
        return event
    rfc3164 = _RFC3164_RE.match(text)
    if rfc3164:
        event.update(
            {
                "syslog_format": "rfc3164",
                "timestamp": rfc3164.group("ts"),
                "host": rfc3164.group("host"),
                "app": rfc3164.group("app"),
                "message": rfc3164.group("msg")[:MAX_SYSLOG_MESSAGE_CHARS],
            }
        )
        if rfc3164.group("proc"):
            event["procid"] = rfc3164.group("proc")
        return event
    return event


class SyslogUDPCollector:
    """Passive UDP syslog receiver. Never sends a packet."""

    name = "syslog"

    def __init__(
        self,
        queue: DurableQueue,
        *,
        host: str = "127.0.0.1",
        port: int = 5514,
        batch_size: int = 100,
        max_datagram_bytes: int = MAX_SYSLOG_DATAGRAM_BYTES,
        flush_interval_seconds: float = 1.0,
        buffer_max_events: int = 10_000,
    ) -> None:
        self.queue = queue
        self.host = host
        self.port = int(port)
        self.batch_size = max(1, min(batch_size, MAX_EVENTS_PER_ENVELOPE))
        self.max_datagram_bytes = max_datagram_bytes
        self.flush_interval_seconds = flush_interval_seconds
        self.buffer_max_events = buffer_max_events
        self._buffer: list[dict[str, Any]] = []
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._socket: socket.socket | None = None
        self._last_flush = time.monotonic()
        self._lock = threading.Lock()
        self._stats = {
            "received": 0,
            "dropped_oversize": 0,
            "parse_errors": 0,
            "enqueued": 0,
            "enqueue_errors": 0,
            "buffer_len": 0,
            "last_error": None,
            "running": False,
        }
        self.bound_port = self.port

    def start(self) -> None:
        if self._thread is not None:
            return
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.settimeout(0.5)
        except OSError as exc:
            sock.close()
            raise CollectorError(f"cannot bind syslog socket {self.host}:{self.port}: {exc}") from exc
        self._socket = sock
        self.bound_port = int(sock.getsockname()[1])
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="hs-syslog", daemon=True)
        self._thread.start()
        with self._lock:
            self._stats["running"] = True
        logger.info("syslog collector listening on %s:%s/udp", self.host, self.bound_port)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                data, _address = self._socket.recvfrom(65535) if self._socket else (b"", None)
            except TimeoutError:
                data = b""
            except OSError:
                if self._stop.is_set():
                    break
                continue
            if data:
                self.handle_datagram(data)
            with self._lock:
                buffer_len = len(self._buffer)
                due = buffer_len >= self.batch_size or (
                    buffer_len > 0 and (time.monotonic() - self._last_flush) >= self.flush_interval_seconds
                )
            if due:
                self._flush()
        self._flush()

    def handle_datagram(self, data: bytes) -> bool:
        with self._lock:
            self._stats["received"] += 1
        if len(data) > self.max_datagram_bytes:
            with self._lock:
                self._stats["dropped_oversize"] += 1
                self._stats["last_error"] = f"datagram of {len(data)} bytes exceeds {self.max_datagram_bytes}"
            logger.warning("syslog datagram dropped: %d bytes exceeds limit", len(data))
            return False
        try:
            event = parse_syslog(data)
        except Exception as exc:  # defensive: parsing must never kill the listener
            event = None
            with self._lock:
                self._stats["parse_errors"] += 1
                self._stats["last_error"] = f"parse error: {exc}"
        if event is None:
            with self._lock:
                self._stats["parse_errors"] += 1
                self._stats["buffer_len"] = len(self._buffer)
            return False
        with self._lock:
            self._buffer.append(event)
            if len(self._buffer) > self.buffer_max_events:
                dropped = len(self._buffer) - self.buffer_max_events
                del self._buffer[:dropped]
                self._stats["dropped_oversize"] += dropped
                logger.error("syslog memory buffer overflow: dropped=%d", dropped)
            self._stats["buffer_len"] = len(self._buffer)
        return True

    def _flush(self) -> int:
        with self._lock:
            if not self._buffer:
                self._last_flush = time.monotonic()
                return 0
            chunk = self._buffer[: self.batch_size]
            del self._buffer[: len(chunk)]
        try:
            self.queue.enqueue("network", chunk)
        except Exception as exc:
            with self._lock:
                self._buffer[0:0] = chunk
                if len(self._buffer) > self.buffer_max_events:
                    del self._buffer[: len(self._buffer) - self.buffer_max_events]
                self._stats["enqueue_errors"] += 1
                self._stats["last_error"] = f"enqueue failed: {exc}"
                self._stats["buffer_len"] = len(self._buffer)
                self._last_flush = time.monotonic()
            logger.error("syslog enqueue failed, retained in memory: %s", exc)
            return 0
        with self._lock:
            self._stats["enqueued"] += len(chunk)
            self._stats["buffer_len"] = len(self._buffer)
            self._last_flush = time.monotonic()
        return len(chunk)

    def flush(self) -> int:
        """Drain the in-memory buffer (bounded loop) into the durable queue."""
        total = 0
        while True:
            with self._lock:
                remaining = len(self._buffer)
            if remaining <= 0:
                break
            flushed = self._flush()
            if flushed == 0:
                break
            total += flushed
        return total

    def stop(self) -> None:
        self._stop.set()
        if self._socket is not None:
            try:
                self._socket.close()
            except OSError:  # pragma: no cover
                pass
            self._socket = None
        if self._thread is not None:
            self._thread.join(timeout=5.0)
            self._thread = None
        self.flush()
        with self._lock:
            self._stats["running"] = False
        logger.info("syslog collector stopped")

    def stats(self) -> dict[str, Any]:
        with self._lock:
            payload = dict(self._stats)
        payload["bound_port"] = self.bound_port
        return payload


# --------------------------------------------------------------------------- #
# OT read-only spool
# --------------------------------------------------------------------------- #
class OtSpoolCollector:
    """Read-only JSONL observation spool.

    It deliberately has no socket code: the OT network has no path from this
    process. It never writes inside ``directory`` either; offsets live in the
    agent data directory so a read-only mount is enough.
    """

    name = "ot"

    def __init__(
        self,
        queue: DurableQueue,
        directory: Path | str,
        state_path: Path | str,
        *,
        max_object_bytes: int = MAX_OBJECT_BYTES,
        batch_size: int = MAX_EVENTS_PER_ENVELOPE,
        max_read_bytes: int = MAX_SPOOL_FILE_BYTES,
    ) -> None:
        self.queue = queue
        self.directory = Path(directory)
        self.state_path = Path(state_path)
        self.max_object_bytes = max_object_bytes
        self.batch_size = max(1, min(batch_size, MAX_EVENTS_PER_ENVELOPE))
        self.max_read_bytes = max_read_bytes
        self._running = False
        self._lock = threading.Lock()
        self._files: dict[str, dict[str, Any]] = {}
        self._stats = {
            "events_enqueued": 0,
            "batches": 0,
            "lines_rejected": 0,
            "files": 0,
            "last_scan_at": None,
            "last_error": None,
            "running": False,
            "mode": "read_only_spool",
            "network_connections": 0,
        }

    def start(self) -> None:
        if not self.directory.exists():
            self.directory.mkdir(parents=True, exist_ok=True)
            logger.info("created OT spool directory %s", self.directory)
        if not self.directory.is_dir():
            raise CollectorError(f"OT spool path is not a directory: {self.directory}")
        self._load_state()
        with self._lock:
            self._running = True
            self._stats["running"] = True
        logger.info("OT spool collector started directory=%s read_only=true", self.directory)

    def _load_state(self) -> None:
        if not self.state_path.exists():
            self._files = {}
            return
        try:
            payload = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("ignoring unreadable OT offset state %s: %s", self.state_path, exc)
            self._files = {}
            return
        files = payload.get("files") if isinstance(payload, dict) else None
        self._files = {str(key): value for key, value in files.items() if isinstance(value, dict)} if files else {}

    def _save_state(self) -> None:
        write_private_json(self.state_path, {"version": 1, "files": self._files}, mode=0o600)

    def stop(self) -> None:
        with self._lock:
            self._running = False
            self._stats["running"] = False
        try:
            self._save_state()
        except OSError as exc:
            logger.error("cannot persist OT offsets: %s", exc)
        logger.info("OT spool collector stopped")

    def stats(self) -> dict[str, Any]:
        with self._lock:
            return dict(self._stats)

    def poll(self) -> int:
        if not self._running:
            return 0
        total = 0
        changed = False
        try:
            candidates = sorted(path for path in self.directory.iterdir() if path.is_file())
        except OSError as exc:
            self._record_error(f"cannot list OT spool: {exc}")
            return 0
        for path in candidates:
            if path.suffix.lower() not in {".jsonl", ".json"} or path.name.startswith("."):
                continue
            try:
                events, advanced = self._read_new(path)
                changed = changed or advanced
            except (OSError, CollectorError) as exc:
                self._record_error(f"{path.name}: {exc}")
                continue
            total += self._enqueue(events)
        if changed:
            try:
                self._save_state()
            except OSError as exc:
                self._record_error(f"cannot persist OT offsets: {exc}")
        with self._lock:
            self._stats["files"] = len(self._files)
            self._stats["last_scan_at"] = _now_iso()
        return total

    def _read_new(self, path: Path) -> tuple[list[dict[str, Any]], bool]:
        stat = path.stat()
        key = f"{path.name}:{stat.st_ino}"
        state = self._files.get(key, {"offset": 0, "size": 0})
        offset = int(state.get("offset", 0))
        if offset < 0 or stat.st_size < offset:
            offset = 0
        with path.open("rb") as handle:
            handle.seek(offset)
            data = handle.read(self.max_read_bytes)
        events: list[dict[str, Any]] = []
        consumed = 0
        rejected = 0
        for line in data.splitlines(keepends=True):
            if not line.endswith(b"\n"):
                break
            consumed += len(line)
            stripped = line.strip()
            if not stripped:
                continue
            if len(stripped) > self.max_object_bytes:
                rejected += 1
                continue
            try:
                event = json.loads(stripped)
            except json.JSONDecodeError:
                rejected += 1
                continue
            if not isinstance(event, dict):
                rejected += 1
                continue
            events.append(event)
        if rejected:
            with self._lock:
                self._stats["lines_rejected"] += rejected
                self._stats["last_error"] = f"{rejected} malformed OT observation(s) in {path.name}"
            logger.error("OT spool rejected_lines=%d file=%s", rejected, path.name)
        new_offset = offset + consumed
        if new_offset != offset:
            self._files[key] = {"offset": new_offset, "size": stat.st_size, "updated_at": _now_iso()}
        return events, new_offset != offset

    def _enqueue(self, events: list[dict[str, Any]]) -> int:
        if not events:
            return 0
        enqueued = 0
        for start in range(0, len(events), self.batch_size):
            chunk = events[start : start + self.batch_size]
            try:
                self.queue.enqueue("ot", chunk)
            except Exception as exc:
                self._record_error(f"queue enqueue failed: {exc}")
                break
            enqueued += len(chunk)
            with self._lock:
                self._stats["batches"] += 1
        with self._lock:
            self._stats["events_enqueued"] += enqueued
        return enqueued

    def _record_error(self, message: str) -> None:
        with self._lock:
            self._stats["last_error"] = message[:300]
        logger.error("%s", message)


__all__ = [
    "MAX_OBJECT_BYTES",
    "MAX_SPOOL_FILE_BYTES",
    "MAX_SYSLOG_DATAGRAM_BYTES",
    "CollectorError",
    "OtSpoolCollector",
    "SpoolCollector",
    "SyslogUDPCollector",
    "parse_syslog",
]
