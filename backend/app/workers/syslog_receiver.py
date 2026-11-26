"""Bounded asyncio UDP/TCP syslog receiver.

The receiver is transport-only: it extracts a source token, resolves it through
an injected callback, parses RFC 3164 / RFC 5424 / CEF / LEEF and hands the
normalized event to an injected sink.  Nothing starts at import time.

Token envelope (optional)::

    HS-TOKEN:<ingestion-token> <34>1 2026-01-01T10:00:00Z host app - - - message

When no envelope is present, ``default_token`` (typically ``HS_SYSLOG_TOKEN``)
is used so a dedicated listener can be bound to one source.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import re
import time
from collections.abc import Awaitable, Callable, Coroutine
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from app.services.normalization import NormalizedEvent, ParseError, parse_payload

logger = logging.getLogger("hispanshield.syslog")

_TOKEN_ENVELOPE_RE = re.compile(rb"^HS-TOKEN:([A-Za-z0-9_\-]{1,200})\s+", re.IGNORECASE)
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_\-]{1,200}$")


@dataclass(frozen=True, slots=True)
class SourceBinding:
    """Minimal source identity resolved from an ingestion token."""

    org_id: UUID | str
    source_id: UUID | str
    name: str = ""
    parser: str = "auto"


Resolver = Callable[[str], SourceBinding | None | Awaitable[SourceBinding | None]]
Sink = Callable[[SourceBinding, bytes, NormalizedEvent], Any | Awaitable[Any]]


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


class SyslogReceiver:
    """UDP + TCP syslog listener with per-source rate limiting and graceful shutdown."""

    def __init__(
        self,
        *,
        resolver: Resolver,
        sink: Sink,
        default_token: str | None = None,
        host: str = "127.0.0.1",  # loopback by default; operators may bind explicitly
        udp_port: int = 5514,
        tcp_port: int = 5514,
        max_message_bytes: int = 16384,
        rate_limit_per_minute: int = 1200,
        tcp_idle_timeout: float = 60.0,
    ) -> None:
        if max_message_bytes < 512:
            raise ValueError("max_message_bytes must be at least 512")
        self._resolver = resolver
        self._sink = sink
        self._default_token = default_token
        self.host = host
        self.udp_port = udp_port
        self.tcp_port = tcp_port
        self.max_message_bytes = max_message_bytes
        self.rate_limit_per_minute = rate_limit_per_minute
        self.tcp_idle_timeout = tcp_idle_timeout

        self._transport: asyncio.DatagramTransport | None = None
        self._server: asyncio.AbstractServer | None = None
        self._stop_event = asyncio.Event()
        self._tasks: set[asyncio.Task[Any]] = set()
        self._rate: dict[str, tuple[int, int]] = {}
        self._started = False
        self.bound_udp_port: int | None = None
        self.bound_tcp_port: int | None = None
        self.counters: dict[str, int] = {
            "received": 0,
            "accepted": 0,
            "rejected_oversize": 0,
            "rejected_unknown_source": 0,
            "rejected_parse_error": 0,
            "rejected_store_error": 0,
            "rate_limited": 0,
            "tcp_connections": 0,
        }

    # -- lifecycle ---------------------------------------------------------
    async def start(self) -> None:
        if self._started:
            raise RuntimeError("Syslog receiver is already started")
        loop = asyncio.get_running_loop()
        self._stop_event.clear()
        try:
            self._transport, _ = await loop.create_datagram_endpoint(
                lambda: _UDPProtocol(self),
                local_addr=(self.host, self.udp_port),
            )
            sockname = self._transport.get_extra_info("sockname")
            self.bound_udp_port = int(sockname[1]) if sockname else self.udp_port
            self._server = await asyncio.start_server(
                self._handle_tcp_client,
                host=self.host,
                port=self.tcp_port,
                limit=self.max_message_bytes + 2,
            )
        except Exception:
            if self._transport is not None:
                self._transport.close()
                self._transport = None
            if self._server is not None:
                self._server.close()
                self._server = None
            raise
        if self._server.sockets:
            self.bound_tcp_port = int(self._server.sockets[0].getsockname()[1])
        else:
            self.bound_tcp_port = self.tcp_port
        self._started = True
        logger.info(
            "syslog_receiver_started",
            extra={"udp_port": self.bound_udp_port, "tcp_port": self.bound_tcp_port},
        )

    def request_stop(self) -> None:
        self._stop_event.set()

    async def wait_closed(self) -> None:
        await self._stop_event.wait()
        await self._shutdown()

    async def stop(self) -> None:
        self._stop_event.set()
        await self._shutdown()

    async def _shutdown(self) -> None:
        if not self._started:
            return
        self._started = False
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        pending = [task for task in self._tasks if not task.done()]
        if pending:
            try:
                await asyncio.wait_for(asyncio.gather(*pending, return_exceptions=True), timeout=5)
            except TimeoutError:
                for task in pending:
                    task.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
        logger.info("syslog_receiver_stopped", extra={"counters": dict(self.counters)})

    # -- message handling --------------------------------------------------
    def _extract_token(self, raw: bytes) -> tuple[str | None, bytes]:
        match = _TOKEN_ENVELOPE_RE.match(raw)
        if match:
            return match.group(1).decode("ascii"), raw[match.end() :]
        if raw.startswith((b"HS-TOKEN:", b"hs-token:")):
            return "", raw
        return None, raw

    def _allow(self, key: str) -> bool:
        if self.rate_limit_per_minute <= 0:
            return True
        window = int(time.monotonic() // 60)
        previous_window, count = self._rate.get(key, (window, 0))
        if previous_window != window:
            count = 0
        count += 1
        self._rate[key] = (window, count)
        if len(self._rate) > 10000:
            self._rate = {name: value for name, value in self._rate.items() if value[0] == window}
        return count <= self.rate_limit_per_minute

    async def handle_message(
        self,
        raw: bytes,
        *,
        peer: tuple[str, int] | str | None = None,
    ) -> dict[str, int]:
        """Parse and store one datagram/line. Returns accepted/rejected counters."""
        result = {"accepted": 0, "rejected": 0}
        self.counters["received"] += 1
        if len(raw) > self.max_message_bytes:
            self.counters["rejected_oversize"] += 1
            result["rejected"] = 1
            return result
        token, payload = self._extract_token(raw)
        if token == "":
            self.counters["rejected_unknown_source"] += 1
            result["rejected"] = 1
            return result
        if token is None:
            token = self._default_token
        binding = None
        if token:
            if not _TOKEN_RE.match(token):
                binding = None
            else:
                try:
                    binding = await _maybe_await(self._resolver(token))
                except Exception:
                    logger.exception("syslog_resolver_error")
                    binding = None
        if binding is None:
            self.counters["rejected_unknown_source"] += 1
            result["rejected"] = 1
            return result
        if not self._allow(str(binding.source_id)):
            self.counters["rate_limited"] += 1
            result["rejected"] = 1
            return result
        try:
            events = parse_payload(payload, parser=binding.parser or "auto")
        except ParseError as exc:
            self.counters["rejected_parse_error"] += 1
            result["rejected"] = 1
            logger.warning("syslog_parse_error", extra={"code": exc.code, "peer": str(peer)})
            return result
        for event in events:
            try:
                await _maybe_await(self._sink(binding, payload, event))
            except Exception:
                self.counters["rejected_store_error"] += 1
                result["rejected"] += 1
                logger.exception("syslog_sink_error", extra={"peer": str(peer)})
                continue
            self.counters["accepted"] += 1
            result["accepted"] += 1
        return result

    def _spawn(self, coroutine: Coroutine[Any, Any, Any]) -> None:
        task: asyncio.Task[Any] = asyncio.create_task(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle_datagram(self, data: bytes, addr: tuple[str, int]) -> None:
        try:
            await self.handle_message(data, peer=addr)
        except Exception:  # pragma: no cover - last-resort isolation
            logger.exception("syslog_datagram_error")

    async def _handle_tcp_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        self.counters["tcp_connections"] += 1
        peer = writer.get_extra_info("peername")
        try:
            while not self._stop_event.is_set():
                try:
                    line = await asyncio.wait_for(reader.readline(), timeout=self.tcp_idle_timeout)
                except (TimeoutError, ValueError, asyncio.LimitOverrunError):
                    break
                if not line:
                    break
                raw_line = line.rstrip(b"\r\n")
                if raw_line:
                    await self.handle_message(raw_line, peer=peer)
        except (ConnectionResetError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except (ConnectionResetError, BrokenPipeError):
                pass

    def stats(self) -> dict[str, int]:
        payload = dict(self.counters)
        payload["bound_udp_port"] = int(self.bound_udp_port or 0)
        payload["bound_tcp_port"] = int(self.bound_tcp_port or 0)
        return payload


class _UDPProtocol(asyncio.DatagramProtocol):
    def __init__(self, receiver: SyslogReceiver) -> None:
        self._receiver = receiver

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        self._receiver._spawn(self._receiver._handle_datagram(data, addr))

    def error_received(self, exc: Exception) -> None:  # pragma: no cover - transport errors
        logger.warning("syslog_udp_error", extra={"error": str(exc)[:200]})


__all__ = ["SourceBinding", "SyslogReceiver"]
