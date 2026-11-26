"""Outbound HTTP with DNS pinning (SSRF/TOCTOU defence).

Validating a hostname and then letting an HTTP library resolve it again leaves a
DNS-rebinding window. This module connects through a custom ``httpcore`` network
backend: the hostname is resolved once inside ``connect_tcp``, every resolved
address is checked against the SSRF policy at that exact moment, and the socket
is opened to the validated IP. TLS still uses the original hostname for SNI and
certificate verification, so pinning does not weaken TLS.

Redirects are never followed. Response bodies are bounded.
"""

from __future__ import annotations

import ipaddress
import json
import socket
import ssl
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlsplit

import httpcore
from httpcore._backends.sync import SyncStream

from app.core.ssrf import SSRFError, assert_address_allowed, validate_outbound_url

DEFAULT_MAX_RESPONSE_BYTES = 2_000_000


class OutboundError(Exception):
    """Base class for sanitized outbound transport failures."""


class OutboundTimeout(OutboundError):
    pass


class OutboundTransportError(OutboundError):
    pass


class OutboundResponseTooLarge(OutboundError):
    pass


@dataclass(frozen=True)
class OutboundResponse:
    status_code: int
    headers: dict[str, str]
    content: bytes

    @property
    def text(self) -> str:
        return self.content.decode("utf-8", errors="replace")

    def json(self) -> Any:
        return json.loads(self.content)


class PinnedDNSBackend(httpcore.NetworkBackend):
    """Resolve, validate and connect to the same address (no second lookup)."""

    def __init__(self, *, allow_private: bool, allowed_private_cidrs: list[str] | None = None) -> None:
        self.allow_private = allow_private
        # ``None`` means "no allowlist configured" (connectors/MCP keep their
        # existing egress policy). An explicit list — including the empty list —
        # is enforced: empty therefore means deny all private destinations.
        self._enforce_allowlist = allowed_private_cidrs is not None
        self.allowed_private_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        for raw in allowed_private_cidrs or []:
            try:
                self.allowed_private_networks.append(ipaddress.ip_network(raw.strip(), strict=False))
            except ValueError as exc:
                raise ValueError(f"Invalid private allowlist CIDR: {raw}") from exc

    def _check(self, address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
        assert_address_allowed(address, allow_private=self.allow_private)
        if self._enforce_allowlist and not any(address in network for network in self.allowed_private_networks):
            raise SSRFError("Destination is outside the configured private allowlist")

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[Any] | None = None,
    ) -> SyncStream:
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise httpcore.ConnectError(f"Unable to resolve host: {host}") from exc

        resolved: list[tuple[int, int, int, tuple[Any, ...]]] = []
        for family, socktype, proto, _canonical, sockaddr in infos:
            try:
                address = ipaddress.ip_address(sockaddr[0])
            except ValueError as exc:
                raise httpcore.ConnectError("Resolver returned an invalid address") from exc
            try:
                self._check(address)
            except SSRFError as exc:
                raise httpcore.ConnectError(str(exc)) from exc
            resolved.append((family, socktype, proto, sockaddr))

        if not resolved:
            raise httpcore.ConnectError(f"Unable to resolve host: {host}")

        last_error: OSError | None = None
        for family2, socktype2, proto2, sockaddr2 in resolved:
            sock = socket.socket(family2, socktype2, proto2)
            try:
                if timeout is not None:
                    sock.settimeout(timeout)
                for option in socket_options or ():
                    sock.setsockopt(*option)
                if local_address:
                    sock.bind((local_address, 0))
                sock.connect(sockaddr2)
                return SyncStream(sock)
            except OSError as exc:
                last_error = exc
                sock.close()
        raise httpcore.ConnectError(f"Unable to connect to {host}:{port}: {last_error}")


def build_url(url: str, params: Mapping[str, Any] | None) -> str:
    if not params:
        return url
    encoded = urlencode({key: value for key, value in params.items() if value is not None}, doseq=True)
    if not encoded:
        return url
    separator = "&" if "?" in url else "?"
    return f"{url}{separator}{encoded}"


def request(
    method: str,
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    params: Mapping[str, Any] | None = None,
    json_body: Any = None,
    content: bytes | None = None,
    timeout: float = 20.0,
    allow_private: bool = False,
    require_https: bool = False,
    allowed_private_cidrs: list[str] | None = None,
    max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    user_agent: str = "HISPANSHIELD/1.0",
) -> OutboundResponse:
    """Perform a bounded outbound request with connection-time SSRF checks."""
    target = build_url(url, params)
    validate_outbound_url(target, allow_private=allow_private, require_https=require_https)

    body = content
    request_headers = {"User-Agent": user_agent, "Accept": "application/json", **(headers or {})}
    if json_body is not None:
        body = json.dumps(json_body, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        request_headers.setdefault("Content-Type", "application/json")

    ssl_context = ssl.create_default_context()
    network_backend = PinnedDNSBackend(allow_private=allow_private, allowed_private_cidrs=allowed_private_cidrs)
    pool = httpcore.ConnectionPool(
        ssl_context=ssl_context,
        network_backend=network_backend,
        max_connections=1,
        max_keepalive_connections=0,
        http2=False,
        retries=0,
    )
    response: httpcore.Response | None = None
    try:
        split = urlsplit(target)
        wire_headers = [(key.lower().encode(), value.encode()) for key, value in request_headers.items()]
        wire_headers.append((b"host", split.netloc.encode("latin-1")))
        if body is not None:
            wire_headers.append((b"content-length", str(len(body)).encode()))
        request_message = httpcore.Request(
            method=method.upper(),
            url=target,
            headers=wire_headers,
            content=body,
            extensions={"timeout": {"connect": timeout, "read": timeout, "write": timeout, "pool": timeout}},
        )
        # ``ConnectionPool.request`` consumes the body internally; handle_request
        # keeps the stream open so the size ceiling can be enforced while reading.
        response = pool.handle_request(request_message)
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_stream():
            total += len(chunk)
            if total > max_response_bytes:
                raise OutboundResponseTooLarge("Response exceeds the configured size limit")
            chunks.append(chunk)
        response_headers = {key.decode("latin-1").lower(): value.decode("latin-1") for key, value in response.headers}
        return OutboundResponse(status_code=response.status, headers=response_headers, content=b"".join(chunks))
    except httpcore.TimeoutException as exc:
        raise OutboundTimeout("Outbound request timed out") from exc
    except httpcore.NetworkError as exc:
        raise OutboundTransportError(str(exc)) from exc
    except httpcore.ProtocolError as exc:
        raise OutboundTransportError(f"Protocol error: {exc}") from exc
    finally:
        if response is not None:
            response.close()
        pool.close()
