"""SSRF protection for connector/AI/webhook egress.

Connectors may only reach http(s) endpoints that resolve exclusively to public
addresses unless the operator explicitly enables private networks (required for
on-premise Wazuh/Keycloak deployments, and documented as a trust decision).
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from app.core.config import settings

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

ALLOWED_SCHEMES = {"http", "https"}


class SSRFError(ValueError):
    pass


def _is_blocked(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        return True
    return any(address in network for network in _BLOCKED_NETWORKS)


def validate_outbound_url(url: str, *, allow_private: bool | None = None) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SSRFError("Only http and https URLs are permitted")
    if not parsed.hostname:
        raise SSRFError("URL must include a hostname")
    if parsed.username or parsed.password:
        raise SSRFError("URLs with embedded credentials are not permitted")
    try:
        port = parsed.port
    except ValueError as exc:
        raise SSRFError("Invalid port in URL") from exc
    host = parsed.hostname
    try:
        infos = socket.getaddrinfo(host, port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFError(f"Unable to resolve host: {host}") from exc
    if not infos:
        raise SSRFError(f"Unable to resolve host: {host}")
    permit_private = settings.connector_allow_private_networks if allow_private is None else allow_private
    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        # Cloud metadata endpoints are always blocked, even when private networks
        # are explicitly authorized for on-premise connectors or local AI models.
        if address in ipaddress.ip_network("169.254.0.0/16") or address in ipaddress.ip_network("100.100.100.200/32"):
            raise SSRFError("Cloud metadata endpoints are never reachable")
        if not permit_private and _is_blocked(address):
            raise SSRFError("Destination resolves to a private, loopback or reserved address")
    return url
