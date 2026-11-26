"""Bounded, authorized reachability probing for attack-surface discovery.

Hard limits (defence in depth, enforced server-side):

* IPv4 only, RFC 1918 private ranges only. Loopback (``127.0.0.0/8``) is
  accepted **solely** so local/lab verification can exercise the probe against
  a loopback TCP server; it is never routable from the platform host.
* Each scope must be /24 or narrower (>= 24 prefix) and the combined scope is
  capped at 256 addresses.
* 0.3 s TCP connect timeout, 32 concurrent sockets and a 5 ms spacing between
  probes provide a hard rate limit. No payload is sent: the probe opens a TCP
  handshake and closes it immediately.
* OT assets are always excluded, regardless of the requested scope.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ValidationFailure
from app.models.assets import Asset
from app.modules.attack_surface.schemas import MAX_SCOPE_CIDRS

PRIVATE_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)
LOOPBACK_NETWORKS = (ipaddress.ip_network("127.0.0.0/8"),)
ALLOWED_NETWORKS = PRIVATE_NETWORKS + LOOPBACK_NETWORKS

MAX_SCOPE_HOSTS = 256
MIN_PREFIX_LEN = 24
CONNECT_TIMEOUT_SECONDS = 0.3
MAX_CONCURRENCY = 32
PROBE_SPACING_SECONDS = 0.005
DEFAULT_PORTS = (22, 80, 443, 445, 3389)


def validate_scope_cidrs(cidrs: list[str], *, required: bool = False) -> list[ipaddress.IPv4Network]:
    """Validate and normalise a discovery scope.

    Raises :class:`ValidationFailure` (422) with a field-level reason for public
    ranges, IPv6, overly broad prefixes and excessive host counts.
    """
    if not cidrs:
        if required:
            raise ValidationFailure([{"field": "scope_cidrs", "message": "At least one CIDR is required"}])
        return []
    if len(cidrs) > MAX_SCOPE_CIDRS:
        raise ValidationFailure([{"field": "scope_cidrs", "message": f"At most {MAX_SCOPE_CIDRS} CIDRs are allowed"}])
    networks: list[ipaddress.IPv4Network] = []
    total_hosts = 0
    for raw in cidrs:
        try:
            network = ipaddress.ip_network(raw.strip(), strict=True)
        except ValueError as exc:
            raise ValidationFailure([{"field": "scope_cidrs", "message": f"Invalid CIDR: {raw}"}]) from exc
        if network.version != 4:
            raise ValidationFailure([{"field": "scope_cidrs", "message": f"IPv6 is not supported: {raw}"}])
        assert isinstance(network, ipaddress.IPv4Network)
        if network.prefixlen < MIN_PREFIX_LEN:
            raise ValidationFailure(
                [
                    {
                        "field": "scope_cidrs",
                        "message": f"Scope {raw} is too broad; use /{MIN_PREFIX_LEN} or narrower",
                    }
                ]
            )
        if not any(network.subnet_of(allowed) for allowed in ALLOWED_NETWORKS):
            raise ValidationFailure(
                [
                    {
                        "field": "scope_cidrs",
                        "message": f"Scope {raw} is not a private RFC 1918 range; public scanning is refused",
                    }
                ]
            )
        total_hosts += network.num_addresses
        if total_hosts > MAX_SCOPE_HOSTS:
            raise ValidationFailure(
                [
                    {
                        "field": "scope_cidrs",
                        "message": f"Scope exceeds {MAX_SCOPE_HOSTS} addresses",
                    }
                ]
            )
        networks.append(network)
    return networks


def normalize_ports(ports: list[int] | None) -> list[int]:
    selected = sorted({int(port) for port in (ports or DEFAULT_PORTS)})
    if not selected:
        raise ValidationFailure([{"field": "ports", "message": "At least one port is required"}])
    if len(selected) > 32:
        raise ValidationFailure([{"field": "ports", "message": "At most 32 ports can be probed"}])
    if any(port < 1 or port > 65535 for port in selected):
        raise ValidationFailure([{"field": "ports", "message": "Ports must be within 1-65535"}])
    return selected


def scope_hosts(networks: list[ipaddress.IPv4Network]) -> list[str]:
    hosts: list[str] = []
    for network in networks:
        for address in network.hosts():
            hosts.append(str(address))
            if len(hosts) > MAX_SCOPE_HOSTS:
                raise ValidationFailure([{"field": "scope_cidrs", "message": f"Scope exceeds {MAX_SCOPE_HOSTS} hosts"}])
    return hosts


def ip_in_scope(value: str, networks: list[ipaddress.IPv4Network]) -> bool:
    if not networks:
        return True
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if address.version != 4:
        return False
    return any(address in network for network in networks)


async def _probe(ip: str, port: int, semaphore: asyncio.Semaphore) -> bool:
    async with semaphore:
        await asyncio.sleep(PROBE_SPACING_SECONDS)
        try:
            _reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=CONNECT_TIMEOUT_SECONDS)
        except (TimeoutError, OSError):
            return False
        try:
            writer.close()
            await writer.wait_closed()
        except (TimeoutError, OSError):
            pass
        return True


async def probe_hosts(hosts: list[str], ports: list[int]) -> dict[str, list[int]]:
    """TCP-connect probe; returns ``{ip: [open ports]}`` with deterministic order."""
    if not hosts or not ports:
        return {}
    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    tasks = [(ip, port, asyncio.create_task(_probe(ip, port, semaphore))) for ip in hosts for port in ports]
    open_ports: dict[str, list[int]] = {}
    for ip, port, task in tasks:
        if await task:
            open_ports.setdefault(ip, []).append(port)
    return {ip: sorted(ports_found) for ip, ports_found in sorted(open_ports.items())}


def ot_asset_addresses(db: Session, org_id: Any) -> set[str]:
    rows = db.execute(select(Asset.ip_addresses).where(Asset.org_id == org_id, Asset.kind == "ot")).scalars()
    addresses: set[str] = set()
    for values in rows:
        for value in values or []:
            addresses.add(str(value))
    return addresses


def run_metadata(scope: list[str], ports: list[int]) -> dict[str, Any]:
    return {
        "scope_cidrs": scope,
        "ports": ports,
        "timeout_seconds": CONNECT_TIMEOUT_SECONDS,
        "max_concurrency": MAX_CONCURRENCY,
        "max_scope_hosts": MAX_SCOPE_HOSTS,
    }


def elapsed_ms(started: float) -> int:
    return int((time.monotonic() - started) * 1000)


__all__ = [
    "ALLOWED_NETWORKS",
    "CONNECT_TIMEOUT_SECONDS",
    "DEFAULT_PORTS",
    "MAX_CONCURRENCY",
    "MAX_SCOPE_HOSTS",
    "elapsed_ms",
    "ip_in_scope",
    "normalize_ports",
    "ot_asset_addresses",
    "probe_hosts",
    "run_metadata",
    "scope_hosts",
    "validate_scope_cidrs",
]
