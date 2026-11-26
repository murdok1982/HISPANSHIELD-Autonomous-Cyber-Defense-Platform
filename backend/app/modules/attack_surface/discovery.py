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
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.core.errors import NotFound, PolicyDenied, ValidationFailure
from app.models.assets import Asset, DiscoveryAuthorization
from app.modules.attack_surface.schemas import MAX_SCOPE_CIDRS

PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
)
LOOPBACK_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (ipaddress.IPv4Network("127.0.0.0/8"),)
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


# ---------------------------------------------------------------------------
# Dual-control discovery authorization
# ---------------------------------------------------------------------------

AUTHORIZATION_APPROVED = "approved"
AUTHORIZATION_PENDING = "pending"
AUTHORIZATION_EXPIRED = "expired"
AUTHORIZATION_REVOKED = "revoked"


def as_utc(value: datetime) -> datetime:
    return value.astimezone(UTC) if value.tzinfo else value.replace(tzinfo=UTC)


def authorization_status(auth: DiscoveryAuthorization, *, now: datetime | None = None) -> str:
    current = now or utcnow()
    if auth.revoked_at is not None:
        return AUTHORIZATION_REVOKED
    if auth.approved_at is None:
        return AUTHORIZATION_PENDING
    if as_utc(auth.expires_at) <= current:
        return AUTHORIZATION_EXPIRED
    return AUTHORIZATION_APPROVED


def load_authorization(db: Session, org_id: UUID, authorization_id: UUID) -> DiscoveryAuthorization:
    authorization = db.get(DiscoveryAuthorization, authorization_id)
    if authorization is None or authorization.org_id != org_id:
        # Cross-tenant identifiers are indistinguishable from missing ones.
        raise NotFound("Discovery authorization")
    return authorization


def ensure_authorization_usable(auth: DiscoveryAuthorization, *, now: datetime | None = None) -> None:
    status = authorization_status(auth, now=now)
    if status == AUTHORIZATION_REVOKED:
        raise PolicyDenied(
            "Discovery authorization has been revoked",
            details=[{"field": "authorization_id", "message": "Authorization revoked"}],
        )
    if status == AUTHORIZATION_PENDING:
        raise PolicyDenied(
            "Discovery authorization has not been approved",
            details=[{"field": "authorization_id", "message": "Approval is required before discovery"}],
        )
    if status == AUTHORIZATION_EXPIRED:
        raise PolicyDenied(
            "Discovery authorization has expired",
            details=[{"field": "authorization_id", "message": "Authorization expired"}],
        )


def authorized_networks(auth: DiscoveryAuthorization) -> list[ipaddress.IPv4Network]:
    return validate_scope_cidrs(list(auth.cidrs or []), required=True)


def ensure_scope_authorized(
    scope_cidrs: list[str], auth: DiscoveryAuthorization, *, required: bool = True
) -> list[ipaddress.IPv4Network]:
    """Reject any requested scope that is not a subnet of the authorized CIDRs."""
    networks = validate_scope_cidrs(scope_cidrs, required=required)
    allowed = authorized_networks(auth)
    for network in networks:
        if not any(network.subnet_of(candidate) for candidate in allowed):
            raise PolicyDenied(
                f"Scope {network} is outside the approved discovery authorization",
                details=[{"field": "scope_cidrs", "message": f"{network} is not authorized"}],
            )
    total_hosts = sum(network.num_addresses for network in networks)
    if total_hosts > int(auth.max_hosts):
        raise PolicyDenied(
            f"Scope covers {total_hosts} addresses but the authorization allows {auth.max_hosts}",
            details=[{"field": "scope_cidrs", "message": "Scope exceeds the authorized host budget"}],
        )
    return networks


def ensure_ports_authorized(ports: list[int], auth: DiscoveryAuthorization) -> list[int]:
    """Reject probes for ports the authorization does not explicitly cover."""
    selected = normalize_ports(ports)
    allowed = {int(port) for port in (auth.ports or [])}
    outside = [port for port in selected if port not in allowed]
    if outside:
        raise PolicyDenied(
            "Requested ports are outside the approved discovery authorization",
            details=[{"field": "ports", "message": f"Unauthorized ports: {outside}"}],
        )
    return selected


__all__ = [
    "ALLOWED_NETWORKS",
    "AUTHORIZATION_APPROVED",
    "AUTHORIZATION_EXPIRED",
    "AUTHORIZATION_PENDING",
    "AUTHORIZATION_REVOKED",
    "CONNECT_TIMEOUT_SECONDS",
    "DEFAULT_PORTS",
    "MAX_CONCURRENCY",
    "MAX_SCOPE_HOSTS",
    "as_utc",
    "authorization_status",
    "authorized_networks",
    "elapsed_ms",
    "ensure_authorization_usable",
    "ensure_ports_authorized",
    "ensure_scope_authorized",
    "ip_in_scope",
    "load_authorization",
    "normalize_ports",
    "ot_asset_addresses",
    "probe_hosts",
    "run_metadata",
    "scope_hosts",
    "validate_scope_cidrs",
]
