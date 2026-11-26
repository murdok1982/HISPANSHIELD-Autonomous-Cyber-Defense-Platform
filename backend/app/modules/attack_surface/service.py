"""Attack-surface analysis and discovery execution (authorized, bounded)."""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.core.errors import PolicyDenied, ValidationFailure
from app.models.assets import Asset, AttackSurfaceFinding, DiscoveryAuthorization, DiscoveryJob
from app.models.events import SecurityEvent
from app.modules.assets.service import asset_public_ip
from app.modules.attack_surface import discovery
from app.modules.attack_surface.schemas import AnalyzeResult, FindingSummaryOut

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_NAMES = ("info", "low", "medium", "high", "critical")

PORT_RISK: dict[int, tuple[str, str]] = {
    21: ("FTP", "high"),
    22: ("SSH", "medium"),
    23: ("Telnet", "critical"),
    25: ("SMTP", "medium"),
    80: ("HTTP", "medium"),
    102: ("S7/MMS", "critical"),
    161: ("SNMP", "medium"),
    443: ("HTTPS", "low"),
    445: ("SMB", "high"),
    502: ("Modbus TCP", "critical"),
    1911: ("Niagara Fox", "high"),
    2404: ("IEC 60870-5-104", "critical"),
    3306: ("MySQL", "high"),
    3389: ("RDP", "high"),
    5432: ("PostgreSQL", "high"),
    5900: ("VNC", "high"),
    6379: ("Redis", "critical"),
    8080: ("HTTP-ALT", "medium"),
    8443: ("HTTPS-ALT", "low"),
    9200: ("Elasticsearch", "high"),
    11211: ("Memcached", "high"),
    20000: ("DNP3", "critical"),
    27017: ("MongoDB", "critical"),
    44818: ("EtherNet/IP", "high"),
    47808: ("BACnet", "high"),
}
OT_CRITICAL_PORTS = {102, 502, 2404, 20000, 44818, 47808}

SERVICE_PORT_HINTS = {
    "telnet": 23,
    "ftp": 21,
    "ssh": 22,
    "rdp": 3389,
    "smb": 445,
    "vnc": 5900,
    "mysql": 3306,
    "postgresql": 5432,
    "postgres": 5432,
    "redis": 6379,
    "mongodb": 27017,
    "snmp": 161,
    "modbus": 502,
    "dnp3": 20000,
    "iec104": 2404,
    "bacnet": 47808,
    "ethernet/ip": 44818,
}

EOL_PATTERNS = (
    "windows xp",
    "windows 7",
    "windows 8",
    "windows server 2003",
    "windows server 2008",
    "windows server 2012",
    "centos 6",
    "centos 7",
    "centos 8",
    "debian 8",
    "debian 9",
    "ubuntu 14.04",
    "ubuntu 16.04",
    "ubuntu 18.04",
    "python 2",
    "php 5",
    "php 7.0",
    "php 7.1",
    "end of life",
    "end-of-life",
    "unsupported firmware",
    "eol firmware",
)

CERT_EXPIRY_SOON = timedelta(days=30)
EVENT_LOOKBACK = timedelta(hours=24)
MAX_ANALYZED_ASSETS = 5000


def max_severity(*severities: str) -> str:
    return max(severities, key=lambda value: SEVERITY_ORDER.get(value, 0))


def _upsert_finding(
    db: Session,
    org_id: UUID,
    *,
    asset_id: UUID | None,
    kind: str,
    title: str,
    severity: str,
    evidence: str | None,
    source: str,
    metadata: dict[str, Any] | None = None,
) -> bool:
    """Create or refresh a deterministic finding. Returns True when created."""
    stmt = select(AttackSurfaceFinding).where(
        AttackSurfaceFinding.org_id == org_id,
        AttackSurfaceFinding.kind == kind,
        AttackSurfaceFinding.title == title,
    )
    stmt = stmt.where(
        AttackSurfaceFinding.asset_id == asset_id if asset_id is not None else AttackSurfaceFinding.asset_id.is_(None)
    )
    existing = db.execute(stmt).scalar_one_or_none()
    now = utcnow()
    if existing is not None:
        existing.last_seen = now
        existing.severity = max_severity(existing.severity, severity)
        if evidence and (not existing.evidence or evidence not in existing.evidence):
            existing.evidence = f"{existing.evidence}\n{evidence}"[-8000:] if existing.evidence else evidence
        if metadata:
            merged = dict(existing.metadata_json or {})
            merged.update(metadata)
            existing.metadata_json = merged
        return False
    db.add(
        AttackSurfaceFinding(
            org_id=org_id,
            asset_id=asset_id,
            kind=kind,
            title=title[:300],
            severity=severity,
            status="open",
            evidence=evidence,
            source=source,
            first_seen=now,
            last_seen=now,
            metadata_json=metadata or {},
        )
    )
    db.flush()
    return True


def _ports_from_metadata(metadata: dict[str, Any]) -> list[tuple[int | None, str]]:
    results: list[tuple[int | None, str]] = []
    seen: set[tuple[int | None, str]] = set()
    for raw in metadata.get("exposed_ports") or []:
        port: int | None = None
        if isinstance(raw, bool):
            continue
        if isinstance(raw, int):
            port = raw
        elif isinstance(raw, str):
            digits = raw.strip()
            if digits.isdigit():
                port = int(digits)
            else:
                lowered = digits.lower()
                hint = SERVICE_PORT_HINTS.get(lowered)
                if hint is not None:
                    port = hint
        name = PORT_RISK.get(port, (f"port {port}", "medium"))[0] if port else "unknown"
        key = (port, name)
        if key not in seen:
            seen.add(key)
            results.append(key)
    for raw in metadata.get("services") or []:
        service_name: str | None = None
        service_port: int | None = None
        if isinstance(raw, dict):
            candidate_port = raw.get("port")
            if isinstance(candidate_port, int):
                service_port = candidate_port
            candidate_name = raw.get("name") or raw.get("service")
            if isinstance(candidate_name, str):
                service_name = candidate_name.strip()[:80]
        elif isinstance(raw, str):
            service_name = raw.strip()[:80]
        if service_name is not None and service_port is None:
            service_port = SERVICE_PORT_HINTS.get(service_name.lower())
        label = service_name or (
            PORT_RISK.get(service_port, (f"port {service_port}", "medium"))[0] if service_port else None
        )
        if label is None:
            continue
        key = (service_port, label)
        if key not in seen:
            seen.add(key)
            results.append(key)
    return results


def _severity_for_port(asset: Asset, port: int | None) -> tuple[str, str]:
    label, severity = PORT_RISK.get(port or -1, (f"port {port}", "medium"))
    if asset.kind == "ot" and port in OT_CRITICAL_PORTS:
        severity = "critical"
    return label, severity


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, int | float) and not isinstance(value, bool):
        try:
            return datetime.fromtimestamp(float(value), tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str):
        token = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(token)
        except ValueError:
            return None
        return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)
    return None


def _find_eol(asset: Asset) -> str | None:
    if (asset.metadata_json or {}).get("eol") is True:
        return "asset metadata flags end-of-life"
    haystack = " ".join(
        value.lower()
        for value in (asset.os_name, asset.firmware, asset.model, asset.vendor)
        if isinstance(value, str) and value
    )
    if not haystack:
        return None
    for pattern in EOL_PATTERNS:
        if pattern in haystack:
            return pattern
    return None


def _analyze_asset(db: Session, org_id: UUID, asset: Asset) -> list[tuple[str, str, str, str, dict[str, Any]]]:
    findings: list[tuple[str, str, str, str, dict[str, Any]]] = []

    for ip in asset_public_ip(asset):
        severity = "high" if asset.criticality >= 4 else "medium"
        findings.append(
            (
                "public_exposure",
                f"Public IP exposure: {ip}",
                severity,
                f"Asset advertises globally routable address {ip}",
                {"ip": ip},
            )
        )

    metadata = asset.metadata_json or {}
    for port, label in _ports_from_metadata(metadata):
        resolved_label, severity = _severity_for_port(asset, port)
        title = f"Exposed service {resolved_label} on port {port}" if port else f"Exposed service {resolved_label}"
        findings.append(
            (
                "exposed_service",
                title,
                severity,
                f"Metadata reports {label} reachable on port {port}" if port else f"Metadata reports {label}",
                {"port": port, "service": label},
            )
        )

    if not asset.owner or not asset.owner.strip():
        findings.append(
            (
                "missing_owner",
                "Asset has no accountable owner",
                "low",
                "No owner is assigned to this asset",
                {"asset_key": asset.asset_key},
            )
        )

    if asset.confidence < 70:
        findings.append(
            (
                "unverified_asset",
                f"Low-confidence discovery ({asset.confidence}%)",
                "medium",
                f"Discovery source '{asset.discovery_source}' reported {asset.confidence}% confidence",
                {"confidence": asset.confidence, "discovery_source": asset.discovery_source},
            )
        )

    eol = _find_eol(asset)
    if eol:
        findings.append(
            (
                "end_of_life_software",
                f"End-of-life software detected: {eol}",
                "high",
                f"OS/firmware metadata matches end-of-life pattern '{eol}'",
                {"pattern": eol, "os_name": asset.os_name, "firmware": asset.firmware},
            )
        )

    for certificate in metadata.get("certificates") or []:
        if not isinstance(certificate, dict):
            continue
        subject = str(
            certificate.get("subject")
            or certificate.get("cn")
            or certificate.get("common_name")
            or certificate.get("serial")
            or "certificate"
        )[:200]
        expires = _parse_datetime(certificate.get("expires_at") or certificate.get("not_after"))
        if expires is not None:
            now = utcnow()
            if expires <= now:
                findings.append(
                    (
                        "expired_certificate",
                        f"Expired certificate: {subject}",
                        "high",
                        f"Certificate expired on {expires.isoformat()}",
                        {"subject": subject, "expires_at": expires.isoformat()},
                    )
                )
            elif expires - now <= CERT_EXPIRY_SOON:
                findings.append(
                    (
                        "expiring_certificate",
                        f"Certificate expiring soon: {subject}",
                        "medium",
                        f"Certificate expires on {expires.isoformat()}",
                        {"subject": subject, "expires_at": expires.isoformat()},
                    )
                )
        if certificate.get("self_signed") is True:
            findings.append(
                (
                    "self_signed_certificate",
                    f"Self-signed certificate: {subject}",
                    "medium",
                    "Certificate is self-signed and therefore not anchored to a trusted CA",
                    {"subject": subject},
                )
            )
    return findings


def analyze(db: Session, org_id: UUID) -> AnalyzeResult:
    """Inspect real inventory rows and materialise deduplicated findings."""
    assets = list(
        db.execute(
            select(Asset).where(Asset.org_id == org_id).order_by(Asset.id.asc()).limit(MAX_ANALYZED_ASSETS)
        ).scalars()
    )
    created = 0
    updated = 0
    by_kind: dict[str, int] = {}
    for asset in assets:
        for kind, title, severity, evidence, metadata in _analyze_asset(db, org_id, asset):
            is_new = _upsert_finding(
                db,
                org_id,
                asset_id=asset.id,
                kind=kind,
                title=title,
                severity=severity,
                evidence=evidence,
                source="inventory",
                metadata=metadata,
            )
            if is_new:
                created += 1
                by_kind[kind] = by_kind.get(kind, 0) + 1
            else:
                updated += 1
    return AnalyzeResult(scanned_assets=len(assets), created=created, updated=updated, by_kind=by_kind)


def finding_summary(db: Session, org_id: UUID) -> FindingSummaryOut:
    rows = db.execute(
        select(AttackSurfaceFinding.severity, AttackSurfaceFinding.kind, AttackSurfaceFinding.status, func.count())
        .where(AttackSurfaceFinding.org_id == org_id)
        .group_by(AttackSurfaceFinding.severity, AttackSurfaceFinding.kind, AttackSurfaceFinding.status)
    ).all()
    by_severity: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    by_status: dict[str, int] = {}
    total = 0
    for severity, kind, status, count in rows:
        total += count
        by_severity[severity] = by_severity.get(severity, 0) + count
        by_kind[kind] = by_kind.get(kind, 0) + count
        by_status[status] = by_status.get(status, 0) + count
    return FindingSummaryOut(total=total, by_severity=by_severity, by_kind=by_kind, by_status=by_status)


def _asset_ip_map(db: Session, org_id: UUID) -> dict[str, UUID]:
    mapping: dict[str, UUID] = {}
    for asset in db.execute(select(Asset).where(Asset.org_id == org_id)).scalars():
        for ip in asset.ip_addresses or []:
            mapping.setdefault(str(ip), asset.id)
    return mapping


async def run_active(db: Session, org_id: UUID, job: DiscoveryJob, ports: list[int]) -> dict[str, Any]:
    """Perform an authorized, bounded TCP-connect probe of private ranges only."""
    if job.authorization_id is None:
        raise PolicyDenied(
            "Discovery requires a linked, approved authorization",
            details=[{"field": "authorization_id", "message": "Discovery authorization is mandatory"}],
        )
    networks = discovery.validate_scope_cidrs(job.scope_cidrs, required=True)
    selected_ports = discovery.normalize_ports(ports)
    hosts = discovery.scope_hosts(networks)
    ot_addresses = discovery.ot_asset_addresses(db, org_id)
    targets = [host for host in hosts if host not in ot_addresses]
    excluded = len(hosts) - len(targets)
    ip_map = _asset_ip_map(db, org_id)

    started = time.monotonic()
    open_ports = await discovery.probe_hosts(targets, selected_ports)
    duration = discovery.elapsed_ms(started)

    created = 0
    updated = 0
    for ip, ports_found in open_ports.items():
        asset_id = ip_map.get(ip)
        for port in ports_found:
            label, severity = PORT_RISK.get(port, (f"port {port}", "medium"))[0:2]
            is_new = _upsert_finding(
                db,
                org_id,
                asset_id=asset_id,
                kind="discovered_open_port",
                title=f"TCP port {port} reachable on {ip} ({label})",
                severity=severity,
                evidence=(
                    f"TCP connect probe with {discovery.CONNECT_TIMEOUT_SECONDS}s timeout, "
                    f"authorization '{job.authorization_reference}'"
                ),
                source="discovery",
                metadata={
                    "ip": ip,
                    "port": port,
                    "service": label,
                    "mode": "active",
                    "job_id": str(job.id),
                    "authorization_reference": job.authorization_reference,
                },
            )
            created += int(is_new)
            updated += int(not is_new)

    return {
        "mode": "active",
        "scope_cidrs": job.scope_cidrs,
        "authorization_id": str(job.authorization_id) if job.authorization_id else None,
        "ports": selected_ports,
        "hosts_in_scope": len(hosts),
        "hosts_scanned": len(targets),
        "ot_hosts_excluded": excluded,
        "open_ports": open_ports,
        "findings_created": created,
        "findings_updated": updated,
        "duration_ms": duration,
        "probe": "tcp_connect",
        "payload_sent": False,
    }


def run_passive(db: Session, org_id: UUID, job: DiscoveryJob) -> dict[str, Any]:
    """Import observed flow/asset metadata without any network interaction."""
    networks = discovery.validate_scope_cidrs(job.scope_cidrs, required=False)
    assets = list(db.execute(select(Asset).where(Asset.org_id == org_id)).scalars())
    in_scope_assets = [
        asset
        for asset in assets
        if not networks or any(discovery.ip_in_scope(str(ip), networks) for ip in (asset.ip_addresses or []))
    ]
    created = 0
    updated = 0
    services_observed = 0
    for asset in in_scope_assets:
        metadata = asset.metadata_json or {}
        for port, label in _ports_from_metadata(metadata):
            services_observed += 1
            resolved_label, severity = _severity_for_port(asset, port)
            is_new = _upsert_finding(
                db,
                org_id,
                asset_id=asset.id,
                kind="observed_service",
                title=f"Observed service {resolved_label} on {asset.asset_key}",
                severity=severity,
                evidence="Imported from observed flow/asset records (passive mode, no probing)",
                source="passive_discovery",
                metadata={
                    "port": port,
                    "service": label,
                    "mode": "passive",
                    "job_id": str(job.id),
                },
            )
            created += int(is_new)
            updated += int(not is_new)

    event_stmt = select(func.count()).select_from(SecurityEvent).where(SecurityEvent.org_id == org_id)
    since = utcnow() - EVENT_LOOKBACK
    event_stmt = event_stmt.where(SecurityEvent.occurred_at >= since)
    if networks:
        scope_addresses = discovery.scope_hosts(networks)
        event_stmt = event_stmt.where(SecurityEvent.dst_ip.in_(scope_addresses))
    observed_events = int(db.execute(event_stmt).scalar_one())

    return {
        "mode": "passive",
        "scope_cidrs": job.scope_cidrs,
        "assets_observed": len(in_scope_assets),
        "services_observed": services_observed,
        "events_observed_24h": observed_events,
        "findings_created": created,
        "findings_updated": updated,
        "network_calls": 0,
    }


def serialize_authorization(auth: DiscoveryAuthorization) -> dict[str, Any]:
    return {
        "id": auth.id,
        "org_id": auth.org_id,
        "name": auth.name,
        "cidrs": list(auth.cidrs or []),
        "ports": [int(port) for port in (auth.ports or [])],
        "max_hosts": int(auth.max_hosts),
        "status": discovery.authorization_status(auth),
        "approved_by": auth.approved_by,
        "approved_at": auth.approved_at,
        "expires_at": auth.expires_at,
        "revoked_at": auth.revoked_at,
        "revoked_by": auth.revoked_by,
        "created_by": auth.created_by,
        "created_at": auth.created_at,
    }


def resolve_job_authorization(
    db: Session,
    org_id: UUID,
    authorization_id: UUID | None,
    scope_cidrs: list[str],
    *,
    required_scope: bool,
) -> DiscoveryAuthorization:
    """Load and enforce the authorization that permits a discovery scope."""
    if authorization_id is None:
        raise ValidationFailure(
            [{"field": "authorization_id", "message": "An approved discovery authorization is mandatory"}]
        )
    auth = discovery.load_authorization(db, org_id, authorization_id)
    discovery.ensure_authorization_usable(auth)
    discovery.ensure_scope_authorized(scope_cidrs, auth, required=required_scope)
    return auth


async def execute_job(db: Session, org_id: UUID, job: DiscoveryJob, ports: list[int]) -> dict[str, Any]:
    if job.mode == "active":
        return await run_active(db, org_id, job, ports)
    if job.mode == "passive":
        return run_passive(db, org_id, job)
    raise ValidationFailure([{"field": "mode", "message": "Unsupported discovery mode"}])


__all__ = [
    "PORT_RISK",
    "analyze",
    "execute_job",
    "finding_summary",
    "resolve_job_authorization",
    "run_active",
    "run_passive",
    "serialize_authorization",
]
