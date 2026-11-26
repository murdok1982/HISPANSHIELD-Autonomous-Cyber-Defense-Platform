"""STIX 2.1 / CSV export for the attack surface, with a lossless round-trip.

The bundle uses standard STIX 2.1 ``infrastructure`` and ``ipv4-addr`` /
``ipv6-addr`` objects plus ``x_hispanshield_*`` custom properties. IP and port
observations are carried verbatim so the bundle can be re-ingested into another
HISPANSHIELD instance (or a STIX-capable SIEM) without losing addressing data.

We intentionally do not use ``indicator`` objects: an exposed service is an
observable about our own estate, not a pattern about adversary infrastructure.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.core.errors import ValidationFailure
from app.models.assets import Asset, AttackSurfaceFinding

_STIX_NAMESPACE = uuid.UUID("0d6f0f2e-6a1f-4c76-9f1d-6a1c1f2a7b10")
_INFRA_TYPES = {
    "ot": "control-system",
    "network": "routers-switches",
    "host": "workstation",
    "service": "hosting-target-lists",
    "cloud": "hosting-target-lists",
    "iot": "unknown",
    "identity": "unknown",
}


def _uuid(kind: str, *parts: object) -> str:
    return f"{kind}--{uuid.uuid5(_STIX_NAMESPACE, ':'.join(str(part) for part in parts))}"


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _ports_from_metadata(metadata: dict[str, Any]) -> set[int]:
    ports: set[int] = set()
    for raw in metadata.get("exposed_ports") or []:
        if isinstance(raw, bool):
            continue
        if isinstance(raw, int):
            ports.add(raw)
        elif isinstance(raw, str) and raw.strip().isdigit():
            ports.add(int(raw.strip()))
    for raw in metadata.get("services") or []:
        if isinstance(raw, dict) and isinstance(raw.get("port"), int):
            ports.add(raw["port"])
    return {port for port in ports if 0 < port <= 65535}


def _address_type(value: str) -> str:
    try:
        parsed = ipaddress.ip_address(value)
    except ValueError:
        return "ipv4-addr"
    return "ipv6-addr" if parsed.version == 6 else "ipv4-addr"


def build_bundle(db: Session, org_id: uuid.UUID) -> dict[str, Any]:
    assets = list(db.execute(select(Asset).where(Asset.org_id == org_id).order_by(Asset.asset_key.asc())).scalars())
    findings = list(
        db.execute(
            select(AttackSurfaceFinding)
            .where(AttackSurfaceFinding.org_id == org_id)
            .order_by(AttackSurfaceFinding.created_at.asc())
        ).scalars()
    )
    by_asset: dict[uuid.UUID, list[AttackSurfaceFinding]] = {}
    for finding in findings:
        if finding.asset_id is not None:
            by_asset.setdefault(finding.asset_id, []).append(finding)

    now = utcnow()
    objects: list[dict[str, Any]] = []
    seen_addresses: set[str] = set()

    for asset in assets:
        asset_findings = by_asset.get(asset.id, [])
        ports = _ports_from_metadata(asset.metadata_json or {})
        for finding in asset_findings:
            metadata = finding.metadata_json or {}
            if isinstance(metadata.get("port"), int):
                ports.add(metadata["port"])

        addresses = [str(ip) for ip in (asset.ip_addresses or []) if ip]
        observations: list[dict[str, Any]] = []
        if addresses:
            for address in addresses:
                if ports:
                    observations.extend({"ip": address, "port": port} for port in sorted(ports))
                else:
                    observations.append({"ip": address, "port": None})
                if address not in seen_addresses:
                    seen_addresses.add(address)
                    objects.append(
                        {
                            "type": _address_type(address),
                            "spec_version": "2.1",
                            "id": _uuid(_address_type(address), address),
                            "value": address,
                            "x_hispanshield_asset_ids": [str(asset.id)],
                        }
                    )
        elif ports:
            observations.extend({"ip": None, "port": port} for port in sorted(ports))

        modified = max([asset.updated_at, now, *(f.updated_at for f in asset_findings)])
        created = min([asset.created_at, *(f.created_at for f in asset_findings)])
        objects.append(
            {
                "type": "infrastructure",
                "spec_version": "2.1",
                "id": _uuid("infrastructure", org_id, asset.id),
                "created": _iso(created),
                "modified": _iso(modified),
                "name": asset.name,
                "infrastructure_types": [_INFRA_TYPES.get(asset.kind, "unknown")],
                "x_hispanshield_asset_id": str(asset.id),
                "x_hispanshield_asset_key": asset.asset_key,
                "x_hispanshield_kind": asset.kind,
                "x_hispanshield_criticality": asset.criticality,
                "x_hispanshield_ips": addresses,
                "x_hispanshield_ports": sorted(ports),
                "x_hispanshield_observations": observations,
                "x_hispanshield_findings": [
                    {
                        "id": str(finding.id),
                        "kind": finding.kind,
                        "title": finding.title,
                        "severity": finding.severity,
                        "status": finding.status,
                        "ip": (finding.metadata_json or {}).get("ip"),
                        "port": (finding.metadata_json or {}).get("port"),
                    }
                    for finding in asset_findings
                ],
            }
        )

    return {
        "type": "bundle",
        "id": _uuid("bundle", org_id, "attack-surface"),
        "objects": objects,
    }


def parse_bundle(bundle: Any) -> list[dict[str, Any]]:
    """Round-trip parser: recover ``asset_key, ip, port`` observations.

    Raises ``ValidationFailure`` for anything that is not a STIX 2.1 bundle so
    an import path cannot silently accept arbitrary JSON.
    """
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise ValidationFailure([{"field": "bundle", "message": "Expected a STIX 2.1 bundle object"}])
    objects = bundle.get("objects")
    if not isinstance(objects, list):
        raise ValidationFailure([{"field": "objects", "message": "Bundle must contain an objects array"}])
    observations: list[dict[str, Any]] = []
    for item in objects:
        if not isinstance(item, dict) or item.get("type") != "infrastructure":
            continue
        asset_key = item.get("x_hispanshield_asset_key")
        if not asset_key:
            continue
        for observation in item.get("x_hispanshield_observations") or []:
            if not isinstance(observation, dict):
                continue
            port = observation.get("port")
            observations.append(
                {
                    "asset_key": asset_key,
                    "asset_id": item.get("x_hispanshield_asset_id"),
                    "kind": item.get("x_hispanshield_kind"),
                    "ip": observation.get("ip"),
                    "port": int(port) if isinstance(port, int) else None,
                }
            )
    return observations


def _csv_safe(value: Any) -> str:
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in {"=", "+", "-", "@", "\t", "\r"} else text


def build_csv(db: Session, org_id: uuid.UUID) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "asset_key",
            "asset_name",
            "kind",
            "criticality",
            "ip",
            "port",
            "finding_kind",
            "finding_title",
            "severity",
            "status",
        ]
    )
    bundle = build_bundle(db, org_id)
    names = {
        obj.get("x_hispanshield_asset_key"): obj.get("name")
        for obj in bundle["objects"]
        if obj.get("type") == "infrastructure"
    }
    for obj in bundle["objects"]:
        if obj.get("type") != "infrastructure":
            continue
        asset_key = obj.get("x_hispanshield_asset_key")
        findings = obj.get("x_hispanshield_findings") or []
        observations = obj.get("x_hispanshield_observations") or []
        if not observations:
            observations = [{"ip": None, "port": None}]
        for observation in observations:
            if findings:
                for finding in findings:
                    writer.writerow(
                        [
                            _csv_safe(asset_key),
                            _csv_safe(names.get(asset_key, "")),
                            _csv_safe(obj.get("x_hispanshield_kind")),
                            obj.get("x_hispanshield_criticality"),
                            _csv_safe(observation.get("ip")),
                            observation.get("port") or "",
                            _csv_safe(finding.get("kind")),
                            _csv_safe(finding.get("title")),
                            _csv_safe(finding.get("severity")),
                            _csv_safe(finding.get("status")),
                        ]
                    )
            else:
                writer.writerow(
                    [
                        _csv_safe(asset_key),
                        _csv_safe(names.get(asset_key, "")),
                        _csv_safe(obj.get("x_hispanshield_kind")),
                        obj.get("x_hispanshield_criticality"),
                        _csv_safe(observation.get("ip")),
                        observation.get("port") or "",
                        "",
                        "",
                        "",
                        "",
                    ]
                )
    return buffer.getvalue()


__all__ = ["build_bundle", "build_csv", "parse_bundle"]
