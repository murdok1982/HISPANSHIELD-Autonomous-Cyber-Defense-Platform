"""Vulnerability lifecycle, intelligence imports and prioritisation wiring."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from datetime import datetime
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.core.errors import Conflict, NotFound, ValidationFailure
from app.models.assets import Asset, CVECatalog, Vulnerability
from app.modules.assets.schemas import AssetRef
from app.modules.vulnerabilities.schemas import (
    CVECatalogOut,
    CVEImportRequest,
    CVEImportResult,
    EPSSImportRequest,
    EPSSImportResult,
    EPSSItem,
    ImportRowError,
    KEVImportRequest,
    KEVImportResult,
    TopRiskyOut,
    VulnerabilityCreate,
    VulnerabilityDetailOut,
    VulnerabilityOut,
    VulnerabilitySummaryOut,
)
from app.services import risk

ALLOWED_STATUS_TRANSITIONS: dict[str, set[str]] = {
    "open": {"open", "mitigated", "accepted", "false_positive", "reopened"},
    "reopened": {"reopened", "open", "mitigated", "accepted", "false_positive"},
    "mitigated": {"mitigated", "open", "reopened"},
    "accepted": {"accepted", "open", "reopened"},
    "false_positive": {"false_positive", "open", "reopened"},
}

MAX_IMPORT_ROWS = 500
EPSS_CSV_RE = re.compile(r"^CVE-\d{4}-\d{4,10}$")


def get_vulnerability(db: Session, org_id: UUID, vulnerability_id: UUID) -> Vulnerability:
    vulnerability = db.get(Vulnerability, vulnerability_id)
    if vulnerability is None or vulnerability.org_id != org_id:
        raise NotFound("Vulnerability")
    return vulnerability


def resolve_asset(db: Session, org_id: UUID, asset_id: UUID | None) -> Asset | None:
    if asset_id is None:
        return None
    asset = db.get(Asset, asset_id)
    if asset is None or asset.org_id != org_id:
        raise NotFound("Asset")
    return asset


def severity_for(cvss_score: float | None, explicit: str | None) -> str:
    return explicit or risk.severity_from_cvss(cvss_score)


def _asset_threat_flags(db: Session, org_id: UUID, assets: Iterable[Asset | None]) -> dict[UUID, bool]:
    """Batch threat-intel matching to avoid one query per vulnerability."""
    unique: dict[UUID, Asset] = {asset.id: asset for asset in assets if asset is not None}
    if not unique:
        return {}
    values: set[str] = set()
    for asset in unique.values():
        values.update(str(item) for item in (asset.ip_addresses or []))
        values.update(str(item) for item in (asset.hostnames or []))
    matched = risk.threat_indicator_values(db, org_id, values)
    result: dict[UUID, bool] = {}
    for asset in unique.values():
        candidates = {risk.normalize_indicator_value(str(item)) for item in (asset.ip_addresses or [])}
        candidates |= {risk.normalize_indicator_value(str(item)) for item in (asset.hostnames or [])}
        result[asset.id] = bool(candidates & matched)
    return result


def recalculate_vulnerability(
    db: Session, org_id: UUID, vulnerability: Vulnerability, *, asset: Asset | None = None
) -> risk.RiskScore:
    if asset is None and vulnerability.asset_id is not None:
        asset = db.get(Asset, vulnerability.asset_id)
        if asset is not None and asset.org_id != org_id:
            asset = None
    threat = risk.asset_matches_threat_intel(db, org_id, asset)
    return risk.apply_priority(vulnerability, asset, threat_match=threat)


def create_vulnerability(db: Session, org_id: UUID, payload: VulnerabilityCreate) -> Vulnerability:
    asset = resolve_asset(db, org_id, payload.asset_id)
    vulnerability = Vulnerability(
        org_id=org_id,
        asset_id=payload.asset_id,
        cve_id=payload.cve_id,
        title=payload.title,
        description=payload.description,
        cvss_score=payload.cvss_score,
        cvss_vector=payload.cvss_vector,
        epss_score=payload.epss_score,
        kev=payload.kev,
        severity=severity_for(payload.cvss_score, payload.severity),
        status=payload.status,
        exploitable=payload.exploitable,
        exposure=payload.exposure,
        source=payload.source,
        due_at=payload.due_at,
        remediation=payload.remediation,
        metadata_json=payload.metadata,
        first_seen=utcnow(),
        last_seen=utcnow(),
    )
    threat = risk.asset_matches_threat_intel(db, org_id, asset)
    risk.apply_priority(vulnerability, asset, threat_match=threat)
    db.add(vulnerability)
    db.flush()
    return vulnerability


def validate_transition(current: str, target: str) -> None:
    allowed = ALLOWED_STATUS_TRANSITIONS.get(current)
    if allowed is None or target not in allowed:
        raise Conflict(
            f"Invalid vulnerability status transition: {current} -> {target}. "
            f"Allowed targets: {', '.join(sorted(ALLOWED_STATUS_TRANSITIONS.get(current, set())))}"
        )


def detail(db: Session, vulnerability: Vulnerability) -> VulnerabilityDetailOut:
    asset = db.get(Asset, vulnerability.asset_id) if vulnerability.asset_id else None
    if asset is not None and asset.org_id != vulnerability.org_id:
        asset = None
    catalog = db.get(CVECatalog, vulnerability.cve_id) if vulnerability.cve_id else None
    base = VulnerabilityOut.model_validate(vulnerability)
    return VulnerabilityDetailOut(
        **base.model_dump(),
        asset=AssetRef.model_validate(asset) if asset else None,
        catalog=CVECatalogOut.model_validate(catalog) if catalog is not None else None,
    )


def _upsert_catalog(db: Session, item: Any) -> bool:
    """Upsert a CVE catalogue row; returns True when a new row was created."""
    catalog = db.get(CVECatalog, item.cve_id)
    created = catalog is None
    if catalog is None:
        catalog = CVECatalog(cve_id=item.cve_id, description=item.description, updated_at=utcnow())
        db.add(catalog)
    catalog.description = item.description
    if getattr(item, "cvss_score", None) is not None:
        catalog.cvss_score = item.cvss_score
    if getattr(item, "cvss_vector", None) is not None:
        catalog.cvss_vector = item.cvss_vector
    if getattr(item, "epss_score", None) is not None:
        catalog.epss_score = item.epss_score
    if getattr(item, "kev", False):
        catalog.kev = True
    if getattr(item, "published_at", None) is not None:
        catalog.published_at = item.published_at
    if getattr(item, "modified_at", None) is not None:
        catalog.modified_at = item.modified_at
    if getattr(item, "references", None):
        catalog.references = list(item.references)
    if getattr(item, "cpes", None):
        catalog.cpes = list(item.cpes)
    if getattr(item, "cwe", None) is not None:
        catalog.cwe = item.cwe
    catalog.updated_at = utcnow()
    db.flush()
    return created


def import_cve(db: Session, org_id: UUID, payload: CVEImportRequest) -> CVEImportResult:
    catalog_created = 0
    catalog_updated = 0
    vulnerabilities_created = 0
    vulnerabilities_updated = 0
    errors: list[ImportRowError] = []

    requested_assets: dict[UUID, Asset | None] = {}
    for item in payload.items:
        for asset_id in item.asset_ids:
            if asset_id in requested_assets:
                continue
            asset = db.get(Asset, asset_id)
            requested_assets[asset_id] = asset if asset is not None and asset.org_id == org_id else None
    threat_flags = _asset_threat_flags(db, org_id, requested_assets.values())

    for index, item in enumerate(payload.items):
        if _upsert_catalog(db, item):
            catalog_created += 1
        else:
            catalog_updated += 1
        severity = risk.severity_from_cvss(item.cvss_score)
        for asset_id in item.asset_ids:
            asset = requested_assets.get(asset_id)
            if asset is None:
                errors.append(ImportRowError(row=index, identifier=item.cve_id, message=f"Asset not found: {asset_id}"))
                continue
            vulnerability = db.execute(
                select(Vulnerability).where(
                    Vulnerability.org_id == org_id,
                    Vulnerability.asset_id == asset.id,
                    Vulnerability.cve_id == item.cve_id,
                )
            ).scalar_one_or_none()
            if vulnerability is None:
                vulnerability = Vulnerability(
                    org_id=org_id,
                    asset_id=asset.id,
                    cve_id=item.cve_id,
                    title=item.description[:300],
                    description=item.description,
                    source="cve_import",
                    metadata_json={"cpe": list(item.cpes), "cwe": item.cwe},
                )
                db.add(vulnerability)
                vulnerabilities_created += 1
            else:
                vulnerability.title = item.description[:300]
                vulnerability.description = item.description
                vulnerability.last_seen = utcnow()
                vulnerabilities_updated += 1
            vulnerability.cvss_score = item.cvss_score
            vulnerability.cvss_vector = item.cvss_vector
            vulnerability.epss_score = item.epss_score
            vulnerability.kev = vulnerability.kev or item.kev
            vulnerability.severity = severity
            risk.apply_priority(vulnerability, asset, threat_match=threat_flags.get(asset.id, False))
            db.flush()

    return CVEImportResult(
        catalog_created=catalog_created,
        catalog_updated=catalog_updated,
        vulnerabilities_created=vulnerabilities_created,
        vulnerabilities_updated=vulnerabilities_updated,
        errors=errors,
    )


def _recalculate_many(db: Session, org_id: UUID, vulnerabilities: Sequence[Vulnerability]) -> int:
    if not vulnerabilities:
        return 0
    assets: dict[UUID, Asset] = {}
    asset_ids = {item.asset_id for item in vulnerabilities if item.asset_id}
    if asset_ids:
        for asset in db.execute(select(Asset).where(Asset.org_id == org_id, Asset.id.in_(asset_ids))).scalars():
            assets[asset.id] = asset
    threat_flags = _asset_threat_flags(db, org_id, assets.values())
    for vulnerability in vulnerabilities:
        asset = assets.get(vulnerability.asset_id) if vulnerability.asset_id else None
        risk.apply_priority(vulnerability, asset, threat_match=threat_flags.get(asset.id, False) if asset else False)
    return len(vulnerabilities)


def import_kev(db: Session, org_id: UUID, payload: KEVImportRequest) -> KEVImportResult:
    catalog_created = 0
    catalog_marked = 0
    vulnerabilities_marked = 0
    unknown: list[str] = []
    seen: set[str] = set()
    entries: list[tuple[str, str | None]] = []
    for entry in payload.vulnerabilities:
        entries.append((entry.cveID, entry.shortDescription))
    for cve in payload.cves:
        entries.append((cve, None))

    affected: list[Vulnerability] = []
    for cve, description in entries:
        if cve in seen:
            continue
        seen.add(cve)
        catalog = db.get(CVECatalog, cve)
        if catalog is None:
            vulnerabilities = list(
                db.execute(
                    select(Vulnerability).where(Vulnerability.org_id == org_id, Vulnerability.cve_id == cve)
                ).scalars()
            )
            if description is None and not vulnerabilities:
                unknown.append(cve)
                continue
            catalog = CVECatalog(
                cve_id=cve,
                description=description or cve,
                kev=True,
                updated_at=utcnow(),
            )
            db.add(catalog)
            db.flush()
            catalog_created += 1
        else:
            catalog.kev = True
            catalog.updated_at = utcnow()
            catalog_marked += 1
        vulnerabilities = list(
            db.execute(
                select(Vulnerability).where(Vulnerability.org_id == org_id, Vulnerability.cve_id == cve)
            ).scalars()
        )
        for vulnerability in vulnerabilities:
            vulnerability.kev = True
        affected.extend(vulnerabilities)

    vulnerabilities_marked = len(affected)
    _recalculate_many(db, org_id, affected)
    return KEVImportResult(
        catalog_created=catalog_created,
        catalog_marked=catalog_marked,
        vulnerabilities_marked=vulnerabilities_marked,
        unknown_cves=sorted(unknown),
    )


def _parse_epss_csv(csv_payload: str) -> tuple[list[EPSSItem], list[ImportRowError]]:
    items: list[EPSSItem] = []
    errors: list[ImportRowError] = []
    for index, raw in enumerate(csv_payload.splitlines()):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [part.strip() for part in line.split(",")]
        if parts[0].lower() in {"cve", "cve_id"}:
            continue
        if len(parts) < 2:
            errors.append(ImportRowError(row=index, message="Expected at least cve,epss columns"))
            continue
        cve = parts[0].upper()
        if not EPSS_CSV_RE.match(cve):
            errors.append(ImportRowError(row=index, identifier=cve[:64], message="Invalid CVE identifier"))
            continue
        try:
            epss = float(parts[1])
        except ValueError:
            errors.append(ImportRowError(row=index, identifier=cve, message="EPSS score is not numeric"))
            continue
        percentile: float | None = None
        if len(parts) > 2 and parts[2]:
            try:
                percentile = float(parts[2])
            except ValueError:
                errors.append(ImportRowError(row=index, identifier=cve, message="Percentile is not numeric"))
                continue
        try:
            items.append(EPSSItem(cve=cve, epss=epss, percentile=percentile))
        except ValueError as exc:
            errors.append(ImportRowError(row=index, identifier=cve, message=str(exc)[:300]))
    return items, errors


def import_epss(db: Session, org_id: UUID, payload: EPSSImportRequest) -> EPSSImportResult:
    items: list[EPSSItem] = list(payload.items)
    errors: list[ImportRowError] = []
    if payload.csv:
        parsed, csv_errors = _parse_epss_csv(payload.csv)
        items.extend(parsed)
        errors.extend(csv_errors)
    if len(items) > MAX_IMPORT_ROWS:
        raise ValidationFailure([{"field": "items", "message": f"EPSS import supports at most {MAX_IMPORT_ROWS} rows"}])

    catalog_updated = 0
    affected: list[Vulnerability] = []
    seen: set[str] = set()
    for item in items:
        if item.cve in seen:
            continue
        seen.add(item.cve)
        catalog = db.get(CVECatalog, item.cve)
        if catalog is None:
            catalog = CVECatalog(
                cve_id=item.cve,
                description=f"EPSS intelligence entry for {item.cve}",
                epss_score=item.epss,
                updated_at=utcnow(),
            )
            db.add(catalog)
        else:
            catalog.epss_score = item.epss
            catalog.updated_at = utcnow()
        db.flush()
        catalog_updated += 1
        vulnerabilities = list(
            db.execute(
                select(Vulnerability).where(Vulnerability.org_id == org_id, Vulnerability.cve_id == item.cve)
            ).scalars()
        )
        for vulnerability in vulnerabilities:
            vulnerability.epss_score = item.epss
        affected.extend(vulnerabilities)

    vulnerabilities_updated = _recalculate_many(db, org_id, affected)
    return EPSSImportResult(
        parsed=len(items),
        catalog_updated=catalog_updated,
        vulnerabilities_updated=vulnerabilities_updated,
        errors=errors,
    )


def summary(db: Session, org_id: UUID, *, now: datetime | None = None) -> VulnerabilitySummaryOut:
    now = now or utcnow()
    rows = db.execute(
        select(Vulnerability.severity, Vulnerability.status, func.count())
        .where(Vulnerability.org_id == org_id)
        .group_by(Vulnerability.severity, Vulnerability.status)
    ).all()
    by_severity: dict[str, int] = {}
    by_status: dict[str, int] = {}
    total = 0
    for severity, status, count in rows:
        total += count
        by_severity[severity] = by_severity.get(severity, 0) + count
        by_status[status] = by_status.get(status, 0) + count
    kev = db.execute(
        select(func.count())
        .select_from(Vulnerability)
        .where(Vulnerability.org_id == org_id, Vulnerability.kev.is_(True))
    ).scalar_one()
    exploitable = db.execute(
        select(func.count())
        .select_from(Vulnerability)
        .where(Vulnerability.org_id == org_id, Vulnerability.exploitable.is_(True))
    ).scalar_one()
    overdue = db.execute(
        select(func.count())
        .select_from(Vulnerability)
        .where(
            Vulnerability.org_id == org_id,
            Vulnerability.due_at.is_not(None),
            Vulnerability.due_at < now,
            Vulnerability.status.in_(["open", "reopened"]),
        )
    ).scalar_one()
    mean_priority = db.execute(
        select(func.coalesce(func.avg(Vulnerability.priority_score), 0.0)).where(Vulnerability.org_id == org_id)
    ).scalar_one()
    top_rows = db.execute(
        select(Vulnerability, Asset.name)
        .outerjoin(Asset, Asset.id == Vulnerability.asset_id)
        .where(Vulnerability.org_id == org_id)
        .order_by(Vulnerability.priority_score.desc(), Vulnerability.first_seen.desc())
        .limit(5)
    ).all()
    top_risky = [
        TopRiskyOut(
            id=vulnerability.id,
            title=vulnerability.title,
            cve_id=vulnerability.cve_id,
            severity=vulnerability.severity,
            status=vulnerability.status,
            priority_score=vulnerability.priority_score,
            asset_id=vulnerability.asset_id,
            asset_name=asset_name,
        )
        for vulnerability, asset_name in top_rows
    ]
    return VulnerabilitySummaryOut(
        total=total,
        by_severity=by_severity,
        by_status=by_status,
        kev=int(kev),
        exploitable=int(exploitable),
        overdue=int(overdue),
        mean_priority=round(float(mean_priority), 2),
        top_risky=top_risky,
    )


__all__ = [
    "ALLOWED_STATUS_TRANSITIONS",
    "MAX_IMPORT_ROWS",
    "create_vulnerability",
    "detail",
    "get_vulnerability",
    "import_cve",
    "import_epss",
    "import_kev",
    "recalculate_vulnerability",
    "resolve_asset",
    "severity_for",
    "summary",
    "validate_transition",
]
