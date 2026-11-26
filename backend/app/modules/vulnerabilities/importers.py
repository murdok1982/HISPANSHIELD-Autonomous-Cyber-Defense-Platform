"""Normalize Nessus, OpenVAS and Trivy reports into vulnerability instances.

Security notes
--------------
* XML input is rejected when it contains a ``DOCTYPE``/``ENTITY`` declaration;
  external entities and entity-expansion bombs never reach the parser.
* Content is size-limited by the request schema *before* parsing.
* Scanner host names are resolved strictly inside the caller's organization;
  an unknown host is reported as a row error, never attached to a foreign
  asset or silently dropped.
* A deterministic fingerprint ``(org, asset, CVE/plugin, port, protocol)``
  makes repeated imports from different scanners update one instance.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException
from sqlalchemy import String, cast, or_, select
from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.core.errors import ValidationFailure
from app.models.assets import Asset, Vulnerability
from app.modules.assets.service import asset_public_ip
from app.modules.vulnerabilities.schemas import ImportRowError
from app.services import risk

MAX_FINDINGS = 10_000
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,10}$", re.IGNORECASE)
_HOST_CLEAN = re.compile(r"[^a-zA-Z0-9_.:\-\[\]]")
_SEVERITY = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "log": "info",
    "none": "info",
    "unknown": "medium",
}


@dataclass
class ScannerFinding:
    host: str
    title: str
    severity: str
    cve: str | None = None
    cvss: float | None = None
    description: str | None = None
    port: int | None = None
    protocol: str = "tcp"
    plugin_id: str | None = None
    package: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ParseResult:
    findings: list[ScannerFinding]
    errors: list[ImportRowError]


def _text(node: ET.Element | None, path: str, default: str | None = None) -> str | None:
    if node is None:
        return default
    found = node.find(path)
    if found is None or found.text is None:
        return default
    value = found.text.strip()
    return value or default


def _float(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = float(str(value).strip())
    except (TypeError, ValueError):
        return None
    return parsed if 0 <= parsed <= 10 else None


def _port(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool) and 0 < value <= 65535:
        return value
    if isinstance(value, str):
        match = re.match(r"^(\d{1,5})(?:/|\b)", value.strip())
        if match:
            candidate = int(match.group(1))
            if 0 < candidate <= 65535:
                return candidate
    return None


def _protocol(value: Any) -> str:
    text = str(value or "tcp").lower()
    return "udp" if "udp" in text else "tcp"


def _xml_root(content: str) -> ET.Element:
    lowered = content.lower()
    if "<!doctype" in lowered or "<!entity" in lowered:
        raise ValidationFailure([{"field": "content", "message": "XML documents with DTD/entities are not accepted"}])
    try:
        # defusedxml forbids DTDs/entities by default; the explicit check above
        # keeps the error message actionable and blocks encoded variants the
        # scanner may not normalise.
        return ET.fromstring(content)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise ValidationFailure([{"field": "content", "message": f"Invalid XML: {str(exc)[:200]}"}]) from exc


def _split_cves(node: ET.Element | None) -> list[str]:
    if node is None:
        return []
    values: list[str] = []
    for element in node.iter():
        if element.text:
            values.extend(re.split(r"[\s,;]+", element.text.strip()))
        # OpenVAS stores the identifier as <ref type="cve" id="CVE-..."/>.
        for attribute in ("id", "value"):
            candidate = element.get(attribute)
            if candidate:
                values.append(candidate.strip())
    return [value.upper() for value in values if CVE_RE.match(value)]


def parse_nessus(content: str) -> ParseResult:
    root = _xml_root(content)
    findings: list[ScannerFinding] = []
    errors: list[ImportRowError] = []
    for host_index, host in enumerate(root.iter("ReportHost")):
        host_name = _HOST_CLEAN.sub("", str(host.get("name") or ""))[:255]
        for row, item in enumerate(host.iter("ReportItem")):
            port = _port(item.get("port"))
            protocol = _protocol(item.get("protocol"))
            severity_num = int(item.get("severity") or 0)
            cvss = _float(_text(item, "cvss3_base_score")) or _float(_text(item, "cvss_base_score"))
            severity = (
                risk.severity_from_cvss(cvss)
                if cvss is not None
                else {
                    4: "critical",
                    3: "high",
                    2: "medium",
                    1: "low",
                }.get(severity_num, "info")
            )
            title = str(item.get("pluginName") or item.get("pluginID") or "Nessus finding")[:300]
            description = (_text(item, "description") or _text(item, "synopsis") or title)[:8000]
            cves: list[str] = []
            for tag in ("cve", "cve3"):
                for node in item.findall(tag):
                    cves.extend(_split_cves(node))
            plugin_id = str(item.get("pluginID") or "")[:60] or None
            base = {
                "scanner": "nessus",
                "plugin_id": plugin_id,
                "service": str(item.get("svc_name") or "")[:80] or None,
                "solution": (_text(item, "solution") or "")[:4000] or None,
            }
            if not cves:
                findings.append(
                    ScannerFinding(
                        host=host_name,
                        title=title,
                        severity=severity,
                        cvss=cvss,
                        description=description,
                        port=port,
                        protocol=protocol,
                        plugin_id=plugin_id,
                        metadata=base,
                    )
                )
            else:
                for cve in cves[:50]:
                    findings.append(
                        ScannerFinding(
                            host=host_name,
                            title=title,
                            severity=severity,
                            cve=cve,
                            cvss=cvss,
                            description=description,
                            port=port,
                            protocol=protocol,
                            plugin_id=plugin_id,
                            metadata=base,
                        )
                    )
            if len(findings) > MAX_FINDINGS:
                errors.append(ImportRowError(row=host_index, message=f"Report exceeds {MAX_FINDINGS} findings"))
                return ParseResult(findings[:MAX_FINDINGS], errors)
            if not host_name:
                errors.append(ImportRowError(row=row, message="ReportHost without a resolvable host name"))
    return ParseResult(findings, errors)


def parse_openvas(content: str) -> ParseResult:
    root = _xml_root(content)
    findings: list[ScannerFinding] = []
    errors: list[ImportRowError] = []
    for index, result in enumerate(root.iter("result")):
        host_name = _text(result, "host") or str(result.get("host") or "")
        host_name = _HOST_CLEAN.sub("", host_name)[:255]
        nvt = result.find("nvt")
        title = _text(nvt, "name") or _text(result, "name") or "OpenVAS finding"
        cvss = _float(_text(nvt, "cvss_base")) or _float(_text(result, "severity"))
        threat = (_text(result, "threat") or "").lower()
        severity = risk.severity_from_cvss(cvss) if cvss is not None else _SEVERITY.get(threat, "medium")
        description = (_text(result, "description") or _text(nvt, "tags") or title)[:8000]
        port = _port(_text(result, "port"))
        protocol = _protocol(_text(result, "port"))
        cves = _split_cves(nvt.find("refs") if nvt is not None else None)
        oid = str(nvt.get("oid") or "")[:60] if nvt is not None else None
        base = {"scanner": "openvas", "oid": oid, "qod": _text(result, "qod")}
        if not host_name:
            errors.append(ImportRowError(row=index, message="OpenVAS result without a host"))
            continue
        if not cves:
            findings.append(
                ScannerFinding(
                    host=host_name,
                    title=title[:300],
                    severity=severity,
                    cvss=cvss,
                    description=description,
                    port=port,
                    protocol=protocol,
                    plugin_id=oid,
                    metadata=base,
                )
            )
        else:
            for cve in cves[:50]:
                findings.append(
                    ScannerFinding(
                        host=host_name,
                        title=title[:300],
                        severity=severity,
                        cve=cve,
                        cvss=cvss,
                        description=description,
                        port=port,
                        protocol=protocol,
                        plugin_id=oid,
                        metadata=base,
                    )
                )
    return ParseResult(findings, errors)


def _trivy_cvss(vulnerability: dict[str, Any]) -> float | None:
    scores: list[float] = []
    for vendor in (vulnerability.get("CVSS") or {}).values():
        if isinstance(vendor, dict):
            for key in ("V3Score", "V2Score"):
                parsed = _float(vendor.get(key))
                if parsed is not None:
                    scores.append(parsed)
    return max(scores) if scores else None


def parse_trivy(content: str) -> ParseResult:
    try:
        document = json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValidationFailure([{"field": "content", "message": f"Invalid Trivy JSON: {str(exc)[:200]}"}]) from exc
    if not isinstance(document, dict):
        raise ValidationFailure([{"field": "content", "message": "Trivy report must be a JSON object"}])
    artifact = str(document.get("ArtifactName") or "")[:255]
    findings: list[ScannerFinding] = []
    errors: list[ImportRowError] = []
    for result_index, result in enumerate(document.get("Results") or []):
        if not isinstance(result, dict):
            continue
        target = str(result.get("Target") or artifact or "")[:255]
        for row, vulnerability in enumerate(result.get("Vulnerabilities") or []):
            if not isinstance(vulnerability, dict):
                continue
            cve = str(vulnerability.get("VulnerabilityID") or "").upper()
            if not CVE_RE.match(cve):
                cve = ""
            title = str(vulnerability.get("Title") or vulnerability.get("VulnerabilityID") or "Trivy finding")[:300]
            severity = _SEVERITY.get(str(vulnerability.get("Severity") or "").lower(), "medium")
            cvss = _trivy_cvss(vulnerability)
            findings.append(
                ScannerFinding(
                    host=target,
                    title=title,
                    severity=risk.severity_from_cvss(cvss) if cvss is not None else severity,
                    cve=cve or None,
                    cvss=cvss,
                    description=str(vulnerability.get("Description") or title)[:8000],
                    plugin_id=str(vulnerability.get("VulnerabilityID") or "")[:60] or None,
                    package=str(vulnerability.get("PkgName") or "")[:200] or None,
                    metadata={
                        "scanner": "trivy",
                        "installed_version": str(vulnerability.get("InstalledVersion") or "")[:120] or None,
                        "fixed_version": str(vulnerability.get("FixedVersion") or "")[:120] or None,
                        "target": target or None,
                        "primary_url": str(vulnerability.get("PrimaryURL") or "")[:500] or None,
                    },
                )
            )
            if len(findings) > MAX_FINDINGS:
                errors.append(ImportRowError(row=result_index, message=f"Report exceeds {MAX_FINDINGS} findings"))
                return ParseResult(findings[:MAX_FINDINGS], errors)
            if not target:
                errors.append(ImportRowError(row=row, message="Trivy result without Target/ArtifactName"))
    return ParseResult(findings, errors)


PARSERS = {"nessus": parse_nessus, "openvas": parse_openvas, "trivy": parse_trivy}


def _fingerprint(asset_id: UUID, finding: ScannerFinding) -> str:
    identifier = finding.cve or f"{finding.plugin_id or ''}:{finding.title.lower()}"
    raw = f"{asset_id}|{identifier}|{finding.port or ''}|{finding.protocol}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _asset_index(db: Session, org_id: UUID) -> dict[str, Asset]:
    assets = list(db.execute(select(Asset).where(Asset.org_id == org_id)).scalars())
    index: dict[str, Asset] = {}
    for asset in assets:
        index.setdefault(asset.asset_key.lower(), asset)
        index.setdefault(asset.name.lower(), asset)
        for hostname in asset.hostnames or []:
            index.setdefault(str(hostname).lower(), asset)
        for address in asset.ip_addresses or []:
            index.setdefault(str(address).lower(), asset)
    return index


def import_scanner_report(
    db: Session,
    org_id: UUID,
    *,
    format: str,
    content: str,
    asset_key: str | None = None,
) -> dict[str, Any]:
    parser = PARSERS.get(format)
    if parser is None:
        raise ValidationFailure([{"field": "format", "message": "format must be nessus, openvas or trivy"}])
    parsed = parser(content)
    assets = _asset_index(db, org_id)
    forced_asset = assets.get(asset_key.lower()) if asset_key else None
    if asset_key and forced_asset is None:
        raise ValidationFailure([{"field": "asset_key", "message": "asset_key does not exist in this organization"}])

    created = 0
    updated = 0
    skipped = 0
    errors = list(parsed.errors)
    seen: set[str] = set()

    for finding in parsed.findings:
        host = finding.host.lower().strip()
        asset = forced_asset or assets.get(host)
        if asset is None:
            # Trivy targets are often image paths; accept the first component.
            asset = assets.get(host.split("/")[0])
        if asset is None:
            errors.append(
                ImportRowError(
                    row=0,
                    identifier=finding.cve or finding.plugin_id,
                    message=f"No inventory asset matches host {finding.host or '(empty)'}",
                )
            )
            continue

        fingerprint = _fingerprint(asset.id, finding)
        if fingerprint in seen:
            skipped += 1
            continue
        seen.add(fingerprint)

        match_conditions = [cast(Vulnerability.metadata_json["fingerprint"], String) == fingerprint]
        if finding.cve:
            match_conditions.append(Vulnerability.cve_id == finding.cve)
        stmt = select(Vulnerability).where(
            Vulnerability.org_id == org_id,
            Vulnerability.asset_id == asset.id,
            or_(*match_conditions),
        )
        vulnerability = db.execute(stmt).scalar_one_or_none()
        public = bool(asset_public_ip(asset))
        if vulnerability is None:
            vulnerability = Vulnerability(
                org_id=org_id,
                asset_id=asset.id,
                cve_id=finding.cve,
                title=finding.title[:300],
                description=finding.description,
                source=f"{format}_import",
                exposure="public" if public else "internal",
                metadata_json={},
            )
            db.add(vulnerability)
            created += 1
        else:
            vulnerability.last_seen = utcnow()
            vulnerability.description = finding.description or vulnerability.description
            updated += 1
        vulnerability.cvss_score = finding.cvss
        vulnerability.severity = finding.severity
        metadata = dict(vulnerability.metadata_json or {})
        metadata.update(finding.metadata)
        metadata.update(
            {
                "fingerprint": fingerprint,
                "port": finding.port,
                "protocol": finding.protocol,
                "package": finding.package,
                "host": finding.host,
            }
        )
        vulnerability.metadata_json = metadata
        risk.apply_priority(vulnerability, asset, threat_match=False)
        db.flush()

    return {
        "format": format,
        "total": len(parsed.findings),
        "created": created,
        "updated": updated,
        "skipped": skipped,
        "errors": errors,
    }


__all__ = ["PARSERS", "ScannerFinding", "import_scanner_report", "parse_nessus", "parse_openvas", "parse_trivy"]
