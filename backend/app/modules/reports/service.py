"""Report data collection, rendering and persistence.

Reports are built exclusively from persisted platform data. When a dataset is
empty the report states the real zero instead of fabricating figures. Every
interpolated value is HTML-escaped with markupsafe before it reaches
``content_html``; the Markdown variant is plain text with table-cell escaping.
"""

from __future__ import annotations

import re
import uuid
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from markupsafe import escape
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.audit import verify_audit_chain
from app.core.crypto import sha256_hex
from app.core.db import utcnow
from app.models.assets import Asset, IoTDevice, OTDevice, Vulnerability
from app.models.compliance import ComplianceAssessment, ComplianceControlStatus, ComplianceFramework
from app.models.connectors import Connector
from app.models.core import Membership, Organization, Policy, User
from app.models.events import IngestSource
from app.models.incidents import Evidence, Incident, IncidentTimeline
from app.modules.reports.schemas import REPORT_DISCLAIMER

REPORT_KINDS = ("executive", "technical", "regulatory", "incident")

SEVERITY_ORDER = ("critical", "high", "medium", "low", "informational")


@dataclass
class Section:
    heading: str
    paragraphs: list[str] = field(default_factory=list)
    bullets: list[str] = field(default_factory=list)
    tables: list[dict[str, Any]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "heading": self.heading,
            "paragraphs": list(self.paragraphs),
            "bullets": list(self.bullets),
            "tables": list(self.tables),
        }


def _table(caption: str, columns: list[str], rows: list[list[str]]) -> dict[str, Any]:
    return {"caption": caption, "columns": columns, "rows": rows}


def _fmt(value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, datetime):
        return value.astimezone().strftime("%Y-%m-%d %H:%M %Z")
    return str(value)


def _fmt_duration(minutes: float | None) -> str:
    if minutes is None:
        return "not available"
    if minutes < 120:
        return f"{minutes:.1f} minutes"
    return f"{minutes / 60:.1f} hours"


def _count_rows(mapping: dict[str, int], label: str) -> list[list[str]]:
    rows = [[label, str(key), str(value)] for key, value in sorted(mapping.items(), key=lambda item: item[0])]
    return rows or [[label, "none recorded", "0"]]


def collect_snapshot(
    db: Session,
    org: Organization,
    period_start: datetime,
    period_end: datetime,
    *,
    framework_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """Query all report data for the organization inside the reporting period."""
    org_id = org.id
    generated_at = utcnow()

    assets_by_kind = {
        str(kind): int(count)
        for kind, count in db.execute(
            select(Asset.kind, func.count()).where(Asset.org_id == org_id).group_by(Asset.kind)
        ).all()
    }
    assets_total = sum(assets_by_kind.values())
    iot_total = db.execute(select(func.count()).select_from(IoTDevice).where(IoTDevice.org_id == org_id)).scalar_one()
    ot_total = db.execute(select(func.count()).select_from(OTDevice).where(OTDevice.org_id == org_id)).scalar_one()
    unowned_assets = db.execute(
        select(func.count())
        .select_from(Asset)
        .where(Asset.org_id == org_id, or_(Asset.owner.is_(None), Asset.owner == ""))
    ).scalar_one()
    sample_assets = list(
        db.execute(
            select(Asset).where(Asset.org_id == org_id).order_by(Asset.criticality.desc(), Asset.name.asc()).limit(10)
        ).scalars()
    )

    incident_stmt = select(Incident).where(
        Incident.org_id == org_id,
        Incident.detected_at >= period_start,
        Incident.detected_at <= period_end,
    )
    incidents = list(db.execute(incident_stmt.order_by(Incident.detected_at.desc()).limit(200)).scalars())
    incident_ids = [incident.id for incident in incidents]
    incident_asset_ids: set[str] = set()
    for incident in incidents:
        for asset_id in incident.affected_asset_ids or []:
            incident_asset_ids.add(str(asset_id))

    affected_assets: list[Asset] = []
    if incident_asset_ids:
        parsed_ids: list[uuid.UUID] = []
        for raw_id in incident_asset_ids:
            try:
                parsed_ids.append(uuid.UUID(raw_id))
            except ValueError:
                continue
        if parsed_ids:
            affected_assets = list(
                db.execute(
                    select(Asset).where(Asset.org_id == org_id, Asset.id.in_(parsed_ids)).order_by(Asset.name)
                ).scalars()
            )

    timeline_rows: list[tuple[IncidentTimeline, str]] = []
    if incident_ids:
        timeline_rows = list(
            db.execute(
                select(IncidentTimeline, Incident.ref)
                .join(Incident, Incident.id == IncidentTimeline.incident_id)
                .where(IncidentTimeline.org_id == org_id, IncidentTimeline.incident_id.in_(incident_ids))
                .order_by(IncidentTimeline.at.desc())
                .limit(200)
            )
            .tuples()
            .all()
        )

    resolved = [incident for incident in incidents if incident.resolved_at is not None]
    resolved_durations = [
        max(0.0, (incident.resolved_at - incident.detected_at).total_seconds() / 60)  # type: ignore[operator]
        for incident in resolved
    ]
    mttr_minutes = round(sum(resolved_durations) / len(resolved_durations), 1) if resolved_durations else None
    open_incidents = [incident for incident in incidents if incident.status not in {"closed", "recovered"}]

    vuln_rows = list(
        db.execute(
            select(Vulnerability.severity, func.count())
            .where(Vulnerability.org_id == org_id, Vulnerability.status == "open")
            .group_by(Vulnerability.severity)
        ).all()
    )
    vulns_by_severity = {str(severity): int(count) for severity, count in vuln_rows}
    vulns_open = sum(vulns_by_severity.values())
    vulns_kev = db.execute(
        select(func.count())
        .select_from(Vulnerability)
        .where(Vulnerability.org_id == org_id, Vulnerability.status == "open", Vulnerability.kev.is_(True))
    ).scalar_one()
    vulns_overdue = db.execute(
        select(func.count())
        .select_from(Vulnerability)
        .where(
            Vulnerability.org_id == org_id,
            Vulnerability.status == "open",
            Vulnerability.due_at.isnot(None),
            Vulnerability.due_at < generated_at,
        )
    ).scalar_one()
    top_vulns = list(
        db.execute(
            select(Vulnerability)
            .where(Vulnerability.org_id == org_id, Vulnerability.status == "open")
            .order_by(Vulnerability.priority_score.desc(), Vulnerability.first_seen.asc())
            .limit(10)
        ).scalars()
    )

    connectors = list(db.execute(select(Connector).where(Connector.org_id == org_id)).scalars())
    connector_status = Counter(str(connector.status) for connector in connectors)
    connectors_unhealthy = sum(
        count for status, count in connector_status.items() if status in {"degraded", "unhealthy", "error"}
    )
    connectors_insecure_tls = sum(1 for connector in connectors if connector.enabled and not connector.verify_tls)

    member_rows = db.execute(
        select(User.mfa_enabled, func.count())
        .join(Membership, Membership.user_id == User.id)
        .where(Membership.org_id == org_id, Membership.status == "active", User.status == "active")
        .group_by(User.mfa_enabled)
    ).all()
    members_total = sum(int(count) for _, count in member_rows)
    members_mfa = sum(int(count) for mfa_enabled, count in member_rows if mfa_enabled)

    evidence_total = db.execute(
        select(func.count()).select_from(Evidence).where(Evidence.org_id == org_id)
    ).scalar_one()
    policy_total = db.execute(
        select(func.count())
        .select_from(Policy)
        .where(or_(Policy.org_id == org_id, Policy.org_id.is_(None)), Policy.enabled.is_(True))
    ).scalar_one()
    ingest_total = db.execute(
        select(func.count())
        .select_from(IngestSource)
        .where(IngestSource.org_id == org_id, IngestSource.enabled.is_(True))
    ).scalar_one()

    assessment_rows = list(
        db.execute(
            select(ComplianceAssessment)
            .where(ComplianceAssessment.org_id == org_id)
            .order_by(ComplianceAssessment.started_at.desc())
        ).scalars()
    )
    latest_assessments: list[ComplianceAssessment] = []
    seen_frameworks: set[uuid.UUID] = set()
    for assessment in assessment_rows:
        if framework_id is not None and assessment.framework_id != framework_id:
            continue
        if assessment.framework_id in seen_frameworks:
            continue
        seen_frameworks.add(assessment.framework_id)
        latest_assessments.append(assessment)

    compliance_items: list[dict[str, Any]] = []
    gap_rows: list[list[str]] = []
    for assessment in latest_assessments:
        framework = db.get(ComplianceFramework, assessment.framework_id)
        if framework is None:
            continue
        status_counts = Counter(
            status
            for status in db.execute(
                select(ComplianceControlStatus.status).where(ComplianceControlStatus.assessment_id == assessment.id)
            ).scalars()
        )
        item = {
            "assessment_id": str(assessment.id),
            "framework_id": str(framework.id),
            "framework_code": framework.code,
            "framework_name": framework.name,
            "framework_version": assessment.framework_version,
            "status": assessment.status,
            "score": assessment.score,
            "completed_at": assessment.completed_at,
            "controls_total": sum(status_counts.values()),
            "compliant": status_counts.get("compliant", 0),
            "partial": status_counts.get("partial", 0),
            "non_compliant": status_counts.get("non_compliant", 0),
            "not_applicable": status_counts.get("not_applicable", 0),
            "not_assessed": status_counts.get("not_assessed", 0),
            "gap_count": len(assessment.gaps or []),
        }
        compliance_items.append(item)
        for gap in (assessment.gaps or [])[:20]:
            if len(gap_rows) >= 50:
                break
            gap_rows.append(
                [
                    framework.code,
                    _fmt(gap.get("control_code")),
                    _fmt(gap.get("title")),
                    _fmt(gap.get("status")),
                    _fmt(gap.get("severity")),
                    _fmt(gap.get("recommendation")),
                ]
            )

    completed_scores = [
        item["score"] for item in compliance_items if item["status"] == "completed" and item["score"] is not None
    ]
    compliance_average = round(sum(completed_scores) / len(completed_scores), 1) if completed_scores else None

    snapshot: dict[str, Any] = {
        "generated_at": generated_at,
        "period": {
            "start": period_start,
            "end": period_end,
            "days": max(1, (period_end - period_start).days),
        },
        "organization": {
            "id": str(org.id),
            "name": org.name,
            "slug": org.slug,
            "kind": org.kind,
            "country": org.country,
            "sector": org.sector,
            "tier": org.tier,
            "autonomy_level": org.autonomy_level,
            "is_demo": org.is_demo,
        },
        "assets": {
            "total": assets_total,
            "by_kind": assets_by_kind,
            "iot": int(iot_total),
            "ot": int(ot_total),
            "unowned": int(unowned_assets),
            "sample": [
                {
                    "name": asset.name,
                    "kind": asset.kind,
                    "criticality": asset.criticality,
                    "owner": asset.owner,
                }
                for asset in sample_assets
            ],
        },
        "incidents": {
            "total": len(incidents),
            "open": len(open_incidents),
            "resolved": len(resolved),
            "by_severity": dict(Counter(str(incident.severity) for incident in incidents)),
            "by_status": dict(Counter(str(incident.status) for incident in incidents)),
            "mttr_minutes": mttr_minutes,
            "items": [
                {
                    "id": str(incident.id),
                    "ref": incident.ref,
                    "title": incident.title,
                    "severity": incident.severity,
                    "status": incident.status,
                    "detected_at": incident.detected_at,
                    "resolved_at": incident.resolved_at,
                    "mttr_minutes": (
                        round((incident.resolved_at - incident.detected_at).total_seconds() / 60, 1)
                        if incident.resolved_at is not None
                        else None
                    ),
                }
                for incident in incidents[:50]
            ],
            "timeline": [
                {
                    "incident_ref": incident_ref,
                    "at": entry.at,
                    "kind": entry.kind,
                    "summary": entry.summary,
                }
                for entry, incident_ref in timeline_rows[:100]
            ],
            "affected_assets": [
                {
                    "id": str(asset.id),
                    "name": asset.name,
                    "kind": asset.kind,
                    "criticality": asset.criticality,
                }
                for asset in affected_assets[:100]
            ],
        },
        "vulnerabilities": {
            "open_total": vulns_open,
            "by_severity": vulns_by_severity,
            "kev": int(vulns_kev),
            "overdue": int(vulns_overdue),
            "top": [
                {
                    "cve_id": item.cve_id,
                    "title": item.title,
                    "severity": item.severity,
                    "cvss": item.cvss_score,
                    "kev": item.kev,
                    "priority_score": item.priority_score,
                    "due_at": item.due_at,
                }
                for item in top_vulns
            ],
        },
        "connectors": {
            "total": len(connectors),
            "by_status": dict(connector_status),
            "unhealthy": connectors_unhealthy,
            "insecure_tls": connectors_insecure_tls,
        },
        "identity": {
            "members": members_total,
            "mfa_enabled": members_mfa,
            "mfa_ratio": round(members_mfa / members_total, 4) if members_total else 0.0,
        },
        "operations": {
            "evidence": int(evidence_total),
            "policies": int(policy_total),
            "ingest_sources": int(ingest_total),
            "audit": verify_audit_chain(db, org_id),
        },
        "compliance": {
            "assessments": compliance_items,
            "average_score": compliance_average,
            "completed": len(completed_scores),
            "gap_rows": gap_rows,
        },
    }
    snapshot["recommendations"] = build_recommendations(snapshot)
    return snapshot


def build_recommendations(snapshot: dict[str, Any]) -> list[dict[str, str]]:
    """Derive recommendations strictly from observed data gaps."""
    recommendations: list[dict[str, str]] = []

    incidents = snapshot["incidents"]
    vulnerabilities = snapshot["vulnerabilities"]
    identity = snapshot["identity"]
    connectors = snapshot["connectors"]
    operations = snapshot["operations"]
    compliance = snapshot["compliance"]
    assets = snapshot["assets"]

    if not operations["audit"].get("valid"):
        recommendations.append(
            {
                "priority": "high",
                "title": "Restore audit-trail integrity",
                "detail": (
                    "The audit hash chain failed verification at record "
                    f"{operations['audit'].get('broken_at')}. Investigate and escalate before relying on "
                    "audit evidence."
                ),
                "source": "audit chain verification",
            }
        )
    if vulnerabilities["kev"] > 0:
        recommendations.append(
            {
                "priority": "high",
                "title": "Remediate known-exploited vulnerabilities",
                "detail": f"{vulnerabilities['kev']} open vulnerabilities are listed in KEV catalogues.",
                "source": "open vulnerabilities with kev=true",
            }
        )
    if vulnerabilities["overdue"] > 0:
        recommendations.append(
            {
                "priority": "high",
                "title": "Clear overdue vulnerability remediation",
                "detail": (
                    f"{vulnerabilities['overdue']} of {vulnerabilities['open_total']} open vulnerabilities are "
                    "past their remediation due date."
                ),
                "source": "vulnerability due dates",
            }
        )
    if identity["members"] and identity["mfa_ratio"] < 1.0:
        missing = identity["members"] - identity["mfa_enabled"]
        recommendations.append(
            {
                "priority": "high",
                "title": "Enforce MFA for every member",
                "detail": f"{missing} of {identity['members']} active members do not have MFA enabled.",
                "source": "membership and user MFA flags",
            }
        )
    if connectors["insecure_tls"] > 0:
        recommendations.append(
            {
                "priority": "high",
                "title": "Re-enable TLS verification",
                "detail": f"{connectors['insecure_tls']} enabled connectors disable TLS certificate verification.",
                "source": "connector configuration",
            }
        )
    if connectors["unhealthy"] > 0:
        recommendations.append(
            {
                "priority": "medium",
                "title": "Recover degraded integrations",
                "detail": f"{connectors['unhealthy']} connectors are degraded, unhealthy or in error.",
                "source": "connector health",
            }
        )
    if incidents["open"] > 0:
        recommendations.append(
            {
                "priority": "medium",
                "title": "Close open incidents",
                "detail": f"{incidents['open']} incidents detected in the period remain open.",
                "source": "incident status",
            }
        )
    if assets["total"] == 0:
        recommendations.append(
            {
                "priority": "medium",
                "title": "Start the asset inventory",
                "detail": "No assets are inventoried, so exposure and control coverage cannot be measured.",
                "source": "asset inventory",
            }
        )
    elif assets["unowned"] > 0:
        recommendations.append(
            {
                "priority": "medium",
                "title": "Assign owners to inventoried assets",
                "detail": f"{assets['unowned']} of {assets['total']} assets have no owner recorded.",
                "source": "asset ownership metadata",
            }
        )
    if compliance["assessments"] and compliance["assessments"][0]["gap_count"]:
        for item in compliance["assessments"]:
            if item["status"] != "completed" or not item["gap_count"]:
                continue
            recommendations.append(
                {
                    "priority": "medium",
                    "title": f"Close {item['gap_count']} gaps in {item['framework_code']}",
                    "detail": (
                        f"The completed {item['framework_code']} {item['framework_version']} assessment scores "
                        f"{item['score']}% with {item['non_compliant']} non-compliant and {item['partial']} "
                        "partial controls."
                    ),
                    "source": "compliance gap analysis",
                }
            )
    if not compliance["assessments"]:
        recommendations.append(
            {
                "priority": "medium",
                "title": "Run a baseline compliance assessment",
                "detail": "No compliance assessment exists for this organization.",
                "source": "compliance assessments",
            }
        )
    if operations["ingest_sources"] == 0:
        recommendations.append(
            {
                "priority": "medium",
                "title": "Connect at least one log source",
                "detail": "No enabled ingest source is feeding detection, limiting monitoring evidence.",
                "source": "ingest source registry",
            }
        )
    if operations["evidence"] == 0:
        recommendations.append(
            {
                "priority": "low",
                "title": "Collect control evidence",
                "detail": "No evidence records are stored, so manual controls cannot be substantiated.",
                "source": "evidence repository",
            }
        )

    if not recommendations:
        recommendations.append(
            {
                "priority": "low",
                "title": "Maintain the current control baseline",
                "detail": (
                    "No material gaps were detected from the available data in this period; continue scheduled "
                    "reviews and evidence collection."
                ),
                "source": "derived from all report sections",
            }
        )

    order = {"high": 0, "medium": 1, "low": 2}
    recommendations.sort(key=lambda item: order[item["priority"]])
    return recommendations


def _profile_section(snapshot: dict[str, Any]) -> Section:
    organization = snapshot["organization"]
    period = snapshot["period"]
    section = Section("Organization and reporting period")
    section.paragraphs.append(
        f"{organization['name']} ({organization['slug']}) is a {organization['kind']} organization in "
        f"{organization['country']}, sector {organization['sector']}, tier {organization['tier']} and autonomy "
        f"level {organization['autonomy_level']}."
    )
    section.paragraphs.append(
        f"Reporting period: {_fmt(period['start'])} to {_fmt(period['end'])} ({period['days']} days)."
    )
    section.tables.append(
        _table(
            "Organization profile",
            ["Field", "Value"],
            [
                ["Organization", organization["name"]],
                ["Slug", organization["slug"]],
                ["Kind", organization["kind"]],
                ["Country", organization["country"]],
                ["Sector", organization["sector"]],
                ["Tier", organization["tier"]],
                ["Autonomy level", organization["autonomy_level"]],
                ["Data classification", "demo" if organization["is_demo"] else "operational"],
            ],
        )
    )
    return section


def _risk_section(snapshot: dict[str, Any]) -> Section:
    incidents = snapshot["incidents"]
    vulnerabilities = snapshot["vulnerabilities"]
    connectors = snapshot["connectors"]
    identity = snapshot["identity"]
    section = Section("Risk overview")
    section.paragraphs.append(
        f"The period recorded {incidents['total']} incidents ({incidents['open']} still open), "
        f"{vulnerabilities['open_total']} open vulnerabilities ({vulnerabilities['kev']} known-exploited), "
        f"and {connectors['unhealthy']} degraded connectors. MFA coverage is "
        f"{identity['mfa_ratio'] * 100:.1f}% of {identity['members']} active members."
    )
    section.tables.append(
        _table(
            "Key risk indicators",
            ["Indicator", "Value"],
            [
                ["Incidents detected in period", str(incidents["total"])],
                ["Open incidents in period", str(incidents["open"])],
                ["Open vulnerabilities (current)", str(vulnerabilities["open_total"])],
                ["Known-exploited vulnerabilities", str(vulnerabilities["kev"])],
                ["Overdue vulnerabilities", str(vulnerabilities["overdue"])],
                ["Degraded connectors", str(connectors["unhealthy"])],
                ["Connectors without TLS verification", str(connectors["insecure_tls"])],
                ["Members without MFA", str(max(0, identity["members"] - identity["mfa_enabled"]))],
            ],
        )
    )
    return section


def _asset_section(snapshot: dict[str, Any]) -> Section:
    assets = snapshot["assets"]
    section = Section("Asset and exposure overview")
    section.paragraphs.append(
        f"The current inventory holds {assets['total']} assets, including {assets['iot']} IoT and "
        f"{assets['ot']} OT devices. {assets['unowned']} assets have no owner recorded."
    )
    rows = [[kind, str(count)] for kind, count in sorted(assets["by_kind"].items())]
    section.tables.append(_table("Assets by kind", ["Kind", "Count"], rows or [["none recorded", "0"]]))
    if assets["sample"]:
        section.tables.append(
            _table(
                "Inventory sample (highest criticality)",
                ["Asset", "Kind", "Criticality", "Owner"],
                [
                    [item["name"], item["kind"], str(item["criticality"]), item["owner"] or "unassigned"]
                    for item in assets["sample"]
                ],
            )
        )
    return section


def _incident_section(snapshot: dict[str, Any], *, detailed: bool) -> Section:
    incidents = snapshot["incidents"]
    section = Section("Incidents and response")
    section.paragraphs.append(
        f"{incidents['total']} incidents were detected in the period: "
        f"{incidents['resolved']} resolved and {incidents['open']} open. "
        f"Mean time to resolve is {_fmt_duration(incidents['mttr_minutes'])}."
    )
    if detailed:
        section.tables.append(
            _table(
                "Incidents by severity",
                ["Severity", "Count"],
                [[severity, str(incidents["by_severity"].get(severity, 0))] for severity in SEVERITY_ORDER],
            )
        )
        section.tables.append(
            _table(
                "Incidents by status",
                ["Status", "Count"],
                _count_rows(incidents["by_status"], "Status"),
            )
        )
    rows = [
        [
            item["ref"],
            item["title"],
            item["severity"],
            item["status"],
            _fmt(item["detected_at"]),
            _fmt(item["resolved_at"]),
            _fmt_duration(item["mttr_minutes"]),
        ]
        for item in incidents["items"]
    ]
    if rows:
        section.tables.append(
            _table(
                "Incident register",
                ["Reference", "Title", "Severity", "Status", "Detected", "Resolved", "Resolution time"],
                rows,
            )
        )
    else:
        section.paragraphs.append("No incidents were recorded in the selected reporting period.")
    return section


def _vulnerability_section(snapshot: dict[str, Any]) -> Section:
    vulnerabilities = snapshot["vulnerabilities"]
    section = Section("Vulnerability management")
    section.paragraphs.append(
        f"{vulnerabilities['open_total']} vulnerabilities are open, {vulnerabilities['kev']} are known-exploited and "
        f"{vulnerabilities['overdue']} are past their remediation due date."
    )
    section.tables.append(
        _table(
            "Open vulnerabilities by severity",
            ["Severity", "Count"],
            [[severity, str(vulnerabilities["by_severity"].get(severity, 0))] for severity in SEVERITY_ORDER],
        )
    )
    top_rows = [
        [
            item["cve_id"] or "no CVE",
            item["title"],
            item["severity"],
            _fmt(item["cvss"]),
            "yes" if item["kev"] else "no",
            _fmt(item["priority_score"]),
            _fmt(item["due_at"]),
        ]
        for item in vulnerabilities["top"]
    ]
    if top_rows:
        section.tables.append(
            _table(
                "Highest-priority open vulnerabilities",
                ["CVE", "Title", "Severity", "CVSS", "KEV", "Priority", "Due"],
                top_rows,
            )
        )
    else:
        section.paragraphs.append("No open vulnerabilities are recorded for this organization.")
    return section


def _connector_section(snapshot: dict[str, Any]) -> Section:
    connectors = snapshot["connectors"]
    section = Section("Integration and connector health")
    section.paragraphs.append(
        f"{connectors['total']} connectors are registered; {connectors['unhealthy']} are degraded or failing and "
        f"{connectors['insecure_tls']} enabled connectors disable TLS verification."
    )
    section.tables.append(
        _table(
            "Connectors by status",
            ["Status", "Count"],
            _count_rows(connectors["by_status"], "Status"),
        )
    )
    return section


def _technical_operations_section(snapshot: dict[str, Any]) -> Section:
    identity = snapshot["identity"]
    operations = snapshot["operations"]
    section = Section("Identity, logging and audit integrity")
    section.paragraphs.append(
        f"{identity['mfa_enabled']} of {identity['members']} active members use MFA. "
        f"{operations['ingest_sources']} ingest sources and {operations['policies']} policies are enabled. "
        f"The audit hash chain is {'intact' if operations['audit'].get('valid') else 'broken'} across "
        f"{operations['audit'].get('checked', 0)} records."
    )
    section.tables.append(
        _table(
            "Operational controls",
            ["Control", "Observed value"],
            [
                ["Active members", str(identity["members"])],
                ["Members with MFA", str(identity["mfa_enabled"])],
                ["MFA coverage", f"{identity['mfa_ratio'] * 100:.1f}%"],
                ["Enabled ingest sources", str(operations["ingest_sources"])],
                ["Enabled policies", str(operations["policies"])],
                ["Evidence records", str(operations["evidence"])],
                ["Audit chain valid", "yes" if operations["audit"].get("valid") else "no"],
                ["Audit records verified", str(operations["audit"].get("checked", 0))],
            ],
        )
    )
    return section


def _compliance_section(snapshot: dict[str, Any], *, include_gaps: bool) -> Section:
    compliance = snapshot["compliance"]
    section = Section("Compliance self-assessment posture")
    if not compliance["assessments"]:
        section.paragraphs.append(
            "No compliance assessment has been created for this organization, so no framework score is available."
        )
        return section
    average = compliance["average_score"]
    section.paragraphs.append(
        f"{len(compliance['assessments'])} frameworks have assessments; {compliance['completed']} are completed. "
        f"Average completed score: {average if average is not None else 'not available'}%."
    )
    rows = [
        [
            item["framework_code"],
            item["framework_version"],
            item["status"],
            _fmt(item["score"]),
            _fmt(item["completed_at"]),
            str(item["controls_total"]),
            str(item["compliant"]),
            str(item["partial"]),
            str(item["non_compliant"]),
            str(item["not_applicable"]),
            str(item["not_assessed"]),
            str(item["gap_count"]),
        ]
        for item in compliance["assessments"]
    ]
    section.tables.append(
        _table(
            "Assessments by framework",
            [
                "Framework",
                "Version",
                "Status",
                "Score",
                "Completed",
                "Controls",
                "Compliant",
                "Partial",
                "Non-compliant",
                "N/A",
                "Not assessed",
                "Gaps",
            ],
            rows,
        )
    )
    if include_gaps:
        if compliance["gap_rows"]:
            section.tables.append(
                _table(
                    "Open gaps (latest completed assessments)",
                    ["Framework", "Control", "Title", "Status", "Severity", "Recommendation"],
                    compliance["gap_rows"],
                )
            )
        else:
            section.paragraphs.append(
                "No gaps are stored for the latest completed assessments; incomplete assessments are excluded."
            )
    return section


def _recommendations_section(snapshot: dict[str, Any]) -> Section:
    section = Section("Recommendations")
    for item in snapshot["recommendations"]:
        section.bullets.append(f"[{item['priority'].upper()}] {item['title']}: {item['detail']}")
    return section


def _provenance_section(snapshot: dict[str, Any]) -> Section:
    section = Section("Data provenance")
    organization = snapshot["organization"]
    section.paragraphs.append(
        f"All figures were queried from the HISPANSHIELD PostgreSQL database for organization "
        f"{organization['name']} (id {organization['id']}) at {_fmt(snapshot['generated_at'])}. "
        "No synthetic or estimated values are included: empty datasets are reported as zero."
    )
    section.paragraphs.append(
        "Incident counts and resolution times use incidents whose detection timestamp falls inside the reporting "
        "period. Asset, vulnerability, connector and identity figures are current-state snapshots taken at "
        "generation time. Compliance scores are weighted technical self-assessments persisted by the compliance "
        "module, and unassessed controls are reported as such."
    )
    return section


def _disclaimer_section() -> Section:
    section = Section("Disclaimer")
    section.paragraphs.append(REPORT_DISCLAIMER)
    return section


def build_sections(
    kind: str,
    snapshot: dict[str, Any],
) -> list[Section]:
    if kind == "executive":
        return [
            _profile_section(snapshot),
            _risk_section(snapshot),
            _incident_section(snapshot, detailed=False),
            _asset_section(snapshot),
            _compliance_section(snapshot, include_gaps=False),
            _recommendations_section(snapshot),
            _provenance_section(snapshot),
            _disclaimer_section(),
        ]
    if kind == "technical":
        return [
            _profile_section(snapshot),
            _technical_operations_section(snapshot),
            _asset_section(snapshot),
            _vulnerability_section(snapshot),
            _connector_section(snapshot),
            _incident_section(snapshot, detailed=True),
            _compliance_section(snapshot, include_gaps=False),
            _recommendations_section(snapshot),
            _provenance_section(snapshot),
            _disclaimer_section(),
        ]
    if kind == "regulatory":
        return [
            _profile_section(snapshot),
            _compliance_section(snapshot, include_gaps=True),
            _incident_section(snapshot, detailed=True),
            _technical_operations_section(snapshot),
            _recommendations_section(snapshot),
            _provenance_section(snapshot),
            _disclaimer_section(),
        ]
    if kind == "incident":
        timeline_section = Section("Incident timeline")
        timeline = snapshot["incidents"]["timeline"]
        if timeline:
            timeline_section.tables.append(
                _table(
                    "Timeline events",
                    ["Incident", "Timestamp", "Kind", "Summary"],
                    [
                        [
                            entry["incident_ref"],
                            _fmt(entry["at"]),
                            entry["kind"],
                            entry["summary"],
                        ]
                        for entry in timeline
                    ],
                )
            )
        else:
            timeline_section.paragraphs.append("No incident timeline events exist for the period.")
        affected_section = Section("Affected assets")
        affected = snapshot["incidents"]["affected_assets"]
        if affected:
            affected_section.tables.append(
                _table(
                    "Assets referenced by incidents",
                    ["Asset", "Kind", "Criticality"],
                    [[item["name"], item["kind"], str(item["criticality"])] for item in affected],
                )
            )
        else:
            affected_section.paragraphs.append("No asset was linked to the incidents in this period.")
        return [
            _profile_section(snapshot),
            _incident_section(snapshot, detailed=True),
            timeline_section,
            affected_section,
            _vulnerability_section(snapshot),
            _recommendations_section(snapshot),
            _provenance_section(snapshot),
            _disclaimer_section(),
        ]
    raise ValueError(f"Unsupported report kind: {kind}")


def _md_cell(value: Any) -> str:
    return _fmt(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_markdown(title: str, subtitle: str, sections: list[Section]) -> str:
    lines: list[str] = [f"# {title}", "", subtitle, ""]
    for section in sections:
        lines.extend([f"## {section.heading}", ""])
        for paragraph in section.paragraphs:
            lines.extend([paragraph, ""])
        for table in section.tables:
            lines.extend([f"**{table['caption']}**", ""])
            header = "| " + " | ".join(_md_cell(column) for column in table["columns"]) + " |"
            separator = "| " + " | ".join("---" for _ in table["columns"]) + " |"
            lines.extend([header, separator])
            for row in table["rows"]:
                lines.append("| " + " | ".join(_md_cell(cell) for cell in row) + " |")
            lines.append("")
        for bullet in section.bullets:
            lines.append(f"- {bullet}")
        if section.bullets:
            lines.append("")
    lines.append("---")
    lines.append(f"Generated by HISPANSHIELD at {_fmt(utcnow())}.")
    return "\n".join(lines).strip() + "\n"


_REPORT_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 40px 24px;
  background: #f5f6f8;
  color: #16181d;
  font-family: "Segoe UI", "Helvetica Neue", Arial, sans-serif;
  font-size: 14px;
  line-height: 1.55;
}
main.report {
  max-width: 960px;
  margin: 0 auto;
  background: #ffffff;
  border: 1px solid #d9dce3;
  border-radius: 10px;
  padding: 40px 44px 32px;
  box-shadow: 0 8px 28px rgba(22, 24, 29, 0.08);
}
header.report-header { border-bottom: 3px solid #123a63; padding-bottom: 16px; margin-bottom: 28px; }
header.report-header h1 { margin: 0 0 6px; font-size: 26px; letter-spacing: -0.01em; color: #123a63; }
header.report-header p { margin: 0; color: #5a6270; }
section { margin: 30px 0 0; }
section h2 { font-size: 17px; margin: 0 0 10px; color: #123a63; border-left: 4px solid #1f6feb; padding-left: 10px; }
p { margin: 0 0 10px; }
table { width: 100%; border-collapse: collapse; margin: 12px 0 18px; font-size: 13px; }
caption { text-align: left; font-weight: 600; padding-bottom: 6px; color: #3a4150; }
th, td { border: 1px solid #d9dce3; padding: 7px 9px; text-align: left; vertical-align: top; }
th { background: #eef2f7; font-weight: 600; }
tbody tr:nth-child(even) { background: #fafbfc; }
ul { margin: 8px 0 14px; padding-left: 20px; }
li { margin-bottom: 6px; }
footer.report-footer {
  margin-top: 34px;
  border-top: 1px solid #d9dce3;
  padding-top: 14px;
  color: #5a6270;
  font-size: 12px;
}
@media print {
  body { background: #ffffff; padding: 0; }
  main.report { border: none; box-shadow: none; border-radius: 0; max-width: none; padding: 0 8mm; }
  section { break-inside: avoid; }
  thead { display: table-header-group; }
}
"""


def _esc(value: Any) -> str:
    return str(escape(_fmt(value)))


def render_html(title: str, subtitle: str, sections: list[Section]) -> str:
    parts: list[str] = [
        "<!doctype html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        f"<title>{_esc(title)}</title>",
        f"<style>{_REPORT_CSS}</style>",
        "</head>",
        "<body>",
        '<main class="report">',
        '<header class="report-header">',
        f"<h1>{_esc(title)}</h1>",
        f"<p>{_esc(subtitle)}</p>",
        "</header>",
    ]
    for section in sections:
        parts.append("<section>")
        parts.append(f"<h2>{_esc(section.heading)}</h2>")
        for paragraph in section.paragraphs:
            parts.append(f"<p>{_esc(paragraph)}</p>")
        for table in section.tables:
            parts.append("<table>")
            parts.append(f"<caption>{_esc(table['caption'])}</caption>")
            parts.append("<thead><tr>")
            parts.extend(f"<th>{_esc(column)}</th>" for column in table["columns"])
            parts.append("</tr></thead>")
            parts.append("<tbody>")
            for row in table["rows"]:
                parts.append("<tr>")
                parts.extend(f"<td>{_esc(cell)}</td>" for cell in row)
                parts.append("</tr>")
            parts.append("</tbody>")
            parts.append("</table>")
        if section.bullets:
            parts.append("<ul>")
            parts.extend(f"<li>{_esc(bullet)}</li>" for bullet in section.bullets)
            parts.append("</ul>")
        parts.append("</section>")
    parts.extend(
        [
            '<footer class="report-footer">',
            f"<p>Generated by HISPANSHIELD at {_esc(utcnow())}. Checksum computed over the HTML and Markdown "
            "versions combined with SHA-256.</p>",
            "</footer>",
            "</main>",
            "</body>",
            "</html>",
        ]
    )
    return "\n".join(parts) + "\n"


def build_content(kind: str, snapshot: dict[str, Any]) -> tuple[str, str, str]:
    """Return (title, content_markdown, content_html) for a snapshot."""
    organization = snapshot["organization"]
    period = snapshot["period"]
    kind_label = kind.capitalize()
    title = (
        f"{kind_label} report - {organization['name']} "
        f"({_fmt(period['start']).split(' ')[0]} to {_fmt(period['end']).split(' ')[0]})"
    )
    subtitle = (
        f"Technical self-assessment report for {organization['name']} | Kind: {kind} | "
        f"Period: {_fmt(period['start'])} to {_fmt(period['end'])} | Generated: {_fmt(snapshot['generated_at'])}"
    )
    sections = build_sections(kind, snapshot)
    markdown = render_markdown(title, subtitle, sections)
    html = render_html(title, subtitle, sections)
    return title, markdown, html


def report_checksum(content_html: str, content_md: str) -> str:
    return sha256_hex(content_html + content_md)


def safe_filename(report_id: uuid.UUID, kind: str, generated_at: datetime, extension: str) -> str:
    stamp = generated_at.astimezone().strftime("%Y%m%d")
    material = f"{kind}-{stamp}-{report_id.hex[:8]}"
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", material).strip("-") or "report"
    return f"{cleaned}.{extension}"


def build_metadata(
    snapshot: dict[str, Any],
    *,
    kind: str,
    framework_code: str | None,
) -> dict[str, Any]:
    return {
        "organization_id": snapshot["organization"]["id"],
        "organization_name": snapshot["organization"]["name"],
        "kind": kind,
        "period_start": snapshot["period"]["start"].isoformat(),
        "period_end": snapshot["period"]["end"].isoformat(),
        "framework_code": framework_code,
        "provenance": {
            "source": "HISPANSHIELD PostgreSQL operational data",
            "queried_at": snapshot["generated_at"].isoformat(),
            "synthetic_values": False,
            "period_applies_to": "incidents (detection timestamp); other figures are current-state snapshots",
        },
        "counts": {
            "assets": snapshot["assets"]["total"],
            "incidents": snapshot["incidents"]["total"],
            "open_vulnerabilities": snapshot["vulnerabilities"]["open_total"],
            "connectors": snapshot["connectors"]["total"],
            "compliance_assessments": len(snapshot["compliance"]["assessments"]),
        },
        "framework_versions": [
            {
                "code": item["framework_code"],
                "version": item["framework_version"],
                "assessment_id": item["assessment_id"],
                "status": item["status"],
                "score": item["score"],
                "completed_at": (item["completed_at"].isoformat() if item["completed_at"] is not None else None),
            }
            for item in snapshot["compliance"]["assessments"]
        ],
        "disclaimer": REPORT_DISCLAIMER,
    }


def serialize_report_summary(report: Any) -> dict[str, Any]:
    return {
        "id": report.id,
        "kind": report.kind,
        "title": report.title,
        "period_start": report.period_start,
        "period_end": report.period_end,
        "status": report.status,
        "format": report.format,
        "checksum": report.checksum,
        "generated_by": report.generated_by,
        "generated_at": report.generated_at,
        "framework_id": report.framework_id,
        "metadata": dict(report.metadata_json or {}),
    }


def serialize_report_detail(report: Any) -> dict[str, Any]:
    return {
        **serialize_report_summary(report),
        "content_md": report.content_md,
        "content_html": report.content_html,
        "disclaimer": REPORT_DISCLAIMER,
    }
