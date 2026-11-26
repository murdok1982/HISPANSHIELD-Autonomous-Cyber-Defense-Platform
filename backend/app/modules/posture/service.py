"""Deterministic, data-driven security posture summaries.

No LLM is involved: every number is derived from persisted rows and every
recommendation cites the counts/row identifiers that justify it. When a domain
has no source data the endpoint returns empty arrays and
``data_quality="insufficient_data"`` rather than inventing a healthy posture.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import Session
from sqlalchemy.sql.elements import ColumnElement

from app.core.db import utcnow
from app.models.assets import Asset, AttackSurfaceFinding, Vulnerability, Zone
from app.models.connectors import Connector
from app.models.core import Membership, User
from app.models.events import Alert, SecurityEvent

NETWORK_ASSET_KINDS = ("network", "ip")
NETWORK_CONNECTOR_TOKENS = (
    "firewall",
    "ids",
    "ips",
    "waf",
    "suricata",
    "snort",
    "zeek",
    "palo",
    "fortinet",
    "checkpoint",
)
LATERAL_TECHNIQUES = ["T1021", "T1570", "T1550", "T1563"]
DEGRADED_CONNECTOR_STATUSES = {"degraded", "unhealthy", "error", "unconfigured"}
FAILED_LOGIN_WINDOW_DAYS = 30


def _clamp(score: int) -> int:
    return max(0, min(100, int(score)))


def _level(score: int) -> str:
    if score >= 85:
        return "strong"
    if score >= 65:
        return "moderate"
    if score >= 40:
        return "weak"
    return "critical"


def _finding_text(finding: AttackSurfaceFinding) -> str:
    return f"{finding.kind} {finding.title} {finding.evidence or ''}".lower()


def _matches(finding: AttackSurfaceFinding, tokens: tuple[str, ...]) -> bool:
    text = _finding_text(finding)
    return any(token in text for token in tokens)


def _open_findings(db: Session, org_id: UUID) -> list[AttackSurfaceFinding]:
    return list(
        db.execute(
            select(AttackSurfaceFinding)
            .where(AttackSurfaceFinding.org_id == org_id, AttackSurfaceFinding.status == "open")
            .order_by(AttackSurfaceFinding.last_seen.desc())
        ).scalars()
    )


def _factor(name: str, impact: int, detail: dict[str, Any]) -> dict[str, Any]:
    return {"factor": name, "impact": impact, "detail": detail}


def _quality(sources: dict[str, int]) -> str:
    if not any(sources.values()):
        return "insufficient_data"
    if any(value == 0 for value in sources.values()):
        return "partial"
    return "ok"


# --------------------------------------------------------------------------- #
# Network
# --------------------------------------------------------------------------- #
def network_posture(db: Session, org_id: UUID) -> dict[str, Any]:
    assets = list(
        db.execute(
            select(Asset).where(Asset.org_id == org_id, Asset.kind.in_(NETWORK_ASSET_KINDS)).order_by(Asset.name)
        ).scalars()
    )
    exposed_assets = [asset for asset in assets if asset.ip_addresses]
    findings = _open_findings(db, org_id)
    exposure_tokens = ("expos", "port", "service", "public", "open")
    exposed_findings = [item for item in findings if _matches(item, exposure_tokens)]

    lateral_conditions: list[ColumnElement[bool]] = [
        func.lower(Alert.title).like("%lateral%"),
        func.lower(func.coalesce(Alert.description, "")).like("%lateral%"),
    ]
    lateral_conditions.extend(Alert.mitre.contains([technique]) for technique in LATERAL_TECHNIQUES)
    lateral_alerts = list(
        db.execute(
            select(Alert)
            .where(
                Alert.org_id == org_id,
                Alert.status.notin_(["closed", "resolved", "suppressed"]),
                or_(*lateral_conditions),
            )
            .order_by(Alert.created_at.desc())
            .limit(200)
        ).scalars()
    )

    zones = list(db.execute(select(Zone).where(Zone.org_id == org_id)).scalars())
    ot_assets = list(db.execute(select(Asset).where(Asset.org_id == org_id, Asset.kind == "ot")).scalars())
    unzoned_ot = [asset for asset in ot_assets if asset.zone_id is None]
    conduits = [zone for zone in zones if zone.kind == "conduit"]
    conduits_without_sl = [zone for zone in conduits if not (zone.metadata_json or {}).get("required_sl")]
    purdue_levels = {zone.purdue_level for zone in zones if zone.purdue_level is not None}
    purdue_gap = bool(purdue_levels) and min(purdue_levels) <= 2 and max(purdue_levels) >= 3 and not conduits

    connectors = list(db.execute(select(Connector).where(Connector.org_id == org_id)).scalars())
    network_connectors = [
        connector
        for connector in connectors
        if any(token in connector.connector_type.lower() for token in NETWORK_CONNECTOR_TOKENS)
    ]
    connector_status = Counter(connector.status for connector in network_connectors)
    degraded_connectors = [
        connector
        for connector in network_connectors
        if connector.status in DEGRADED_CONNECTOR_STATUSES or bool(connector.last_error)
    ]

    segmentation_gaps: list[dict[str, Any]] = []
    if unzoned_ot:
        segmentation_gaps.append(
            {
                "kind": "unzoned_ot_assets",
                "count": len(unzoned_ot),
                "asset_ids": [str(asset.id) for asset in unzoned_ot[:20]],
            }
        )
    if conduits_without_sl:
        segmentation_gaps.append(
            {
                "kind": "conduit_without_required_sl",
                "count": len(conduits_without_sl),
                "zone_ids": [str(zone.id) for zone in conduits_without_sl[:20]],
            }
        )
    if purdue_gap:
        segmentation_gaps.append(
            {
                "kind": "missing_it_ot_conduit",
                "count": 1,
                "purdue_levels": sorted(level for level in purdue_levels if level is not None),
            }
        )

    score = 100
    factors: list[dict[str, Any]] = []
    exposure_impact = min(40, len(exposed_findings) * 8)
    if exposure_impact:
        factors.append(_factor("exposed_services", exposure_impact, {"open_findings": len(exposed_findings)}))
    lateral_impact = min(20, len(lateral_alerts) * 10)
    if lateral_impact:
        factors.append(_factor("lateral_movement_signals", lateral_impact, {"open_alerts": len(lateral_alerts)}))
    segmentation_impact = min(15, len(unzoned_ot) * 5 + len(conduits_without_sl) * 6 + (6 if purdue_gap else 0))
    if segmentation_impact:
        factors.append(
            _factor(
                "segmentation_gaps",
                segmentation_impact,
                {
                    "unzoned_ot_assets": len(unzoned_ot),
                    "conduits_without_required_sl": len(conduits_without_sl),
                    "missing_it_ot_conduit": purdue_gap,
                },
            )
        )
    connector_impact = min(10, len(degraded_connectors) * 5)
    if connector_impact:
        factors.append(
            _factor("network_control_health", connector_impact, {"degraded_connectors": len(degraded_connectors)})
        )
    for item in factors:
        score -= item["impact"]
    score = _clamp(score)

    recommendations: list[dict[str, Any]] = []
    if exposed_findings:
        recommendations.append(
            {
                "id": "NET-01",
                "severity": "high",
                "title": "Reduce exposed network services",
                "detail": "Close, filter or authenticate internet-reachable services identified by exposure findings.",
                "evidence": {
                    "open_exposed_findings": len(exposed_findings),
                    "finding_ids": [str(item.id) for item in exposed_findings[:20]],
                    "severities": dict(Counter(item.severity for item in exposed_findings)),
                },
            }
        )
    if lateral_alerts:
        recommendations.append(
            {
                "id": "NET-02",
                "severity": "critical" if len(lateral_alerts) >= 3 else "high",
                "title": "Investigate lateral movement signals",
                "detail": "Alerts reference lateral movement techniques; validate segmentation and credential hygiene.",
                "evidence": {
                    "open_lateral_alerts": len(lateral_alerts),
                    "alert_ids": [str(item.id) for item in lateral_alerts[:20]],
                    "techniques": LATERAL_TECHNIQUES,
                },
            }
        )
    if segmentation_gaps:
        recommendations.append(
            {
                "id": "NET-03",
                "severity": "high" if unzoned_ot else "medium",
                "title": "Close IEC 62443 segmentation gaps",
                "detail": "Assign OT assets to zones and declare conduits with a required security level.",
                "evidence": {"gaps": segmentation_gaps, "zone_count": len(zones)},
            }
        )
    if degraded_connectors:
        recommendations.append(
            {
                "id": "NET-04",
                "severity": "medium",
                "title": "Restore firewall/IDS connector health",
                "detail": "Network control connectors are degraded; visibility may be incomplete.",
                "evidence": {
                    "network_connectors": len(network_connectors),
                    "degraded_connectors": len(degraded_connectors),
                    "connector_ids": [str(item.id) for item in degraded_connectors[:20]],
                    "status_counts": dict(connector_status),
                },
            }
        )

    return {
        "generated_at": utcnow(),
        "score": score,
        "level": _level(score),
        "data_quality": _quality(
            {
                "network_assets": len(assets),
                "open_findings": len(findings),
                "network_connectors": len(network_connectors),
                "ot_zones": len(zones),
            }
        ),
        "factors": factors,
        "assets": {
            "total": len(assets),
            "by_kind": dict(Counter(asset.kind for asset in assets)),
            "with_ip_addresses": len(exposed_assets),
            "criticality_counts": dict(Counter(asset.criticality for asset in assets)),
            "rows": [
                {
                    "id": str(asset.id),
                    "name": asset.name,
                    "kind": asset.kind,
                    "criticality": asset.criticality,
                    "ip_addresses": list(asset.ip_addresses or []),
                    "zone_id": str(asset.zone_id) if asset.zone_id else None,
                }
                for asset in assets[:50]
            ],
        },
        "exposed_findings": [
            {
                "id": str(item.id),
                "kind": item.kind,
                "title": item.title,
                "severity": item.severity,
                "asset_id": str(item.asset_id) if item.asset_id else None,
                "last_seen": item.last_seen,
            }
            for item in exposed_findings[:50]
        ],
        "lateral_movement_alerts": [
            {
                "id": str(item.id),
                "title": item.title,
                "severity": item.severity,
                "count": item.count,
                "mitre": list(item.mitre or []),
                "last_seen": item.last_seen,
            }
            for item in lateral_alerts[:50]
        ],
        "zones": {
            "total": len(zones),
            "conduits": len(conduits),
            "purdue_levels": sorted(level for level in purdue_levels if level is not None),
            "segmentation_gaps": segmentation_gaps,
        },
        "connectors": {
            "network_total": len(network_connectors),
            "by_status": dict(connector_status),
            "degraded_ids": [str(item.id) for item in degraded_connectors[:20]],
        },
        "recommendations": recommendations,
    }


# --------------------------------------------------------------------------- #
# Cloud
# --------------------------------------------------------------------------- #
def cloud_posture(db: Session, org_id: UUID) -> dict[str, Any]:
    assets = list(
        db.execute(select(Asset).where(Asset.org_id == org_id, Asset.kind == "cloud").order_by(Asset.name)).scalars()
    )
    by_provider: dict[str, int] = defaultdict(int)
    by_subtype: dict[str, int] = defaultdict(int)
    for asset in assets:
        provider = asset.vendor or (asset.metadata_json or {}).get("provider") or asset.subtype or "unknown"
        by_provider[str(provider)] += 1
        by_subtype[str(asset.subtype or "unspecified")] += 1

    findings = _open_findings(db, org_id)
    identity_tokens = ("iam", "identity", "privilege", "credential", "role", "mfa")
    public_storage = [
        item
        for item in findings
        if _matches(item, ("storage", "bucket", "s3", "blob")) and _matches(item, ("public", "expos", "open"))
    ]
    identity_findings = [item for item in findings if _matches(item, identity_tokens)]

    vuln_rows = db.execute(
        select(Vulnerability.severity, func.count())
        .join(Asset, Asset.id == Vulnerability.asset_id)
        .where(
            Vulnerability.org_id == org_id,
            Vulnerability.status == "open",
            Asset.kind == "cloud",
        )
        .group_by(Vulnerability.severity)
    ).all()
    vuln_counts = {str(severity): int(count) for severity, count in vuln_rows}
    critical_vulns = vuln_counts.get("critical", 0)
    high_vulns = vuln_counts.get("high", 0)

    score = 100
    factors: list[dict[str, Any]] = []
    storage_impact = min(45, len(public_storage) * 15)
    if storage_impact:
        factors.append(_factor("public_storage", storage_impact, {"open_findings": len(public_storage)}))
    identity_impact = min(20, len(identity_findings) * 6)
    if identity_impact:
        factors.append(_factor("cloud_identity_findings", identity_impact, {"open_findings": len(identity_findings)}))
    vuln_impact = min(35, critical_vulns * 6 + high_vulns * 2)
    if vuln_impact:
        factors.append(
            _factor(
                "cloud_vulnerabilities",
                vuln_impact,
                {"critical": critical_vulns, "high": high_vulns, "by_severity": vuln_counts},
            )
        )
    for item in factors:
        score -= item["impact"]
    score = _clamp(score)

    recommendations: list[dict[str, Any]] = []
    if public_storage:
        recommendations.append(
            {
                "id": "CLOUD-01",
                "severity": "critical",
                "title": "Remediate public cloud storage",
                "detail": "Block public read/write on buckets or objects flagged by posture findings.",
                "evidence": {
                    "public_storage_findings": len(public_storage),
                    "finding_ids": [str(item.id) for item in public_storage[:20]],
                    "assets": [str(item.asset_id) for item in public_storage if item.asset_id],
                },
            }
        )
    if identity_findings:
        recommendations.append(
            {
                "id": "CLOUD-02",
                "severity": "high",
                "title": "Tighten cloud identities and permissions",
                "detail": "Remove wildcard permissions and enforce least privilege on cloud roles.",
                "evidence": {
                    "identity_findings": len(identity_findings),
                    "finding_ids": [str(item.id) for item in identity_findings[:20]],
                },
            }
        )
    if critical_vulns or high_vulns:
        recommendations.append(
            {
                "id": "CLOUD-03",
                "severity": "high",
                "title": "Patch cloud workloads",
                "detail": "Prioritise critical and known-exploited vulnerabilities on cloud assets.",
                "evidence": {"critical": critical_vulns, "high": high_vulns, "by_severity": vuln_counts},
            }
        )

    return {
        "generated_at": utcnow(),
        "score": score,
        "level": _level(score),
        "data_quality": "insufficient_data" if not assets and not findings and not vuln_counts else "ok",
        "factors": factors,
        "assets": {
            "total": len(assets),
            "by_provider": dict(by_provider),
            "by_subtype": dict(by_subtype),
            "rows": [
                {
                    "id": str(asset.id),
                    "name": asset.name,
                    "subtype": asset.subtype,
                    "provider": asset.vendor or (asset.metadata_json or {}).get("provider"),
                    "criticality": asset.criticality,
                    "status": asset.status,
                }
                for asset in assets[:50]
            ],
        },
        "public_storage_findings": [
            {
                "id": str(item.id),
                "title": item.title,
                "severity": item.severity,
                "asset_id": str(item.asset_id) if item.asset_id else None,
            }
            for item in public_storage[:50]
        ],
        "identity_findings": [
            {
                "id": str(item.id),
                "title": item.title,
                "severity": item.severity,
                "asset_id": str(item.asset_id) if item.asset_id else None,
            }
            for item in identity_findings[:50]
        ],
        "vulnerabilities": {"open_total": sum(vuln_counts.values()), "by_severity": vuln_counts},
        "recommendations": recommendations,
    }


# --------------------------------------------------------------------------- #
# Identity
# --------------------------------------------------------------------------- #
def identity_posture(db: Session, org_id: UUID) -> dict[str, Any]:
    identity_assets = list(
        db.execute(select(Asset).where(Asset.org_id == org_id, Asset.kind == "identity").order_by(Asset.name)).scalars()
    )
    member_rows = db.execute(
        select(User)
        .join(Membership, Membership.user_id == User.id)
        .where(Membership.org_id == org_id, Membership.status == "active", User.status == "active")
    ).scalars()
    members = list(member_rows)
    mfa_enabled = sum(1 for user in members if user.mfa_enabled)
    mfa_percent = round((mfa_enabled / len(members)) * 100, 1) if members else 0.0

    since = utcnow() - timedelta(days=FAILED_LOGIN_WINDOW_DAYS)
    failed_conditions = or_(
        func.lower(SecurityEvent.message).like("%failed login%"),
        func.lower(SecurityEvent.message).like("%authentication failure%"),
        and_(
            SecurityEvent.class_uid.in_([3002, 3003]),
            func.lower(SecurityEvent.message).like("%fail%"),
        ),
    )
    failed_logins = int(
        db.execute(
            select(func.count())
            .select_from(SecurityEvent)
            .where(SecurityEvent.org_id == org_id, SecurityEvent.occurred_at >= since, failed_conditions)
        ).scalar_one()
    )
    top_failed_users = [
        {"user_name": str(user_name), "count": int(count)}
        for user_name, count in db.execute(
            select(SecurityEvent.user_name, func.count())
            .where(
                SecurityEvent.org_id == org_id,
                SecurityEvent.occurred_at >= since,
                SecurityEvent.user_name.is_not(None),
                failed_conditions,
            )
            .group_by(SecurityEvent.user_name)
            .order_by(func.count().desc())
            .limit(5)
        ).all()
    ]

    identity_alerts = list(
        db.execute(
            select(Alert)
            .where(
                Alert.org_id == org_id,
                Alert.status.notin_(["closed", "resolved", "suppressed"]),
                or_(
                    func.lower(Alert.title).like("%identity%"),
                    func.lower(Alert.title).like("%credential%"),
                    func.lower(Alert.title).like("%account%"),
                    Alert.mitre.contains(["T1078"]),
                    Alert.mitre.contains(["T1110"]),
                    Alert.mitre.contains(["T1621"]),
                ),
            )
            .order_by(Alert.created_at.desc())
            .limit(200)
        ).scalars()
    )
    findings = _open_findings(db, org_id)
    identity_findings = [
        item for item in findings if _matches(item, ("identity", "iam", "credential", "privilege", "mfa", "account"))
    ]

    score = 100
    factors: list[dict[str, Any]] = []
    if members:
        mfa_impact = int(round((100 - mfa_percent) * 0.4))
        if mfa_impact:
            factors.append(
                _factor(
                    "mfa_adoption",
                    mfa_impact,
                    {"members": len(members), "mfa_enabled": mfa_enabled, "mfa_percent": mfa_percent},
                )
            )
            score -= mfa_impact
    login_impact = min(20, failed_logins * 2)
    if login_impact:
        factors.append(_factor("failed_logins_30d", login_impact, {"failed_logins": failed_logins}))
        score -= login_impact
    alert_impact = min(20, len(identity_alerts) * 8)
    if alert_impact:
        factors.append(_factor("identity_alerts", alert_impact, {"open_alerts": len(identity_alerts)}))
        score -= alert_impact
    finding_impact = min(10, len(identity_findings) * 5)
    if finding_impact:
        factors.append(_factor("identity_findings", finding_impact, {"open_findings": len(identity_findings)}))
        score -= finding_impact
    score = _clamp(score)

    recommendations: list[dict[str, Any]] = []
    if members and mfa_percent < 100:
        recommendations.append(
            {
                "id": "ID-01",
                "severity": "high" if mfa_percent < 50 else "medium",
                "title": "Increase MFA adoption",
                "detail": "Enforce TOTP MFA for every active organization member.",
                "evidence": {
                    "members": len(members),
                    "mfa_enabled": mfa_enabled,
                    "mfa_percent": mfa_percent,
                    "missing_mfa_user_ids": [str(user.id) for user in members if not user.mfa_enabled][:50],
                },
            }
        )
    if failed_logins:
        recommendations.append(
            {
                "id": "ID-02",
                "severity": "high" if failed_logins >= 5 else "medium",
                "title": "Investigate authentication failures",
                "detail": "Repeated failed logins may indicate password spraying or credential stuffing.",
                "evidence": {
                    "failed_logins": failed_logins,
                    "window_days": FAILED_LOGIN_WINDOW_DAYS,
                    "top_users": top_failed_users,
                },
            }
        )
    if identity_alerts:
        recommendations.append(
            {
                "id": "ID-03",
                "severity": "high",
                "title": "Review identity-related alerts",
                "detail": "Triage alerts referencing valid accounts, brute force or MFA abuse.",
                "evidence": {
                    "open_identity_alerts": len(identity_alerts),
                    "alert_ids": [str(item.id) for item in identity_alerts[:20]],
                },
            }
        )
    if identity_findings:
        recommendations.append(
            {
                "id": "ID-04",
                "severity": "medium",
                "title": "Remediate identity findings",
                "detail": "Remove stale identities and excessive privileges detected by discovery.",
                "evidence": {
                    "identity_findings": len(identity_findings),
                    "finding_ids": [str(item.id) for item in identity_findings[:20]],
                },
            }
        )

    return {
        "generated_at": utcnow(),
        "score": score,
        "level": _level(score),
        "data_quality": "insufficient_data" if not members and not identity_assets and not failed_logins else "ok",
        "factors": factors,
        "identities": {
            "assets": len(identity_assets),
            "members": len(members),
            "mfa_enabled": mfa_enabled,
            "mfa_percent": mfa_percent,
            "rows": [
                {
                    "id": str(asset.id),
                    "name": asset.name,
                    "subtype": asset.subtype,
                    "criticality": asset.criticality,
                }
                for asset in identity_assets[:50]
            ],
        },
        "failed_logins": {
            "window_days": FAILED_LOGIN_WINDOW_DAYS,
            "total": failed_logins,
            "top_users": top_failed_users,
        },
        "identity_alerts": [
            {
                "id": str(item.id),
                "title": item.title,
                "severity": item.severity,
                "status": item.status,
                "mitre": list(item.mitre or []),
            }
            for item in identity_alerts[:50]
        ],
        "identity_findings": [
            {"id": str(item.id), "title": item.title, "severity": item.severity} for item in identity_findings[:50]
        ],
        "recommendations": recommendations,
    }


# --------------------------------------------------------------------------- #
# Combined summary
# --------------------------------------------------------------------------- #
def posture_summary(db: Session, org_id: UUID) -> dict[str, Any]:
    network = network_posture(db, org_id)
    cloud = cloud_posture(db, org_id)
    identity = identity_posture(db, org_id)

    domains = [
        ("network", network, 0.4),
        ("cloud", cloud, 0.3),
        ("identity", identity, 0.3),
    ]
    available = [
        (name, payload, weight) for name, payload, weight in domains if payload["data_quality"] != "insufficient_data"
    ]
    if available:
        total_weight = sum(weight for _name, _payload, weight in available)
        overall = _clamp(round(sum(payload["score"] * weight for _name, payload, weight in available) / total_weight))
    else:
        overall = 0

    factors: list[dict[str, Any]] = []
    recommendations: list[dict[str, Any]] = []
    for name, payload, _weight in domains:
        for factor in payload["factors"]:
            factors.append({"domain": name, **factor})
        for recommendation in payload["recommendations"]:
            recommendations.append({"domain": name, **recommendation})

    quality = "ok"
    if not available:
        quality = "insufficient_data"
    elif any(payload["data_quality"] != "ok" for _name, payload, _weight in domains):
        quality = "partial"

    return {
        "generated_at": utcnow(),
        "score": overall,
        "level": _level(overall),
        "data_quality": quality,
        "scores": {
            "network": network["score"],
            "cloud": cloud["score"],
            "identity": identity["score"],
        },
        "weights": {"network": 0.4, "cloud": 0.3, "identity": 0.3},
        "factors": factors,
        "recommendations": sorted(
            recommendations,
            key=lambda item: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(item["severity"], 5),
        ),
        "domains": {
            "network": network,
            "cloud": cloud,
            "identity": identity,
        },
    }


__all__ = ["cloud_posture", "identity_posture", "network_posture", "posture_summary"]
