"""Deterministic technical-check engine evaluated against real platform data.

Every check reads persisted data for the active organization. No check invents
results: when the evidence needed for a check is absent the check fails (or is
marked not applicable for purely OT-specific controls) with an explicit detail
string. This keeps compliance scores honest and reproducible.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.audit import verify_audit_chain
from app.core.config import settings as platform_settings
from app.core.db import utcnow
from app.core.rbac import ROLE_LABELS
from app.models.assets import Asset, OTDevice, Vulnerability, Zone
from app.models.connectors import Connector
from app.models.core import Membership, Policy, User
from app.models.events import IngestSource
from app.models.incidents import Evidence, Playbook

BACKUP_POLICY_KINDS = {"backup", "continuity", "business_continuity", "disaster_recovery"}
RETENTION_POLICY_KINDS = {"retention", "records_retention", "data_retention"}
INCIDENT_POLICY_KINDS = {"incident", "incident_response", "incident_management", "ir"}
SUPPLIER_POLICY_KINDS = {"supplier", "supply_chain", "supplier_management", "procurement"}
ENCRYPTION_POLICY_KINDS = {"cryptography", "encryption", "crypto", "key_management"}
LOGGING_POLICY_KINDS = {"logging", "monitoring", "log_management"}
ACCESS_REVIEW_POLICY_KINDS = {"access_review", "access_control_review"}
DATA_PROTECTION_POLICY_KINDS = {"data_protection", "privacy", "data_minimisation", "gdpr"}
PATCH_POLICY_KINDS = {"patch_management", "patching", "vulnerability_management"}


def _parse_datetime(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    return None


@dataclass
class Signals:
    """Point-in-time snapshot of the evidence used to evaluate controls."""

    db: Session
    org_id: uuid.UUID
    org_settings: dict[str, Any]
    members_total: int
    members_mfa: int
    admin_count: int
    unknown_roles: list[str]
    audit: dict[str, Any]
    connectors_enabled: int
    connectors_total: int
    connectors_insecure_tls: int
    connectors_status: dict[str, int]
    policies: list[Policy]
    assets_total: int
    assets_covered: int
    assets_by_kind: dict[str, int]
    ot_total: int
    ot_passive: int
    ot_zoned: int
    zones_total: int
    vulns_open: int
    vulns_overdue: int
    vulns_kev: int
    ingest_sources_enabled: int
    published_playbooks: int
    evidence_total: int
    conduits_total: int = 0
    conduits_missing_compensating_control: int = 0
    last_access_review_at: datetime | None = None
    captured_at: datetime = field(default_factory=utcnow)


def build_signals(db: Session, org_id: uuid.UUID, org_settings: dict[str, Any]) -> Signals:
    """Collect all aggregate evidence needed by the check engine in one pass."""
    membership_rows = db.execute(
        select(User.mfa_enabled, Membership.role, func.count())
        .join(Membership, Membership.user_id == User.id)
        .where(Membership.org_id == org_id, Membership.status == "active", User.status == "active")
        .group_by(User.mfa_enabled, Membership.role)
    ).all()

    members_total = 0
    members_mfa = 0
    admin_count = 0
    unknown_roles: list[str] = []
    for mfa_enabled, role, count in membership_rows:
        amount = int(count)
        members_total += amount
        if mfa_enabled:
            members_mfa += amount
        if role == "org_admin":
            admin_count += amount
        if role not in ROLE_LABELS:
            unknown_roles.append(str(role))

    connector_rows = db.execute(
        select(Connector.status, Connector.verify_tls, Connector.enabled, func.count())
        .where(Connector.org_id == org_id)
        .group_by(Connector.status, Connector.verify_tls, Connector.enabled)
    ).all()
    connectors_total = 0
    connectors_enabled = 0
    connectors_insecure_tls = 0
    connectors_status: dict[str, int] = {}
    for status, verify_tls, enabled, count in connector_rows:
        amount = int(count)
        connectors_total += amount
        connectors_status[str(status)] = connectors_status.get(str(status), 0) + amount
        if enabled:
            connectors_enabled += amount
            if not verify_tls:
                connectors_insecure_tls += amount

    policies = list(
        db.execute(
            select(Policy).where(
                or_(Policy.org_id == org_id, Policy.org_id.is_(None)),
                Policy.enabled.is_(True),
            )
        ).scalars()
    )

    assets_total = db.execute(
        select(func.count()).select_from(Asset).where(Asset.org_id == org_id, Asset.deleted_at.is_(None))
    ).scalar_one()
    assets_covered = db.execute(
        select(func.count())
        .select_from(Asset)
        .where(
            Asset.org_id == org_id,
            Asset.deleted_at.is_(None),
            or_(
                Asset.owner.isnot(None),
                Asset.zone_id.isnot(None),
                func.jsonb_array_length(Asset.tags) > 0,
            ),
        )
    ).scalar_one()
    assets_by_kind = {
        str(kind): int(count)
        for kind, count in db.execute(
            select(Asset.kind, func.count())
            .where(Asset.org_id == org_id, Asset.deleted_at.is_(None))
            .group_by(Asset.kind)
        ).all()
    }

    zone_rows = db.execute(select(Zone.kind, func.count()).where(Zone.org_id == org_id).group_by(Zone.kind)).all()
    zones_total = sum(int(count) for kind, count in zone_rows if str(kind) == "zone")

    conduits = list(db.execute(select(Zone).where(Zone.org_id == org_id, Zone.kind == "conduit")).scalars())
    conduits_missing_control = 0
    for conduit in conduits:
        metadata = conduit.metadata_json if isinstance(conduit.metadata_json, dict) else {}
        required_sl = metadata.get("required_sl")
        compensating = metadata.get("compensating_controls") or metadata.get("compensating_control")
        if isinstance(required_sl, int) and required_sl >= 3 and not compensating:
            conduits_missing_control += 1

    ot_total = db.execute(select(func.count()).select_from(OTDevice).where(OTDevice.org_id == org_id)).scalar_one()
    ot_passive = db.execute(
        select(func.count()).select_from(OTDevice).where(OTDevice.org_id == org_id, OTDevice.passive_only.is_(True))
    ).scalar_one()
    ot_zoned = db.execute(
        select(func.count()).select_from(OTDevice).where(OTDevice.org_id == org_id, OTDevice.zone_id.isnot(None))
    ).scalar_one()

    now = utcnow()
    vulns_open = db.execute(
        select(func.count())
        .select_from(Vulnerability)
        .where(Vulnerability.org_id == org_id, Vulnerability.status == "open")
    ).scalar_one()
    vulns_overdue = db.execute(
        select(func.count())
        .select_from(Vulnerability)
        .where(
            Vulnerability.org_id == org_id,
            Vulnerability.status == "open",
            Vulnerability.due_at.isnot(None),
            Vulnerability.due_at < now,
        )
    ).scalar_one()
    vulns_kev = db.execute(
        select(func.count())
        .select_from(Vulnerability)
        .where(Vulnerability.org_id == org_id, Vulnerability.status == "open", Vulnerability.kev.is_(True))
    ).scalar_one()

    ingest_sources_enabled = db.execute(
        select(func.count())
        .select_from(IngestSource)
        .where(IngestSource.org_id == org_id, IngestSource.enabled.is_(True))
    ).scalar_one()
    published_playbooks = db.execute(
        select(func.count())
        .select_from(Playbook)
        .where(
            or_(Playbook.org_id == org_id, Playbook.org_id.is_(None)),
            Playbook.status == "published",
        )
    ).scalar_one()
    evidence_total = db.execute(
        select(func.count()).select_from(Evidence).where(Evidence.org_id == org_id)
    ).scalar_one()

    review_candidates: list[datetime] = []
    settings_review = _parse_datetime(org_settings.get("last_access_review_at"))
    if settings_review:
        review_candidates.append(settings_review)
    for policy in policies:
        if policy.kind in ACCESS_REVIEW_POLICY_KINDS:
            review_candidates.append(policy.updated_at)
            definition_review = _parse_datetime(policy.definition.get("last_review_at"))
            if definition_review:
                review_candidates.append(definition_review)

    return Signals(
        db=db,
        org_id=org_id,
        org_settings=dict(org_settings or {}),
        members_total=members_total,
        members_mfa=members_mfa,
        admin_count=admin_count,
        unknown_roles=sorted(set(unknown_roles)),
        audit=verify_audit_chain(db, org_id),
        connectors_enabled=connectors_enabled,
        connectors_total=connectors_total,
        connectors_insecure_tls=connectors_insecure_tls,
        connectors_status=connectors_status,
        policies=policies,
        assets_total=int(assets_total),
        assets_covered=int(assets_covered),
        assets_by_kind=assets_by_kind,
        ot_total=int(ot_total),
        ot_passive=int(ot_passive),
        ot_zoned=int(ot_zoned),
        zones_total=int(zones_total),
        conduits_total=len(conduits),
        conduits_missing_compensating_control=conduits_missing_control,
        vulns_open=int(vulns_open),
        vulns_overdue=int(vulns_overdue),
        vulns_kev=int(vulns_kev),
        ingest_sources_enabled=int(ingest_sources_enabled),
        published_playbooks=int(published_playbooks),
        evidence_total=int(evidence_total),
        last_access_review_at=max(review_candidates) if review_candidates else None,
    )


# ---------------------------------------------------------------------------
# Parameter and setting helpers
# ---------------------------------------------------------------------------


def _int_param(params: dict[str, Any], key: str, default: int) -> int:
    try:
        return int(params.get(key, default))
    except (TypeError, ValueError):
        return default


def _float_param(params: dict[str, Any], key: str, default: float) -> float:
    try:
        return float(params.get(key, default))
    except (TypeError, ValueError):
        return default


def _bool_param(params: dict[str, Any], key: str, default: bool) -> bool:
    value = params.get(key, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return bool(value)


def _setting_bool(settings: dict[str, Any], *keys: str) -> bool | None:
    for key in keys:
        if key in settings and settings[key] is not None:
            value = settings[key]
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.strip().lower() in {"1", "true", "yes", "on"}
            return bool(value)
    return None


def _setting_int(settings: dict[str, Any], *keys: str) -> int | None:
    for key in keys:
        if key in settings and settings[key] is not None:
            try:
                return int(settings[key])
            except (TypeError, ValueError):
                continue
    return None


def _policy(signals: Signals, kinds: set[str]) -> Policy | None:
    for policy in signals.policies:
        if policy.kind in kinds:
            return policy
    return None


def _policy_days(policy: Policy) -> int | None:
    definition = policy.definition or {}
    for key in ("security_events_days", "retention_days", "audit_days", "days", "min_days"):
        if key in definition:
            try:
                return int(definition[key])
            except (TypeError, ValueError):
                continue
    return None


def _policy_bool(policy: Policy | None) -> bool:
    if policy is None:
        return False
    definition = policy.definition or {}
    for key in ("enabled", "operational", "configured", "implemented", "reviewed"):
        if key in definition and isinstance(definition[key], bool):
            return definition[key]
    return True


def _result(applicable: bool, passed: bool, observed: dict[str, Any], detail: str) -> dict[str, Any]:
    return {"applicable": applicable, "passed": passed, "observed": observed, "detail": detail}


# ---------------------------------------------------------------------------
# Individual check evaluators
# ---------------------------------------------------------------------------


def _mfa_enforced(signals: Signals, params: dict[str, Any]) -> dict[str, Any]:
    minimum = _float_param(params, "min_ratio", 1.0)
    if signals.members_total == 0:
        return _result(False, True, {"members": 0}, "No active memberships to evaluate.")
    ratio = signals.members_mfa / signals.members_total
    passed = ratio >= minimum
    return _result(
        True,
        passed,
        {
            "members": signals.members_total,
            "mfa_members": signals.members_mfa,
            "ratio": round(ratio, 4),
            "min_ratio": minimum,
        },
        f"{signals.members_mfa}/{signals.members_total} active members use MFA "
        f"(ratio {ratio:.2f}, required {minimum:.2f}).",
    )


def _audit_chain_valid(signals: Signals, params: dict[str, Any]) -> dict[str, Any]:
    audit = signals.audit or {}
    passed = bool(audit.get("valid"))
    detail = (
        f"Audit hash chain verified across {audit.get('checked', 0)} records."
        if passed
        else f"Audit hash chain diverged at record {audit.get('broken_at')} ({audit.get('reason')})."
    )
    return _result(
        True,
        passed,
        {
            "valid": passed,
            "checked": audit.get("checked", 0),
            "broken_at": audit.get("broken_at"),
            "reason": audit.get("reason"),
        },
        detail,
    )


def _connector_tls(signals: Signals, params: dict[str, Any]) -> dict[str, Any]:
    require_all = _bool_param(params, "require_all", True)
    if signals.connectors_enabled == 0:
        return _result(
            True,
            False,
            {"enabled_connectors": 0},
            "No enabled connectors provide evidence of TLS verification.",
        )
    insecure = signals.connectors_insecure_tls
    passed = insecure == 0 if require_all else insecure < signals.connectors_enabled
    return _result(
        True,
        passed,
        {
            "enabled_connectors": signals.connectors_enabled,
            "insecure_tls": insecure,
            "status": signals.connectors_status,
        },
        f"{insecure} of {signals.connectors_enabled} enabled connectors disable TLS verification.",
    )


def _backup_configured(signals: Signals, params: dict[str, Any]) -> dict[str, Any]:
    configured = _setting_bool(signals.org_settings, "backup_configured", "backups_enabled")
    policy = _policy(signals, BACKUP_POLICY_KINDS)
    passed = bool(configured) if configured is not None else _policy_bool(policy)
    source = "organization settings" if configured is not None else (policy.name if policy else "no source")
    return _result(
        True,
        passed,
        {"configured": passed, "source": source},
        f"Backup configuration {'declared' if passed else 'not declared'} ({source}).",
    )


def _retention_policy_days(signals: Signals, params: dict[str, Any]) -> dict[str, Any]:
    minimum = _int_param(params, "min_days", 365)
    days = _setting_int(signals.org_settings, "retention_policy_days", "retention_days", "security_events_days")
    source = "organization settings" if days is not None else "not configured"
    if days is None:
        policy = _policy(signals, RETENTION_POLICY_KINDS)
        if policy is not None:
            days = _policy_days(policy)
            source = f"policy {policy.name}"
    passed = days is not None and days >= minimum
    return _result(
        True,
        passed,
        {"retention_days": days, "min_days": minimum, "source": source},
        f"Retention is {days if days is not None else 'not configured'} days; minimum required is {minimum}.",
    )


def _incident_process_exists(signals: Signals, params: dict[str, Any]) -> dict[str, Any]:
    configured = _setting_bool(signals.org_settings, "incident_process", "incident_response_plan")
    policy = _policy(signals, INCIDENT_POLICY_KINDS)
    passed = bool(configured) or _policy_bool(policy) or signals.published_playbooks > 0
    source = (
        "organization settings"
        if configured is not None
        else (f"policy {policy.name}" if policy else ("published playbook" if signals.published_playbooks else "none"))
    )
    return _result(
        True,
        passed,
        {"published_playbooks": signals.published_playbooks, "source": source},
        f"Incident process {'available' if passed else 'missing'} ({source}).",
    )


def _vulnerability_sla(signals: Signals, params: dict[str, Any]) -> dict[str, Any]:
    maximum = _float_param(params, "max_overdue_ratio", 0.0)
    ratio = (signals.vulns_overdue / signals.vulns_open) if signals.vulns_open else 0.0
    passed = ratio <= maximum
    return _result(
        True,
        passed,
        {
            "open": signals.vulns_open,
            "overdue": signals.vulns_overdue,
            "kev": signals.vulns_kev,
            "overdue_ratio": round(ratio, 4),
            "max_overdue_ratio": maximum,
        },
        f"{signals.vulns_overdue} of {signals.vulns_open} open vulnerabilities are past due "
        f"(ratio {ratio:.2f}, limit {maximum:.2f}).",
    )


def _asset_inventory_coverage(signals: Signals, params: dict[str, Any]) -> dict[str, Any]:
    minimum = _float_param(params, "min_ratio", 0.8)
    if signals.assets_total == 0:
        return _result(True, False, {"assets": 0}, "No assets are inventoried, so coverage cannot be evidenced.")
    ratio = signals.assets_covered / signals.assets_total
    passed = ratio >= minimum
    return _result(
        True,
        passed,
        {
            "assets": signals.assets_total,
            "covered": signals.assets_covered,
            "ratio": round(ratio, 4),
            "min_ratio": minimum,
        },
        f"{signals.assets_covered}/{signals.assets_total} assets carry owner, zone or classification metadata "
        f"(ratio {ratio:.2f}).",
    )


def _ot_passive_only(signals: Signals, params: dict[str, Any]) -> dict[str, Any]:
    if signals.ot_total == 0:
        return _result(
            False, True, {"ot_devices": 0}, "No OT devices inventoried; passive-only requirement not applicable."
        )
    passed = signals.ot_passive == signals.ot_total
    return _result(
        True,
        passed,
        {"ot_devices": signals.ot_total, "passive": signals.ot_passive},
        f"{signals.ot_passive}/{signals.ot_total} OT devices are flagged passive-only.",
    )


def _supplier_register(signals: Signals, params: dict[str, Any]) -> dict[str, Any]:
    configured = _setting_bool(signals.org_settings, "supplier_register", "supplier_register_enabled")
    policy = _policy(signals, SUPPLIER_POLICY_KINDS)
    passed = bool(configured) if configured is not None else _policy_bool(policy)
    source = "organization settings" if configured is not None else (policy.name if policy else "no source")
    return _result(
        True,
        passed,
        {"maintained": passed, "source": source},
        f"Supplier register {'maintained' if passed else 'not evidenced'} ({source}).",
    )


def _encryption_at_rest(signals: Signals, params: dict[str, Any]) -> dict[str, Any]:
    configured = _setting_bool(signals.org_settings, "encryption_at_rest", "disk_encryption")
    policy = _policy(signals, ENCRYPTION_POLICY_KINDS)
    passed = bool(configured) if configured is not None else _policy_bool(policy)
    source = "organization settings" if configured is not None else (policy.name if policy else "no source")
    return _result(
        True,
        passed,
        {"enabled": passed, "source": source},
        f"Encryption at rest {'declared' if passed else 'not evidenced'} ({source}).",
    )


def _rbac_least_privilege(signals: Signals, params: dict[str, Any]) -> dict[str, Any]:
    maximum = _int_param(params, "max_admins", 2)
    passed = signals.admin_count <= maximum and not signals.unknown_roles
    return _result(
        True,
        passed,
        {
            "admin_count": signals.admin_count,
            "max_admins": maximum,
            "unknown_roles": signals.unknown_roles,
        },
        f"{signals.admin_count} active organization administrators (limit {maximum}); "
        f"unknown roles: {signals.unknown_roles or 'none'}.",
    )


def _session_timeout(signals: Signals, params: dict[str, Any]) -> dict[str, Any]:
    maximum = _int_param(params, "max_minutes", 30)
    minutes = _setting_int(signals.org_settings, "session_timeout_minutes", "idle_timeout_minutes")
    source = "organization settings"
    if minutes is None:
        policy = _policy(signals, {"session", "session_management", "access_control"})
        if policy is not None:
            definition = policy.definition or {}
            for key in ("session_timeout_minutes", "idle_timeout_minutes", "timeout_minutes"):
                if key in definition:
                    try:
                        minutes = int(definition[key])
                        source = f"policy {policy.name}"
                        break
                    except (TypeError, ValueError):
                        continue
    if minutes is None:
        minutes = platform_settings.session_ttl_minutes
        source = "platform default"
    passed = minutes <= maximum
    return _result(
        True,
        passed,
        {"session_timeout_minutes": minutes, "max_minutes": maximum, "source": source},
        f"Idle session timeout is {minutes} minutes (maximum {maximum}).",
    )


def _logging_enabled(signals: Signals, params: dict[str, Any]) -> dict[str, Any]:
    minimum = _int_param(params, "min_sources", 1)
    configured = _setting_bool(signals.org_settings, "logging_enabled", "central_logging")
    policy = _policy(signals, LOGGING_POLICY_KINDS)
    passed = bool(configured) or signals.ingest_sources_enabled >= minimum or _policy_bool(policy)
    return _result(
        True,
        passed,
        {
            "enabled_ingest_sources": signals.ingest_sources_enabled,
            "min_sources": minimum,
            "settings_flag": configured,
            "policy": policy.name if policy else None,
        },
        f"{signals.ingest_sources_enabled} enabled ingest sources (minimum {minimum}).",
    )


def _patch_management(signals: Signals, params: dict[str, Any]) -> dict[str, Any]:
    max_days = _int_param(params, "max_days_since_scan", 30)
    minimum = _float_param(params, "min_ratio", 0.8)
    configured = _setting_bool(signals.org_settings, "patch_management", "patching_enabled")
    policy = _policy(signals, PATCH_POLICY_KINDS)
    if signals.assets_total == 0:
        passed = bool(configured) or _policy_bool(policy)
        return _result(
            True,
            passed,
            {"assets": 0, "source": "settings/policy" if passed else "none"},
            "No assets inventoried; patch evidence falls back to declared policy.",
        )
    cutoff = utcnow() - timedelta(days=max_days)
    recent = signals.db.execute(
        select(func.count())
        .select_from(Asset)
        .where(Asset.org_id == signals.org_id, Asset.last_scanned_at.isnot(None), Asset.last_scanned_at >= cutoff)
    ).scalar_one()
    ratio = int(recent) / signals.assets_total
    passed = ratio >= minimum
    return _result(
        True,
        passed,
        {
            "assets": signals.assets_total,
            "recently_scanned": int(recent),
            "ratio": round(ratio, 4),
            "max_days_since_scan": max_days,
            "min_ratio": minimum,
        },
        f"{int(recent)}/{signals.assets_total} assets scanned or patched in the last {max_days} days "
        f"(ratio {ratio:.2f}).",
    )


def _network_segmentation(signals: Signals, params: dict[str, Any]) -> dict[str, Any]:
    minimum = _float_param(params, "min_ratio", 0.8)
    if signals.conduits_missing_compensating_control:
        return _result(
            True,
            False,
            {
                "conduits": signals.conduits_total,
                "missing_compensating_control": signals.conduits_missing_compensating_control,
            },
            (
                f"{signals.conduits_missing_compensating_control} conduit(s) require SL >= 3 and do not document "
                "a compensating control."
            ),
        )
    if signals.zones_total == 0:
        return _result(True, False, {"zones": 0}, "No security zones are defined for the organization.")
    if signals.ot_total == 0:
        return _result(
            True,
            True,
            {"zones": signals.zones_total, "ot_devices": 0},
            f"{signals.zones_total} zones defined; no OT devices require conduit assignment.",
        )
    ratio = signals.ot_zoned / signals.ot_total
    passed = ratio >= minimum
    return _result(
        True,
        passed,
        {
            "zones": signals.zones_total,
            "ot_devices": signals.ot_total,
            "zoned": signals.ot_zoned,
            "ratio": round(ratio, 4),
            "min_ratio": minimum,
        },
        f"{signals.ot_zoned}/{signals.ot_total} OT devices are assigned to a zone (ratio {ratio:.2f}).",
    )


def _access_review(signals: Signals, params: dict[str, Any]) -> dict[str, Any]:
    max_days = _int_param(params, "max_days", 90)
    reviewed_at = signals.last_access_review_at
    if reviewed_at is None:
        return _result(
            True, False, {"last_review_at": None, "max_days": max_days}, "No access review has been recorded."
        )
    age_days = (utcnow() - reviewed_at).days
    passed = age_days <= max_days
    return _result(
        True,
        passed,
        {"last_review_at": reviewed_at.isoformat(), "age_days": age_days, "max_days": max_days},
        f"Last access review was {age_days} days ago (maximum {max_days}).",
    )


def _data_minimisation(signals: Signals, params: dict[str, Any]) -> dict[str, Any]:
    configured = _setting_bool(signals.org_settings, "data_minimisation", "data_minimization")
    policy = _policy(signals, DATA_PROTECTION_POLICY_KINDS)
    passed = bool(configured) if configured is not None else _policy_bool(policy)
    source = "organization settings" if configured is not None else (policy.name if policy else "no source")
    return _result(
        True,
        passed,
        {"enabled": passed, "source": source},
        f"Data-minimisation measures {'documented' if passed else 'not evidenced'} ({source}).",
    )


EVALUATORS = {
    "mfa_enforced": _mfa_enforced,
    "audit_chain_valid": _audit_chain_valid,
    "connector_tls": _connector_tls,
    "backup_configured": _backup_configured,
    "retention_policy_days": _retention_policy_days,
    "incident_process_exists": _incident_process_exists,
    "vulnerability_sla": _vulnerability_sla,
    "asset_inventory_coverage": _asset_inventory_coverage,
    "ot_passive_only": _ot_passive_only,
    "supplier_register": _supplier_register,
    "encryption_at_rest": _encryption_at_rest,
    "rbac_least_privilege": _rbac_least_privilege,
    "session_timeout": _session_timeout,
    "logging_enabled": _logging_enabled,
    "patch_management": _patch_management,
    "network_segmentation": _network_segmentation,
    "access_review": _access_review,
    "data_minimisation": _data_minimisation,
}


def evaluate_check(check: dict[str, Any], signals: Signals) -> dict[str, Any]:
    """Evaluate a single technical check definition and return a serializable result."""
    check_type = str(check.get("type", ""))
    evaluator = EVALUATORS.get(check_type)
    key = str(check.get("key", check_type or "check"))
    title = str(check.get("title", key))
    if evaluator is None:
        return {
            "key": key,
            "type": check_type,
            "title": title,
            "applicable": False,
            "passed": False,
            "observed": {},
            "detail": f"Unsupported technical check type: {check_type}",
        }
    params = check.get("params") or {}
    if not isinstance(params, dict):
        params = {}
    outcome = evaluator(signals, params)
    return {
        "key": key,
        "type": check_type,
        "title": title,
        "applicable": bool(outcome["applicable"]),
        "passed": bool(outcome["passed"]),
        "observed": outcome["observed"],
        "detail": outcome["detail"],
    }


def derive_control_status(results: list[dict[str, Any]]) -> str:
    """Map check outcomes to a control status; manual evidence is never implied."""
    if not results:
        return "not_assessed"
    applicable = [result for result in results if result["applicable"]]
    if not applicable:
        return "not_applicable"
    passed = sum(1 for result in applicable if result["passed"])
    if passed == len(applicable):
        return "compliant"
    if passed == 0:
        return "non_compliant"
    return "partial"


def summarise_checks(results: list[dict[str, Any]]) -> str:
    """Human-readable technical evidence summary persisted in the control notes."""
    if not results:
        return "No automated technical checks are defined; manual evidence and assessor review required."
    applicable = [result for result in results if result["applicable"]]
    passed = [result for result in applicable if result["passed"]]
    lines = [
        f"Automated evaluation {utcnow().date().isoformat()}: {len(passed)}/{len(applicable)} applicable checks passed."
    ]
    for result in applicable:
        if not result["passed"]:
            lines.append(f"FAIL {result['key']}: {result['detail']}")
    skipped = [result for result in results if not result["applicable"]]
    for result in skipped:
        lines.append(f"N/A {result['key']}: {result['detail']}")
    return "\n".join(lines)[:4000]


def control_weight(control: Any) -> int:
    """Weight persisted in the control mapping, defaulting to 2."""
    mapping = getattr(control, "mapping", None) or {}
    try:
        weight = int(mapping.get("weight", 2))
    except (TypeError, ValueError):
        return 2
    return max(1, min(5, weight))


__all__ = [
    "EVALUATORS",
    "Signals",
    "build_signals",
    "control_weight",
    "derive_control_status",
    "evaluate_check",
    "summarise_checks",
]
