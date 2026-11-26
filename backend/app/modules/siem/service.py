"""SIEM business logic: rule lifecycle, Sigma conversion, alerts and promotion."""

from __future__ import annotations

import json
import re
from datetime import UTC, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.core.deps import RequestContext
from app.core.errors import Conflict, Forbidden, NotFound, ValidationFailure
from app.models.core import Membership
from app.models.events import Alert, DetectionRule, SecurityEvent
from app.models.incidents import Incident, IncidentTimeline
from app.modules.siem.builtin_rules import builtin_rules
from app.modules.siem.schemas import RuleCreate, RulePatch, SigmaRule
from app.services.detection import (
    MAX_WINDOW_EVENTS,
    DefinitionError,
    evaluate_rule,
    explain_rule,
    group_values,
    validate_definition,
)

MITRE_NAMES: dict[str, str] = {
    "T1041": "Exfiltration Over C2 Channel",
    "T1046": "Network Service Discovery",
    "T1068": "Exploitation for Privilege Escalation",
    "T1071": "Application Layer Protocol",
    "T1105": "Ingress Tool Transfer",
    "T1110": "Brute Force",
    "T1204": "User Execution",
    "T1548": "Abuse Elevation Control Mechanism",
}

_SIGMA_FIELD_MAP = {
    "commandline": "message",
    "processcommandline": "message",
    "image": "process_name",
    "processname": "process_name",
    "newprocessname": "process_name",
    "parentimage": "unmapped.ParentImage",
    "parentprocessname": "unmapped.ParentProcessName",
    "user": "user_name",
    "username": "user_name",
    "targetusername": "user_name",
    "targetuser": "user_name",
    "suser": "user_name",
    "ipaddress": "src_ip",
    "sourceip": "src_ip",
    "srcip": "src_ip",
    "destinationip": "dst_ip",
    "destip": "dst_ip",
    "destinationport": "dst_port",
    "destport": "dst_port",
    "sourceport": "src_port",
    "srcport": "src_port",
    "computer": "host_name",
    "hostname": "host_name",
    "queryname": "domain",
    "url": "url",
    "targetfilename": "unmapped.TargetFilename",
    "filename": "unmapped.FileName",
    "hashes": "file_hash_sha256",
    "eventid": "unmapped.EventID",
    "providername": "unmapped.ProviderName",
    "channel": "unmapped.Channel",
    "protocol": "protocol",
}

_SIGMA_MODIFIERS = {"contains", "startswith", "endswith", "re", "gt", "gte", "lt", "lte", "ne"}
_SIGMA_LEVELS = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def serialize_rule(rule: DetectionRule) -> dict[str, Any]:
    return {
        "id": rule.id,
        "org_id": rule.org_id,
        "name": rule.name,
        "description": rule.description,
        "severity": rule.severity,
        "status": rule.status,
        "enabled": rule.enabled,
        "version": rule.version,
        "logsource": rule.logsource or {},
        "definition": rule.definition or {},
        "mitre": rule.mitre or [],
        "tags": rule.tags or [],
        "false_positive_count": int(rule.false_positive_count or 0),
        "true_positive_count": int(rule.true_positive_count or 0),
        "created_by": rule.created_by,
        "created_at": rule.created_at,
        "updated_at": rule.updated_at,
        "scope": "global" if rule.org_id is None else "organization",
    }


def serialize_alert(alert: Alert, *, rule_name: str | None = None, detail: bool = False) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": alert.id,
        "org_id": alert.org_id,
        "rule_id": alert.rule_id,
        "rule_name": rule_name,
        "title": alert.title,
        "description": alert.description,
        "severity": alert.severity,
        "status": alert.status,
        "dedupe_key": alert.dedupe_key,
        "event_ids": list(alert.event_ids or []),
        "first_seen": alert.first_seen,
        "last_seen": alert.last_seen,
        "count": int(alert.count or 0),
        "assignee_id": alert.assignee_id,
        "incident_id": alert.incident_id,
        "mitre": list(alert.mitre or []),
        "risk_score": float(alert.risk_score or 0.0),
        "is_demo": alert.is_demo,
        "created_at": alert.created_at,
        "updated_at": alert.updated_at,
    }
    if detail:
        payload["evidence"] = alert.evidence or {}
    return payload


def rule_or_404(db: Session, org_id: UUID, rule_id: UUID) -> DetectionRule:
    rule = db.get(DetectionRule, rule_id)
    if rule is None or (rule.org_id is not None and rule.org_id != org_id):
        raise NotFound("Detection rule")
    return rule


def _ensure_global_write(rule: DetectionRule, is_platform_admin: bool) -> None:
    if rule.org_id is None and not is_platform_admin:
        raise Forbidden("Only platform administrators can modify global detection rules")


def create_rule(
    db: Session,
    *,
    org_id: UUID,
    actor_id: str | None,
    payload: RuleCreate,
    is_platform_admin: bool,
) -> DetectionRule:
    if payload.is_global and not is_platform_admin:
        raise Forbidden("Only platform administrators can create global detection rules")
    try:
        validate_definition(payload.definition)
    except DefinitionError as exc:
        raise ValidationFailure(exc.details) from exc
    target_org = None if payload.is_global else org_id
    org_filter = DetectionRule.org_id.is_(None) if target_org is None else DetectionRule.org_id == target_org
    duplicate = db.execute(
        select(DetectionRule).where(org_filter, DetectionRule.name == payload.name)
    ).scalar_one_or_none()
    if duplicate is not None:
        raise Conflict("A detection rule with this name already exists in this scope")
    rule = DetectionRule(
        org_id=target_org,
        name=payload.name,
        description=payload.description,
        severity=payload.severity,
        status=payload.status,
        enabled=payload.enabled,
        version=1,
        logsource=payload.logsource,
        definition=payload.definition,
        mitre=payload.mitre,
        tags=payload.tags,
        created_by=actor_id,
    )
    db.add(rule)
    db.flush()
    return rule


def update_rule(
    db: Session,
    *,
    rule: DetectionRule,
    payload: RulePatch,
    is_platform_admin: bool,
) -> DetectionRule:
    _ensure_global_write(rule, is_platform_admin)
    changes = payload.model_dump(exclude_unset=True)
    if "definition" in changes and changes["definition"] is not None:
        try:
            validate_definition(changes["definition"])
        except DefinitionError as exc:
            raise ValidationFailure(exc.details) from exc
    if "name" in changes and changes["name"] not in (None, rule.name):
        org_filter = DetectionRule.org_id.is_(None) if rule.org_id is None else DetectionRule.org_id == rule.org_id
        if db.execute(
            select(DetectionRule).where(org_filter, DetectionRule.name == changes["name"], DetectionRule.id != rule.id)
        ).scalar_one_or_none():
            raise Conflict("A detection rule with this name already exists in this scope")
    for field, value in changes.items():
        if value is not None:
            setattr(rule, field, value)
    rule.version = int(rule.version or 1) + 1
    db.add(rule)
    db.flush()
    return rule


def set_rule_enabled(db: Session, *, rule: DetectionRule, enabled: bool, is_platform_admin: bool) -> DetectionRule:
    _ensure_global_write(rule, is_platform_admin)
    rule.enabled = enabled
    db.add(rule)
    db.flush()
    return rule


def delete_rule(db: Session, *, rule: DetectionRule, is_platform_admin: bool) -> None:
    _ensure_global_write(rule, is_platform_admin)
    db.delete(rule)
    db.flush()


# ---------------------------------------------------------------------------
# Rule testing
# ---------------------------------------------------------------------------


def _sample_id(sample: Any) -> int | None:
    if isinstance(sample, dict):
        value = sample.get("id")
        return int(value) if isinstance(value, int) else None
    value = getattr(sample, "id", None)
    return int(value) if isinstance(value, int) else None


def test_rule(
    db: Session,
    *,
    org_id: UUID,
    rule: DetectionRule,
    samples: list[Any] | None,
    event_ids: list[int] | None,
    apply_threshold: bool,
) -> dict[str, Any]:
    try:
        validate_definition(rule.definition)
    except DefinitionError as exc:
        raise ValidationFailure(exc.details) from exc

    if samples is not None:
        sample_events = samples
    else:
        ids = event_ids or []
        rows = list(
            db.execute(select(SecurityEvent).where(SecurityEvent.org_id == org_id, SecurityEvent.id.in_(ids))).scalars()
        )
        by_id = {row.id: row for row in rows}
        missing = [identifier for identifier in ids if identifier not in by_id]
        if missing:
            raise NotFound("Security event")
        sample_events = [by_id[identifier] for identifier in ids]

    threshold = rule.definition.get("threshold") if apply_threshold else None
    threshold_state: dict[str, Any] | None = None
    if isinstance(threshold, dict):
        group_by = threshold.get("group_by")
        required = int(threshold.get("count", 1))
        window_seconds = int(threshold.get("window_seconds", 300))
        if samples is not None:
            pool: list[Any] = list(sample_events)
        else:
            since = utcnow() - timedelta(seconds=window_seconds)
            pool = list(
                db.execute(
                    select(SecurityEvent)
                    .where(SecurityEvent.org_id == org_id, SecurityEvent.occurred_at >= since)
                    .order_by(SecurityEvent.occurred_at.desc())
                    .limit(MAX_WINDOW_EVENTS)
                ).scalars()
            )
        index: dict[str, list[Any]] = {}
        for candidate in pool:
            if not evaluate_rule(rule.definition, candidate).matched:
                continue
            group = group_values(candidate, group_by)
            index.setdefault(json.dumps(group, sort_keys=True, separators=(",", ":")), []).append(candidate)
        groups: list[dict[str, Any]] = []
        seen: set[str] = set()
        for sample in sample_events:
            if not evaluate_rule(rule.definition, sample).matched:
                continue
            group = group_values(sample, group_by)
            key = json.dumps(group, sort_keys=True, separators=(",", ":"))
            if key in seen:
                continue
            seen.add(key)
            matching = index.get(key, [])
            observed = len(matching)
            if not any(_sample_id(item) == _sample_id(sample) for item in matching):
                observed += 1
            groups.append(
                {
                    "group": group,
                    "observed": observed,
                    "required": required,
                    "would_trigger": observed >= required,
                }
            )
        threshold_state = {
            "required": required,
            "window_seconds": window_seconds,
            "groups": groups,
            "would_trigger": any(item["would_trigger"] for item in groups),
        }

    result = explain_rule(rule.definition, sample_events, threshold_state=threshold_state)
    if threshold_state is not None:
        result["would_alert"] = bool(result["matched_count"] and threshold_state["would_trigger"])
    return {
        "rule_id": str(rule.id),
        "rule_name": rule.name,
        "version": rule.version,
        **result,
    }


# ---------------------------------------------------------------------------
# Sigma subset import
# ---------------------------------------------------------------------------


def _sigma_field(name: str) -> str:
    return _SIGMA_FIELD_MAP.get(name.strip().lower(), f"unmapped.{name.strip()}")


def _sigma_wildcard_regex(value: str) -> str:
    escaped = re.escape(value).replace(r"\*", ".*").replace(r"\?", ".")
    return f"^{escaped}$"


def _sigma_scalar(value: Any) -> Any:
    if isinstance(value, str) and ("*" in value or "?" in value):
        return {"regex": _sigma_wildcard_regex(value)}
    return value


def _sigma_value(field_name: str, value: Any, modifier: str | None) -> Any:
    if isinstance(value, dict):
        raise ValueError("Nested Sigma selection values are not supported")
    if modifier == "contains":
        if isinstance(value, list):
            return {"regex": "(?:" + "|".join(re.escape(str(item).replace("*", "")) for item in value) + ")"}
        return {"contains": str(value).replace("*", "")}
    if modifier in {"startswith", "endswith"}:
        if isinstance(value, list):
            raise ValueError(f"Modifier {modifier} does not support list values")
        text = str(value)
        if modifier == "startswith":
            return {"regex": "^" + re.escape(text.replace("*", ""))}
        return {"regex": re.escape(text.replace("*", "")) + "$"}
    if modifier == "re":
        if not isinstance(value, str):
            raise ValueError("Modifier re expects a string")
        return {"regex": value}
    if modifier in {"gt", "gte", "lt", "lte"}:
        if isinstance(value, bool) or not isinstance(value, int | float):
            raise ValueError(f"Modifier {modifier} expects a number")
        return {modifier: value}
    if modifier == "ne":
        return {"ne": value}
    if modifier is not None:
        raise ValueError(f"Unsupported Sigma modifier: {modifier}")

    if field_name == "file_hash_sha256" and isinstance(value, str):
        hashes = [part.strip() for part in value.split(",")]
        for entry in hashes:
            _, _, digest = entry.partition("=")
            candidate = (digest or entry).strip()
            if re.fullmatch(r"[a-fA-F0-9]{64}", candidate):
                return candidate.lower()
        return {"regex": re.escape(value)}
    if isinstance(value, list):
        converted = [_sigma_scalar(item) for item in value]
        if any(isinstance(item, dict) for item in converted):
            patterns = []
            for item in value:
                if isinstance(item, str) and ("*" in item or "?" in item):
                    patterns.append(_sigma_wildcard_regex(item)[1:-1])
                else:
                    patterns.append(re.escape(str(item)))
            return {"regex": "^(?:" + "|".join(patterns) + ")$"}
        return converted
    return _sigma_scalar(value)


def _sigma_timeframe(value: Any) -> int | None:
    if isinstance(value, int | float) and not isinstance(value, bool):
        seconds = int(value)
        return seconds if 10 <= seconds <= 86400 else None
    if isinstance(value, str):
        match = re.fullmatch(r"(\d+)\s*([smhd])", value.strip().lower())
        if match:
            multiplier = {"s": 1, "m": 60, "h": 3600, "d": 86400}[match.group(2)]
            seconds = int(match.group(1)) * multiplier
            return seconds if 10 <= seconds <= 86400 else None
    return None


def convert_sigma(sigma: SigmaRule) -> dict[str, Any]:
    detection = dict(sigma.detection)
    selection = detection.get("selection")
    if not isinstance(selection, dict) or not selection:
        raise ValueError("Sigma detection.selection must be a non-empty object")
    unsupported = set(detection) - {"selection", "condition", "timeframe"}
    if unsupported:
        raise ValueError(f"Unsupported Sigma detection keys: {', '.join(sorted(unsupported))}")

    condition = str(detection.get("condition", "and")).strip().lower()
    if condition in {"selection", "all of selection", "any of selection"}:
        condition = "and"
    if condition not in {"and", "or"}:
        raise ValueError(f"Unsupported Sigma condition: {condition}")

    converted: dict[str, Any] = {}
    for raw_field, raw_value in selection.items():
        parts = str(raw_field).split("|")
        field_name = parts[0]
        modifiers = parts[1:]
        if len(modifiers) > 1:
            raise ValueError(f"Multiple Sigma modifiers are not supported: {raw_field}")
        modifier = modifiers[0] if modifiers else None
        if modifier is not None and modifier not in _SIGMA_MODIFIERS:
            raise ValueError(f"Unsupported Sigma modifier: {modifier}")
        target_field = _sigma_field(field_name)
        converted[target_field] = _sigma_value(target_field, raw_value, modifier)

    definition: dict[str, Any] = {"selection": converted, "condition": condition}
    timeframe = _sigma_timeframe(detection.get("timeframe"))
    if timeframe:
        definition["timeframe_seconds"] = timeframe
    try:
        validate_definition(definition)
    except DefinitionError as exc:
        raise ValueError("; ".join(f"{item['path']}: {item['message']}" for item in exc.details)) from exc

    mitre: list[str] = []
    tags: list[str] = []
    for tag in sigma.tags:
        candidate = tag.strip()
        attack = re.match(r"(?i)^attack\.(t\d{4}(?:\.\d{3})?)$", candidate)
        if attack:
            mitre.append(attack.group(1).upper())
        elif candidate:
            tags.append(candidate[:80])
    return {
        "name": sigma.title,
        "description": sigma.description,
        "severity": _SIGMA_LEVELS.get((sigma.level or "medium").lower(), "medium"),
        "logsource": sigma.logsource,
        "definition": definition,
        "mitre": sorted(set(mitre)),
        "tags": tags[:20],
    }


def import_sigma(
    db: Session,
    *,
    org_id: UUID,
    actor_id: str | None,
    rules: list[SigmaRule],
) -> tuple[list[DetectionRule], list[dict[str, str]]]:
    imported: list[DetectionRule] = []
    skipped: list[dict[str, str]] = []
    existing_names = {
        name for (name,) in db.execute(select(DetectionRule.name).where(DetectionRule.org_id == org_id)).all()
    }
    for sigma in rules:
        try:
            spec = convert_sigma(sigma)
        except ValueError as exc:
            skipped.append({"title": sigma.title, "reason": str(exc)[:300]})
            continue
        if spec["name"] in existing_names:
            skipped.append({"title": sigma.title, "reason": "duplicate rule name"})
            continue
        rule = DetectionRule(
            org_id=org_id,
            name=spec["name"],
            description=spec["description"],
            severity=spec["severity"],
            status="production",
            enabled=True,
            version=1,
            logsource=spec["logsource"],
            definition=spec["definition"],
            mitre=spec["mitre"],
            tags=spec["tags"],
            created_by=actor_id,
        )
        db.add(rule)
        db.flush()
        existing_names.add(rule.name)
        imported.append(rule)
    return imported, skipped


def rule_templates() -> list[dict[str, Any]]:
    return builtin_rules()


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


def alert_or_404(db: Session, org_id: UUID, alert_id: UUID) -> Alert:
    alert = db.get(Alert, alert_id)
    if alert is None or alert.org_id != org_id:
        raise NotFound("Alert")
    return alert


def _validate_assignee(db: Session, org_id: UUID, assignee_id: UUID) -> None:
    membership = db.execute(
        select(Membership).where(
            Membership.org_id == org_id,
            Membership.user_id == assignee_id,
            Membership.status == "active",
        )
    ).scalar_one_or_none()
    if membership is None:
        raise ValidationFailure([{"field": "assignee_id", "message": "Assignee is not an active member"}])
    if membership.role not in {
        "org_admin",
        "soc_manager",
        "soc_analyst",
        "incident_responder",
        "threat_analyst",
        "compliance_officer",
        "auditor",
        "viewer",
    }:
        raise ValidationFailure([{"field": "assignee_id", "message": "Assignee cannot own alerts"}])


def apply_triage(
    alert: Alert,
    *,
    status: str | None,
    assignee_id: UUID | None,
    assignee_set: bool,
    note: str | None,
    actor: str | None,
) -> bool:
    changed = False
    if status is not None and status != alert.status:
        alert.status = status
        changed = True
    if assignee_set and assignee_id != alert.assignee_id:
        alert.assignee_id = assignee_id
        changed = True
    if note:
        evidence = dict(alert.evidence or {})
        notes = list(evidence.get("notes") or [])
        notes.append({"at": utcnow().isoformat(), "actor": actor, "note": note[:4000]})
        evidence["notes"] = notes[-50:]
        alert.evidence = evidence
        changed = True
    return changed


def triage_alert(
    db: Session,
    *,
    alert: Alert,
    status: str | None,
    assignee_id: UUID | None,
    assignee_set: bool,
    note: str | None,
    actor: str | None,
) -> bool:
    if assignee_set and assignee_id is not None:
        _validate_assignee(db, alert.org_id, assignee_id)
    changed = apply_triage(
        alert,
        status=status,
        assignee_id=assignee_id,
        assignee_set=assignee_set,
        note=note,
        actor=actor,
    )
    if changed:
        db.add(alert)
        db.flush()
    return changed


def bulk_update_alerts(
    db: Session,
    *,
    org_id: UUID,
    ids: list[UUID],
    status: str | None,
    assignee_id: UUID | None,
    assignee_set: bool,
    note: str | None,
    actor: str | None,
) -> tuple[int, int, list[UUID]]:
    if assignee_set and assignee_id is not None:
        _validate_assignee(db, org_id, assignee_id)
    alerts = list(db.execute(select(Alert).where(Alert.org_id == org_id, Alert.id.in_(ids))).scalars())
    by_id = {alert.id: alert for alert in alerts}
    updated_ids: list[UUID] = []
    skipped = 0
    for identifier in ids:
        alert = by_id.get(identifier)
        if alert is None:
            skipped += 1
            continue
        if not apply_triage(
            alert,
            status=status,
            assignee_id=assignee_id,
            assignee_set=assignee_set,
            note=note,
            actor=actor,
        ):
            skipped += 1
            continue
        db.add(alert)
        updated_ids.append(identifier)
    db.flush()
    return len(updated_ids), skipped, updated_ids


def alert_stats(db: Session, org_id: UUID, *, hours: int = 24) -> dict[str, Any]:
    since = utcnow() - timedelta(hours=hours)
    base = [Alert.org_id == org_id]
    total = db.execute(select(func.count()).select_from(Alert).where(*base)).scalar_one()
    open_count = db.execute(
        select(func.count()).select_from(Alert).where(*base, Alert.status.in_(("new", "triaged", "investigating")))
    ).scalar_one()
    by_status = {
        str(row[0]): int(row[1])
        for row in db.execute(select(Alert.status, func.count()).where(*base).group_by(Alert.status)).all()
    }
    by_severity = {
        str(row[0]): int(row[1])
        for row in db.execute(select(Alert.severity, func.count()).where(*base).group_by(Alert.severity)).all()
    }
    top_rules = db.execute(
        select(DetectionRule.id, DetectionRule.name, func.count(Alert.id).label("count"))
        .select_from(Alert)
        .outerjoin(DetectionRule, DetectionRule.id == Alert.rule_id)
        .where(*base)
        .group_by(DetectionRule.id, DetectionRule.name)
        .order_by(func.count(Alert.id).desc())
        .limit(10)
    ).all()
    bucket = func.date_trunc("hour", Alert.created_at)
    bucket_rows = db.execute(
        select(bucket, func.count()).where(*base, Alert.created_at >= since).group_by(bucket).order_by(bucket)
    ).all()
    by_bucket = {row[0].astimezone(UTC).isoformat(): int(row[1]) for row in bucket_rows}
    timeline: list[dict[str, Any]] = []
    cursor = utcnow().replace(minute=0, second=0, microsecond=0) - timedelta(hours=hours - 1)
    for _ in range(hours):
        timeline.append({"timestamp": cursor.isoformat(), "count": by_bucket.get(cursor.isoformat(), 0)})
        cursor += timedelta(hours=1)
    return {
        "generated_at": utcnow().isoformat(),
        "window_hours": hours,
        "total": int(total),
        "open": int(open_count),
        "by_status": by_status,
        "by_severity": by_severity,
        "top_rules": [
            {"rule_id": str(row[0]) if row[0] else None, "name": row[1] or "removed rule", "count": int(row[2])}
            for row in top_rules
        ],
        "timeline": timeline,
    }


# ---------------------------------------------------------------------------
# Promotion to incident
# ---------------------------------------------------------------------------


def _priority_for(severity: str) -> int:
    return {"critical": 1, "high": 2, "medium": 3, "low": 4, "informational": 5}.get(severity, 3)


def promote_alert(ctx: RequestContext, alert: Alert, title: str | None, description: str | None) -> Incident:
    db = ctx.db
    if alert.incident_id is not None:
        raise Conflict("Alert is already linked to an incident")
    now = utcnow()
    year = now.year
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": f"incident-ref:{year}"})
    refs = list(db.execute(select(Incident.ref).where(Incident.ref.like(f"HS-{year}-%"))).scalars())
    numbers = [int(ref.rsplit("-", 1)[-1]) for ref in refs if ref.rsplit("-", 1)[-1].isdigit()]
    ref = f"HS-{year}-{max(numbers, default=0) + 1:04d}"

    incident_title = (title or alert.title)[:300]
    incident = Incident(
        org_id=ctx.org.id,
        ref=ref,
        title=incident_title,
        description=(description or alert.description or f"Promoted from alert {alert.id}")[:4000],
        severity=alert.severity
        if alert.severity in {"informational", "low", "medium", "high", "critical"}
        else "medium",
        status="new",
        priority=_priority_for(alert.severity),
        detected_at=alert.first_seen,
        mitre=list(alert.mitre or []),
        affected_asset_ids=[],
        created_by=ctx.actor_id,
    )
    db.add(incident)
    db.flush()
    db.add(
        IncidentTimeline(
            incident_id=incident.id,
            org_id=ctx.org.id,
            kind="created_from_alert",
            actor=ctx.actor_email or ctx.actor_id,
            summary=f"Incident created from alert: {alert.title}"[:500],
            detail={
                "alert_id": str(alert.id),
                "rule_id": str(alert.rule_id) if alert.rule_id else None,
                "dedupe_key": alert.dedupe_key,
                "event_ids": list(alert.event_ids or [])[:50],
                "risk_score": float(alert.risk_score or 0.0),
            },
        )
    )
    alert.incident_id = incident.id
    if alert.status in {"new", "triaged"}:
        alert.status = "investigating"
    db.add(alert)
    db.flush()
    return incident


# ---------------------------------------------------------------------------
# MITRE coverage
# ---------------------------------------------------------------------------


def mitre_coverage(db: Session, org_id: UUID) -> dict[str, Any]:
    event_rows = db.execute(
        text(
            """
            SELECT t.technique AS technique, COUNT(DISTINCT e.id) AS count
            FROM security_events e
            CROSS JOIN LATERAL jsonb_array_elements_text(e.mitre_techniques) AS t(technique)
            WHERE e.org_id = :org_id
            GROUP BY t.technique
            """
        ),
        {"org_id": org_id},
    ).all()
    alert_rows = db.execute(
        text(
            """
            SELECT t.technique AS technique, COUNT(DISTINCT a.id) AS count
            FROM alerts a
            CROSS JOIN LATERAL jsonb_array_elements_text(a.mitre) AS t(technique)
            WHERE a.org_id = :org_id
            GROUP BY t.technique
            """
        ),
        {"org_id": org_id},
    ).all()
    merged: dict[str, dict[str, int]] = {}
    for technique, count in event_rows:
        merged.setdefault(str(technique), {"events": 0, "alerts": 0})["events"] = int(count)
    for technique, count in alert_rows:
        merged.setdefault(str(technique), {"events": 0, "alerts": 0})["alerts"] = int(count)
    techniques = [
        {
            "technique": technique,
            "name": MITRE_NAMES.get(technique, "Unmapped technique"),
            "events": values["events"],
            "alerts": values["alerts"],
            "total": values["events"] + values["alerts"],
        }
        for technique, values in sorted(
            merged.items(), key=lambda item: (item[1]["events"] + item[1]["alerts"]), reverse=True
        )
    ]
    return {
        "generated_at": utcnow().isoformat(),
        "total_techniques": len(techniques),
        "techniques": techniques,
    }


__all__ = [
    "MITRE_NAMES",
    "alert_or_404",
    "alert_stats",
    "apply_triage",
    "bulk_update_alerts",
    "convert_sigma",
    "create_rule",
    "delete_rule",
    "import_sigma",
    "mitre_coverage",
    "promote_alert",
    "rule_or_404",
    "rule_templates",
    "serialize_alert",
    "serialize_rule",
    "set_rule_enabled",
    "test_rule",
    "triage_alert",
    "update_rule",
]
