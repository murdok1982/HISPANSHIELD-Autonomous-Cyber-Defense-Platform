"""Bounded, typed detection engine evaluated synchronously at ingest.

A rule's ``definition`` is a small DSL::

    {
      "selection": {
        "user_name": "root",
        "dst_port": [22, 3389, {"gte": 8000}],
        "message": {"regex": "(?i)failed login"},
        "ioc_matches": {"exists": true}
      },
      "condition": "and",                    # or "or"
      "threshold": {"count": 5, "group_by": ["src_ip"], "window_seconds": 300},
      "timeframe_seconds": 300
    }

Evaluation is deliberately bounded: rules per batch, events per window and
regex input length are capped so an untrusted rule cannot stall ingestion.
Regular expressions are length-limited and rejected when they contain nested
quantifiers (catastrophic backtracking).
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import lru_cache
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.models.events import Alert, DetectionRule, SecurityEvent

MAX_RULES_PER_BATCH = 250
MAX_WINDOW_EVENTS = 5000
MAX_REGEX_LENGTH = 200
MAX_SELECTION_FIELDS = 50
MAX_LIST_VALUES = 50
MAX_STRING_VALUE = 500
REGEX_INPUT_LIMIT = 4096
DEDUPE_WINDOW = timedelta(minutes=10)
MAX_EVENT_IDS = 50

OPEN_ALERT_STATUSES = ("new", "triaged", "investigating")
ALERT_SEVERITIES = ("informational", "low", "medium", "high", "critical")

_ALLOWED_TOP_LEVEL = {"selection", "condition", "threshold", "timeframe_seconds", "group_by"}
_ALLOWED_OPERATORS = {
    "contains",
    "startswith",
    "endswith",
    "regex",
    "in",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "exists",
    "known_bad",
}
_FIELD_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.\-]{0,120}$")
_CATASTROPHIC_RE = re.compile(
    r"\([^)]*[+*][^)]*\)\s*(?:[+*]|\{\d*,?\d*\})"
    r"|\([^)]*\|[^)]*\)\s*(?:[+*]|\{\d*,?\d*\})"
    r"|\(\.[*+]\)[*+]"
)

_FIELD_ALIASES = {
    "severity": "severity_id",
    "status": "status_id",
    "user": "user_name",
    "username": "user_name",
    "host": "host_name",
    "hostname": "host_name",
    "process": "process_name",
    "src": "src_ip",
    "dst": "dst_ip",
    "sport": "src_port",
    "dport": "dst_port",
    "proto": "protocol",
    "src_endpoint.ip": "src_ip",
    "source.ip": "src_ip",
    "srcip": "src_ip",
    "dst_endpoint.ip": "dst_ip",
    "destination.ip": "dst_ip",
    "dstip": "dst_ip",
    "src_endpoint.port": "src_port",
    "dst_endpoint.port": "dst_port",
    "actor.user.name": "user_name",
    "user.name": "user_name",
    "device.hostname": "host_name",
    "host.hostname": "host_name",
    "actor.process.name": "process_name",
    "process.name": "process_name",
    "file.hashes.sha256": "file_hash_sha256",
    "http_request.url": "url",
    "dns.query.hostname": "domain",
    "network.protocol": "protocol",
    "event_type": "action",
}

_EXTRA_FIELDS = {
    "action",
    "outcome",
    "category",
    "bytes_in",
    "bytes_out",
    "external_id",
    "event_category",
    "status_text",
    "file_name",
}

# Fields a rule may reference directly. Vendor-specific attributes remain
# addressable through the ``unmapped.`` / ``normalized.`` / ``raw.`` prefixes.
KNOWN_FIELDS = (
    {
        "class_uid",
        "class_name",
        "category_uid",
        "activity_id",
        "severity",
        "severity_id",
        "status",
        "status_id",
        "message",
        "src_ip",
        "dst_ip",
        "src_port",
        "dst_port",
        "protocol",
        "user_name",
        "host_name",
        "process_name",
        "file_hash_sha256",
        "url",
        "domain",
        "ioc_matches",
        "mitre_techniques",
        "event_uid",
        "raw_format",
        "source_id",
        "org_id",
        "occurred_at",
        "received_at",
        "is_demo",
        "action",
        "outcome",
        "category",
        "bytes_in",
        "bytes_out",
        "external_id",
        "event_category",
        "status_text",
        "file_name",
    }
    | set(_FIELD_ALIASES)
    | set(_FIELD_ALIASES.values())
)

_ORM_FIELDS = {
    "class_uid",
    "class_name",
    "category_uid",
    "activity_id",
    "severity_id",
    "status_id",
    "message",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "protocol",
    "user_name",
    "host_name",
    "process_name",
    "file_hash_sha256",
    "url",
    "domain",
    "ioc_matches",
    "mitre_techniques",
    "event_uid",
    "raw_format",
    "source_id",
    "org_id",
    "occurred_at",
    "received_at",
    "is_demo",
}


class DefinitionError(ValueError):
    def __init__(self, details: list[dict[str, str]]) -> None:
        super().__init__("Invalid detection rule definition")
        self.details = details


@dataclass(slots=True)
class RuleMatch:
    matched: bool
    matched_fields: dict[str, Any]
    explanation: str
    checks: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class DetectionOutcome:
    alerts_created: int = 0
    alerts_updated: int = 0
    alert_ids: list[str] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    evaluated_rules: int = 0


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _is_scalar(value: Any) -> bool:
    if isinstance(value, float) and not math.isfinite(value):
        return False
    return value is None or isinstance(value, str | int | float | bool)


def _validate_matcher(value: Any, path: str, errors: list[dict[str, str]]) -> None:
    if isinstance(value, dict):
        if len(value) != 1:
            errors.append({"path": path, "message": "A matcher object must contain exactly one operator"})
            return
        operator, operand = next(iter(value.items()))
        if operator not in _ALLOWED_OPERATORS:
            errors.append({"path": path, "message": f"Unsupported operator: {operator}"})
            return
        if operator == "regex":
            if not isinstance(operand, str) or not 1 <= len(operand) <= MAX_REGEX_LENGTH:
                errors.append({"path": path, "message": "regex must be a string of 1..200 characters"})
                return
            if _CATASTROPHIC_RE.search(operand):
                errors.append({"path": path, "message": "regex contains a nested quantifier (ReDoS risk)"})
                return
            try:
                re.compile(operand, re.IGNORECASE)
            except re.error as exc:
                errors.append({"path": path, "message": f"Invalid regex: {exc.msg}"})
            return
        if operator == "exists":
            if not isinstance(operand, bool):
                errors.append({"path": path, "message": "exists expects a boolean"})
            return
        if operator == "known_bad":
            if operand not in {"sha256", "ip", "domain", "url"}:
                errors.append({"path": path, "message": "known_bad expects sha256, ip, domain or url"})
            return
        if operator == "in":
            if not isinstance(operand, list) or not 1 <= len(operand) <= MAX_LIST_VALUES:
                errors.append({"path": path, "message": "in expects a list of 1..50 values"})
                return
            for item in operand:
                if not _is_scalar(item):
                    errors.append({"path": path, "message": "in values must be scalars"})
                    return
            return
        if operator in {"gt", "gte", "lt", "lte"}:
            if (
                isinstance(operand, bool)
                or not isinstance(operand, int | float)
                or (isinstance(operand, float) and not math.isfinite(operand))
            ):
                errors.append({"path": path, "message": f"{operator} expects a number"})
            return
        if operator in {"contains", "startswith", "endswith", "ne"}:
            if not _is_scalar(operand):
                errors.append({"path": path, "message": f"{operator} expects a scalar"})
            elif isinstance(operand, str) and len(operand) > MAX_STRING_VALUE:
                errors.append({"path": path, "message": f"{operator} value is too long"})
            return
        return

    if isinstance(value, list):
        if not 1 <= len(value) <= MAX_LIST_VALUES:
            errors.append({"path": path, "message": "A list matcher must contain 1..50 values"})
            return
        for item in value:
            if isinstance(item, dict):
                _validate_matcher(item, path, errors)
                continue
            if not _is_scalar(item):
                errors.append({"path": path, "message": "List values must be scalars or matcher objects"})
                return
            if isinstance(item, str) and len(item) > MAX_STRING_VALUE:
                errors.append({"path": path, "message": "List value is too long"})
                return
        return
    if not _is_scalar(value):
        errors.append({"path": path, "message": "Matcher must be a scalar, list or operator object"})
        return
    if isinstance(value, str) and len(value) > MAX_STRING_VALUE:
        errors.append({"path": path, "message": "Matcher value is too long"})


def validate_definition(definition: Any) -> None:
    """Validate the rule DSL, raising :class:`DefinitionError` on any defect."""
    errors: list[dict[str, str]] = []
    if not isinstance(definition, dict) or not definition:
        raise DefinitionError([{"path": "definition", "message": "definition must be a non-empty object"}])
    unknown = set(definition) - _ALLOWED_TOP_LEVEL
    if unknown:
        errors.append({"path": "definition", "message": f"Unknown keys: {', '.join(sorted(unknown))}"})

    selection = definition.get("selection")
    if not isinstance(selection, dict) or not selection:
        errors.append({"path": "definition.selection", "message": "selection must be a non-empty object"})
    elif len(selection) > MAX_SELECTION_FIELDS:
        errors.append({"path": "definition.selection", "message": "selection contains too many fields"})
    else:
        for field_name, matcher in selection.items():
            if not isinstance(field_name, str) or not _FIELD_RE.match(field_name) or "__" in field_name:
                errors.append({"path": "definition.selection", "message": f"Invalid field name: {field_name}"})
                continue
            if not _field_is_known(field_name):
                errors.append({"path": f"definition.selection.{field_name}", "message": "Unknown field"})
                continue
            _validate_matcher(matcher, f"definition.selection.{field_name}", errors)

    condition = definition.get("condition", "and")
    if not isinstance(condition, str) or condition.lower() not in {"and", "or"}:
        errors.append({"path": "definition.condition", "message": "condition must be 'and' or 'or'"})

    if "timeframe_seconds" in definition:
        timeframe = definition["timeframe_seconds"]
        if isinstance(timeframe, bool) or not isinstance(timeframe, int) or not 10 <= timeframe <= 86400:
            errors.append({"path": "definition.timeframe_seconds", "message": "timeframe must be 10..86400 seconds"})

    if "group_by" in definition:
        _validate_group_by(definition["group_by"], "definition.group_by", errors)

    if "threshold" in definition:
        threshold = definition["threshold"]
        if not isinstance(threshold, dict):
            errors.append({"path": "definition.threshold", "message": "threshold must be an object"})
        else:
            unknown_threshold = set(threshold) - {"count", "group_by", "window_seconds"}
            if unknown_threshold:
                errors.append(
                    {
                        "path": "definition.threshold",
                        "message": f"Unknown keys: {', '.join(sorted(unknown_threshold))}",
                    }
                )
            count = threshold.get("count")
            if isinstance(count, bool) or not isinstance(count, int) or not 2 <= count <= 100000:
                errors.append(
                    {"path": "definition.threshold.count", "message": "count must be an integer of 2..100000"}
                )
            if "window_seconds" in threshold:
                window = threshold["window_seconds"]
                if isinstance(window, bool) or not isinstance(window, int) or not 10 <= window <= 86400:
                    errors.append(
                        {
                            "path": "definition.threshold.window_seconds",
                            "message": "window_seconds must be 10..86400",
                        }
                    )
            if "group_by" in threshold:
                _validate_group_by(threshold["group_by"], "definition.threshold.group_by", errors)

    try:
        serialized = json.dumps(definition, default=str)
    except (TypeError, ValueError):
        errors.append({"path": "definition", "message": "definition must be JSON serialisable"})
    else:
        if len(serialized) > 65536:
            errors.append({"path": "definition", "message": "definition exceeds 64 KiB"})

    if errors:
        raise DefinitionError(errors)


def _field_is_known(field_name: str) -> bool:
    if field_name in KNOWN_FIELDS:
        return True
    for prefix in ("unmapped.", "normalized.", "raw."):
        if field_name.startswith(prefix) and len(field_name) > len(prefix):
            return True
    return False


def _validate_group_by(value: Any, path: str, errors: list[dict[str, str]]) -> None:
    if not isinstance(value, list) or not 1 <= len(value) <= 5:
        errors.append({"path": path, "message": "group_by must be a list of 1..5 field names"})
        return
    for item in value:
        if not isinstance(item, str) or not _FIELD_RE.match(item):
            errors.append({"path": path, "message": f"Invalid group_by field: {item}"})
        elif not _field_is_known(item):
            errors.append({"path": path, "message": f"Unknown group_by field: {item}"})


# ---------------------------------------------------------------------------
# Field resolution
# ---------------------------------------------------------------------------


def _traverse(data: Any, path: str) -> Any:
    current = data
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return None
        if current is None:
            return None
    return current


def resolve_field(event: Any, field_name: str) -> Any:
    """Read a rule field from an ORM event or a plain sample dictionary."""
    name = _FIELD_ALIASES.get(field_name, field_name)

    if name.startswith("unmapped."):
        key = name[len("unmapped.") :]
        if isinstance(event, dict):
            raw_normalized = event.get("normalized")
            nested = raw_normalized if isinstance(raw_normalized, dict) else {}
            return (nested.get("unmapped") or {}).get(key)
        orm_normalized = event.normalized or {}
        return (orm_normalized.get("unmapped") or {}).get(key)

    if isinstance(event, dict):
        if name in event:
            return event[name]
        normalized = event.get("normalized")
        if isinstance(normalized, dict):
            if name in {"ioc_matches", "mitre_techniques"}:
                return event.get(name) or normalized.get(name)
            value = _traverse(normalized, name)
            if value is not None:
                return value
            extra = normalized.get("extra")
            if isinstance(extra, dict) and name in extra:
                return extra[name]
            unmapped = normalized.get("unmapped")
            if isinstance(unmapped, dict) and name in unmapped:
                return unmapped[name]
        raw = event.get("raw")
        if isinstance(raw, dict):
            value = _traverse(raw, name)
            if value is not None:
                return value
        return None

    if name in _ORM_FIELDS:
        return getattr(event, name, None)
    normalized = getattr(event, "normalized", None) or {}
    if isinstance(normalized, dict):
        extra = normalized.get("extra")
        if isinstance(extra, dict) and name in extra:
            return extra[name]
        value = _traverse(normalized, name)
        if value is not None:
            return value
        unmapped = normalized.get("unmapped")
        if isinstance(unmapped, dict):
            value = unmapped.get(name)
            if value is not None:
                return value
    return getattr(event, name, None) if name in _EXTRA_FIELDS else None


def _equals(actual: Any, expected: Any) -> bool:
    if actual is None or expected is None:
        return actual is None and expected is None
    if isinstance(expected, bool):
        if isinstance(actual, bool):
            return actual is expected
        truthy = str(actual).strip().lower() in {"true", "1", "yes"}
        return truthy if expected else not truthy
    if isinstance(expected, int | float):
        try:
            return float(actual) == float(expected)
        except (TypeError, ValueError):
            return False
    if isinstance(actual, list | tuple | dict):
        return False
    return str(actual).strip().casefold() == str(expected).strip().casefold()


def _haystack(actual: Any) -> str:
    if isinstance(actual, list | tuple):
        return " ".join(str(item) for item in actual)
    if isinstance(actual, dict):
        return json.dumps(actual, default=str)
    return "" if actual is None else str(actual)


@lru_cache(maxsize=256)
def _compile_regex(pattern: str) -> re.Pattern[str]:
    if len(pattern) > MAX_REGEX_LENGTH or _CATASTROPHIC_RE.search(pattern):
        raise ValueError("unsafe regex")
    return re.compile(pattern, re.IGNORECASE)


def _match_operator(actual: Any, operator: str, operand: Any) -> bool:
    if operator == "exists":
        present = actual is not None and actual != "" and actual != []
        return bool(present) is bool(operand)
    if operator == "known_bad":
        if not isinstance(actual, list):
            return False
        return any(
            isinstance(item, dict) and str(item.get("indicator_type", "")).lower() == str(operand).lower()
            for item in actual
        )
    if operator == "in":
        return any(_equals(actual, item) for item in operand)
    if operator == "ne":
        return not _equals(actual, operand)
    if operator in {"gt", "gte", "lt", "lte"}:
        try:
            left = float(actual)
            right = float(operand)
        except (TypeError, ValueError):
            return False
        return {
            "gt": left > right,
            "gte": left >= right,
            "lt": left < right,
            "lte": left <= right,
        }[operator]
    if actual is None:
        return False
    if operator == "contains":
        return str(operand).casefold() in _haystack(actual).casefold()
    if operator == "startswith":
        return _haystack(actual).casefold().startswith(str(operand).casefold())
    if operator == "endswith":
        return _haystack(actual).casefold().endswith(str(operand).casefold())
    if operator == "regex":
        try:
            pattern = _compile_regex(str(operand))
        except (ValueError, re.error):
            return False
        return pattern.search(_haystack(actual)[:REGEX_INPUT_LIMIT]) is not None
    return False


def match_value(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict) and len(expected) == 1:
        operator, operand = next(iter(expected.items()))
        return _match_operator(actual, operator, operand)
    if isinstance(expected, list):
        return any(match_value(actual, item) for item in expected)
    return _equals(actual, expected)


# ---------------------------------------------------------------------------
# Rule evaluation
# ---------------------------------------------------------------------------


def evaluate_rule(definition: dict[str, Any], event: Any) -> RuleMatch:
    """Evaluate the selection against one event and explain each check."""
    selection = definition.get("selection") or {}
    condition = str(definition.get("condition", "and")).lower()
    checks: list[dict[str, Any]] = []
    matched_fields: dict[str, Any] = {}
    for field_name, expected in selection.items():
        actual = resolve_field(event, field_name)
        ok = match_value(actual, expected)
        checks.append(
            {
                "field": field_name,
                "operator": next(iter(expected)) if isinstance(expected, dict) else "equals",
                "expected": expected,
                "actual": _brief(actual),
                "matched": ok,
            }
        )
        if ok:
            matched_fields[field_name] = _brief(actual)

    if condition == "or":
        matched = any(check["matched"] for check in checks) if checks else False
    else:
        matched = all(check["matched"] for check in checks) if checks else False
    matched_count = sum(1 for check in checks if check["matched"])
    explanation = f"{matched_count}/{len(checks)} selection fields matched ({condition})"
    if matched_fields:
        explanation += "; matched: " + ", ".join(sorted(matched_fields))
    return RuleMatch(matched=matched, matched_fields=matched_fields, explanation=explanation, checks=checks)


def _brief(value: Any) -> Any:
    if isinstance(value, list | dict):
        try:
            text = json.dumps(value, default=str, sort_keys=True)
        except (TypeError, ValueError):
            text = str(value)
        return text[:300]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, str):
        return value[:300]
    return value


def _group_value(value: Any) -> str:
    if value is None:
        return "__missing__"
    if isinstance(value, list | dict):
        return json.dumps(value, default=str, sort_keys=True)[:200]
    return str(value)[:200]


def group_values(event: Any, group_by: list[str] | None) -> dict[str, str]:
    fields = group_by or [name for name in ("src_ip", "host_name", "user_name") if resolve_field(event, name)]
    return {name: _group_value(resolve_field(event, name)) for name in fields}


def build_dedupe_key(rule_id: Any, group: dict[str, str]) -> str:
    material = json.dumps({"rule": str(rule_id), "group": group}, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _risk_score(rule: DetectionRule, event: SecurityEvent) -> float:
    base = {"critical": 92, "high": 72, "medium": 52, "low": 30, "informational": 12}.get(rule.severity, 50)
    score = base + min(8, len(getattr(event, "ioc_matches", None) or []) * 4)
    score += min(6, int(getattr(event, "severity_id", 0) or 0) * 2)
    return float(max(0.0, min(100.0, score)))


def _merge_event_ids(existing: list[int] | None, new: list[int]) -> list[int]:
    merged: list[int] = []
    for item in [*(existing or []), *new]:
        if isinstance(item, int) and item not in merged:
            merged.append(item)
    return merged[-MAX_EVENT_IDS:]


def _alert_title(rule: DetectionRule, group: dict[str, str]) -> str:
    if not group:
        return rule.name[:300]
    summary = ", ".join(f"{key}={value}" for key, value in group.items())
    return f"{rule.name} — {summary}"[:300]


def _evidence(
    *,
    rule: DetectionRule,
    group: dict[str, str],
    observed: int,
    window_seconds: int | None,
    matched_fields: dict[str, Any],
    event: SecurityEvent,
    related: list[SecurityEvent],
    event_ids: list[int],
) -> dict[str, Any]:
    samples = [
        {
            "id": item.id,
            "event_uid": item.event_uid,
            "occurred_at": item.occurred_at.isoformat() if item.occurred_at else None,
            "severity_id": item.severity_id,
            "message": (item.message or "")[:300],
        }
        for item in related[:10]
    ]
    if not samples:
        samples = [
            {
                "id": event.id,
                "event_uid": event.event_uid,
                "occurred_at": event.occurred_at.isoformat() if event.occurred_at else None,
                "severity_id": event.severity_id,
                "message": (event.message or "")[:300],
            }
        ]
    return {
        "rule": {
            "id": str(rule.id),
            "name": rule.name,
            "version": rule.version,
            "severity": rule.severity,
            "definition": rule.definition,
        },
        "group": group,
        "observed": observed,
        "window_seconds": window_seconds,
        "matched_fields": matched_fields,
        "events": samples,
        "event_ids": event_ids,
    }


def _upsert_alert(
    db: Session,
    *,
    org_id: Any,
    rule: DetectionRule,
    event: SecurityEvent,
    group: dict[str, str],
    observed: int,
    window_seconds: int | None,
    matched_fields: dict[str, Any],
    related: list[SecurityEvent],
) -> tuple[Alert, bool]:
    now = utcnow()
    dedupe_key = build_dedupe_key(rule.id, group)
    existing = db.execute(
        select(Alert)
        .where(
            Alert.org_id == org_id,
            Alert.dedupe_key == dedupe_key,
            Alert.status.in_(OPEN_ALERT_STATUSES),
            Alert.last_seen >= now - DEDUPE_WINDOW,
        )
        .order_by(Alert.last_seen.desc())
        .limit(1)
    ).scalar_one_or_none()

    related_ids = [item.id for item in related if item.id is not None]
    if event.id is not None:
        related_ids.append(event.id)
    event_ids = _merge_event_ids(None, related_ids)
    if existing is not None:
        existing.count += 1
        existing.last_seen = now
        existing.event_ids = _merge_event_ids(existing.event_ids, related_ids)
        existing.evidence = _evidence(
            rule=rule,
            group=group,
            observed=observed,
            window_seconds=window_seconds,
            matched_fields=matched_fields,
            event=event,
            related=related,
            event_ids=existing.event_ids,
        )
        existing.risk_score = max(existing.risk_score, _risk_score(rule, event))
        db.add(existing)
        return existing, False

    alert = Alert(
        org_id=org_id,
        rule_id=rule.id,
        title=_alert_title(rule, group),
        description=rule.description,
        severity=rule.severity if rule.severity in ALERT_SEVERITIES else "medium",
        status="new",
        dedupe_key=dedupe_key,
        event_ids=event_ids,
        first_seen=now,
        last_seen=now,
        count=1,
        mitre=list(rule.mitre or []),
        evidence=_evidence(
            rule=rule,
            group=group,
            observed=observed,
            window_seconds=window_seconds,
            matched_fields=matched_fields,
            event=event,
            related=related,
            event_ids=event_ids,
        ),
        risk_score=_risk_score(rule, event),
        is_demo=bool(getattr(event, "is_demo", False)),
    )
    db.add(alert)
    db.flush()
    return alert, True


def _window_index(
    db: Session,
    *,
    org_id: Any,
    rule: DetectionRule,
    group_by: list[str] | None,
    window_seconds: int,
    now: datetime,
) -> dict[str, list[SecurityEvent]]:
    since = now - timedelta(seconds=window_seconds)
    candidates = list(
        db.execute(
            select(SecurityEvent)
            .where(SecurityEvent.org_id == org_id, SecurityEvent.occurred_at >= since)
            .order_by(SecurityEvent.occurred_at.desc())
            .limit(MAX_WINDOW_EVENTS)
        ).scalars()
    )
    index: dict[str, list[SecurityEvent]] = {}
    for candidate in candidates:
        try:
            if not evaluate_rule(rule.definition, candidate).matched:
                continue
        except (ValueError, re.error):
            continue
        key = json.dumps(group_values(candidate, group_by), sort_keys=True, separators=(",", ":"))
        index.setdefault(key, []).append(candidate)
    return index


def run_detection(db: Session, *, org_id: Any, events: list[SecurityEvent]) -> DetectionOutcome:
    """Evaluate every enabled rule (org + global) against ingested events."""
    outcome = DetectionOutcome()
    if not events:
        return outcome
    if any(event.id is None for event in events):
        db.flush()

    rules = list(
        db.execute(
            select(DetectionRule)
            .where(
                DetectionRule.enabled.is_(True),
                or_(DetectionRule.org_id == org_id, DetectionRule.org_id.is_(None)),
            )
            .order_by(DetectionRule.created_at.asc())
            .limit(MAX_RULES_PER_BATCH)
        ).scalars()
    )
    now = utcnow()
    for rule in rules:
        try:
            validate_definition(rule.definition)
        except DefinitionError as exc:
            outcome.errors.append({"rule_id": str(rule.id), "error": "invalid_definition", "detail": str(exc)})
            continue
        except Exception as exc:  # pragma: no cover - defensive: a broken row must not stop ingest
            outcome.errors.append({"rule_id": str(rule.id), "error": "rule_error", "detail": str(exc)[:200]})
            continue

        threshold = rule.definition.get("threshold")
        group_by = (threshold or {}).get("group_by") or rule.definition.get("group_by")
        window_seconds = int((threshold or {}).get("window_seconds", 300)) if threshold else None
        window_index: dict[str, list[SecurityEvent]] | None = None
        outcome.evaluated_rules += 1

        try:
            for event in events:
                match = evaluate_rule(rule.definition, event)
                if not match.matched:
                    continue
                group = group_values(event, group_by)
                related: list[SecurityEvent] = [event]
                observed = 1
                if threshold:
                    if window_index is None:
                        window_index = _window_index(
                            db,
                            org_id=org_id,
                            rule=rule,
                            group_by=group_by,
                            window_seconds=int(window_seconds or 300),
                            now=now,
                        )
                    key = json.dumps(group, sort_keys=True, separators=(",", ":"))
                    related = list(window_index.get(key, []))
                    if not any(item.id == event.id for item in related):
                        related.insert(0, event)
                        observed = len(related)
                    else:
                        observed = len(related)
                    if observed < int(threshold.get("count", 1)):
                        continue
                alert, created = _upsert_alert(
                    db,
                    org_id=org_id,
                    rule=rule,
                    event=event,
                    group=group,
                    observed=observed,
                    window_seconds=window_seconds,
                    matched_fields=match.matched_fields,
                    related=related,
                )
                outcome.alert_ids.append(str(alert.id))
                if created:
                    outcome.alerts_created += 1
                else:
                    outcome.alerts_updated += 1
        except Exception as exc:  # defensive: bound a single rule failure
            outcome.errors.append({"rule_id": str(rule.id), "error": "evaluation_error", "detail": str(exc)[:200]})
            continue

    db.flush()
    return outcome


def explain_rule(
    definition: dict[str, Any],
    samples: list[Any],
    *,
    threshold_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Evaluate a rule against sample events for the rule-test endpoint."""
    matches: list[dict[str, Any]] = []
    for index, sample in enumerate(samples):
        result = evaluate_rule(definition, sample)
        matches.append(
            {
                "index": index,
                "event_id": sample.get("id") if isinstance(sample, dict) else getattr(sample, "id", None),
                "matched": result.matched,
                "matched_fields": result.matched_fields,
                "explanation": result.explanation,
                "checks": result.checks,
            }
        )
    return {
        "matches": matches,
        "matched_count": sum(1 for item in matches if item["matched"]),
        "threshold": threshold_state,
        "would_alert": bool(
            any(item["matched"] for item in matches)
            and (threshold_state is None or threshold_state.get("would_trigger"))
        ),
    }


__all__ = [
    "ALERT_SEVERITIES",
    "DEDUPE_WINDOW",
    "MAX_REGEX_LENGTH",
    "OPEN_ALERT_STATUSES",
    "DefinitionError",
    "DetectionOutcome",
    "RuleMatch",
    "build_dedupe_key",
    "evaluate_rule",
    "explain_rule",
    "group_values",
    "match_value",
    "resolve_field",
    "run_detection",
    "validate_definition",
]
