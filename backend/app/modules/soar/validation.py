"""Strict validation for SOAR playbook definitions.

Definitions are authored by users and executed by the autonomy plane, so the
validator is deny-by-default: unknown actions, unknown keys, oversized
definitions, forbidden OT operations and unapproved high-risk defence steps are
all rejected before a playbook can be stored or published.
"""

from __future__ import annotations

import json
import re
from typing import Any

from app.core.errors import ValidationFailure
from app.services.actions import ACTIONS, FORBIDDEN_ACTIONS, level_index

MAX_STEPS = 50
MAX_PARAM_BYTES = 20_000
MAX_CONTEXT_BYTES = 64_000
MAX_DEPTH = 8

INTERNAL_ACTIONS = {
    "internal.investigate",
    "internal.create_incident",
    "internal.add_timeline",
    "internal.request_approval",
    "internal.notify",
}
CONNECTOR_ACTION = "connector.read"
DEFENCE_ACTION = "defence.execute"
STEP_ACTIONS = INTERNAL_ACTIONS | {CONNECTOR_ACTION, DEFENCE_ACTION}

ON_FAILURE_POLICIES = {"compensate", "abort", "continue"}
CONDITION_OPS = {
    "eq",
    "ne",
    "gt",
    "gte",
    "lt",
    "lte",
    "in",
    "not_in",
    "contains",
    "not_contains",
    "exists",
    "startswith",
    "endswith",
    "truthy",
    "falsy",
}
STEP_KEYS = {
    "key",
    "name",
    "action",
    "params",
    "condition",
    "on_failure",
    "retries",
    "timeout_seconds",
    "compensation",
}
TOP_LEVEL_KEYS = {"steps", "triggers"}
TRIGGER_KEYS = {"alert_severity", "rules"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}
AUTONOMY_LEVELS = {"A0", "A1", "A2", "A3", "A4"}
TARGET_TYPES = {"endpoint", "ip", "identity", "session", "incident", "asset", "organization", "integration"}
KEY_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,79}$")
CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9_]{1,60}$")


def _fail(details: list[dict[str, Any]], field: str, message: str) -> None:
    details.append({"field": field, "message": message})


def _json_size(value: Any) -> int:
    return len(json.dumps(value, sort_keys=True, default=str, separators=(",", ":")))


def _depth(value: Any, depth: int = 0) -> int:
    if depth > MAX_DEPTH:
        return depth
    if isinstance(value, dict):
        return max((_depth(item, depth + 1) for item in value.values()), default=depth)
    if isinstance(value, list):
        return max((_depth(item, depth + 1) for item in value), default=depth)
    return depth


def validate_context(context: dict[str, Any] | None) -> dict[str, Any]:
    if context is None:
        return {}
    if not isinstance(context, dict):
        raise ValidationFailure([{"field": "context", "message": "Context must be an object"}])
    if _json_size(context) > MAX_CONTEXT_BYTES:
        raise ValidationFailure([{"field": "context", "message": "Context exceeds the 64KB limit"}])
    if _depth(context) > MAX_DEPTH:
        raise ValidationFailure([{"field": "context", "message": "Context is nested too deeply"}])
    return context


def _validate_condition(condition: Any, field_prefix: str, details: list[dict[str, Any]]) -> dict[str, Any] | None:
    if condition is None:
        return None
    if not isinstance(condition, dict):
        _fail(details, field_prefix, "Condition must be an object or null")
        return None
    unknown = set(condition) - {"field", "op", "value"}
    if unknown:
        _fail(details, field_prefix, f"Unknown condition keys: {', '.join(sorted(unknown))}")
        return None
    path = condition.get("field")
    op = condition.get("op")
    if not isinstance(path, str) or not path or len(path) > 200:
        _fail(details, f"{field_prefix}.field", "Condition field must be a 1-200 character path")
        return None
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", path):
        _fail(details, f"{field_prefix}.field", "Condition field contains invalid characters")
        return None
    if op not in CONDITION_OPS:
        _fail(details, f"{field_prefix}.op", f"Unsupported operator: {op}")
        return None
    if "value" not in condition and op not in {"exists", "truthy", "falsy"}:
        _fail(details, f"{field_prefix}.value", "This operator requires a value")
        return None
    value = condition.get("value")
    if op in {"in", "not_in"} and not isinstance(value, list):
        _fail(details, f"{field_prefix}.value", f"Operator {op} requires a list value")
        return None
    if _json_size(value) > 8_000:
        _fail(details, f"{field_prefix}.value", "Condition value is too large")
        return None
    return {"field": path, "op": op, "value": value}


def _validate_compensation(
    compensation: Any, field_prefix: str, details: list[dict[str, Any]]
) -> dict[str, Any] | None:
    if compensation is None:
        return None
    if not isinstance(compensation, dict):
        _fail(details, field_prefix, "Compensation must be an object or null")
        return None
    unknown = set(compensation) - {"action", "params"}
    if unknown:
        _fail(details, field_prefix, f"Unknown compensation keys: {', '.join(sorted(unknown))}")
        return None
    action = compensation.get("action")
    params = compensation.get("params") or {}
    if action not in STEP_ACTIONS:
        _fail(details, f"{field_prefix}.action", f"Unknown compensation action: {action}")
        return None
    if not isinstance(params, dict):
        _fail(details, f"{field_prefix}.params", "Compensation params must be an object")
        return None
    if _json_size(params) > MAX_PARAM_BYTES:
        _fail(details, f"{field_prefix}.params", "Compensation params exceed the size limit")
        return None
    if action == DEFENCE_ACTION:
        action_type = params.get("action_type")
        definition = ACTIONS.get(action_type) if isinstance(action_type, str) else None
        if definition is None:
            _fail(details, f"{field_prefix}.params.action_type", "Compensation must use a catalogue action")
        elif action_type in FORBIDDEN_ACTIONS:
            _fail(details, f"{field_prefix}.params.action_type", FORBIDDEN_ACTIONS[action_type])
        elif not definition.reversible:
            _fail(details, f"{field_prefix}.params.action_type", "Compensation action is not reversible")
    if action == CONNECTOR_ACTION:
        capability = params.get("capability")
        if not isinstance(capability, str) or not CAPABILITY_RE.match(capability):
            _fail(details, f"{field_prefix}.params.capability", "A connector read capability is required")
    return {"action": action, "params": params}


def _validate_params(action: str, params: Any, field_prefix: str, details: list[dict[str, Any]]) -> dict[str, Any]:
    if params is None:
        params = {}
    if not isinstance(params, dict):
        _fail(details, field_prefix, "Params must be an object")
        return {}
    if _json_size(params) > MAX_PARAM_BYTES:
        _fail(details, field_prefix, "Params exceed the size limit")
        return {}
    if _depth(params) > 4:
        _fail(details, field_prefix, "Params are nested too deeply")
        return {}

    if action == CONNECTOR_ACTION:
        capability = params.get("capability")
        if not isinstance(capability, str) or not CAPABILITY_RE.match(capability):
            _fail(details, f"{field_prefix}.capability", "A read capability name is required")
        connector_id = params.get("connector_id")
        if connector_id is not None:
            try:
                from uuid import UUID

                UUID(str(connector_id))
            except (ValueError, TypeError):
                _fail(details, f"{field_prefix}.connector_id", "connector_id must be a UUID")
        nested = params.get("params", {})
        if not isinstance(nested, dict):
            _fail(details, f"{field_prefix}.params", "Nested read params must be an object")

    if action == DEFENCE_ACTION:
        action_type = params.get("action_type")
        definition = ACTIONS.get(action_type) if isinstance(action_type, str) else None
        if isinstance(action_type, str) and action_type in FORBIDDEN_ACTIONS:
            _fail(details, f"{field_prefix}.action_type", FORBIDDEN_ACTIONS[action_type])
            definition = None
        if definition is None or definition.internal:
            _fail(
                details,
                f"{field_prefix}.action_type",
                "defence.execute requires a non-internal catalogue action",
            )
            return params
        target_type = params.get("target_type", definition.target_type)
        if target_type not in TARGET_TYPES:
            _fail(details, f"{field_prefix}.target_type", f"Unknown target type: {target_type}")
        elif target_type != definition.target_type:
            _fail(
                details,
                f"{field_prefix}.target_type",
                f"Action '{action_type}' targets '{definition.target_type}', not '{target_type}'",
            )
        target_id = params.get("target_id")
        if not isinstance(target_id, str) or not target_id or len(target_id) > 300:
            _fail(details, f"{field_prefix}.target_id", "target_id is required (max 300 characters)")
        inner = params.get("parameters", {})
        if not isinstance(inner, dict):
            _fail(details, f"{field_prefix}.parameters", "Action parameters must be an object")
        requested_level = params.get("requested_level")
        if requested_level is not None and requested_level not in AUTONOMY_LEVELS:
            _fail(details, f"{field_prefix}.requested_level", "requested_level must be A0..A4")

    if action == "internal.create_incident":
        severity = params.get("severity")
        if severity is not None and str(severity).lower() not in SEVERITIES | {"p1", "p2", "p3", "p4", "p5"}:
            _fail(details, f"{field_prefix}.severity", "Invalid incident severity")
        title = params.get("title")
        if title is not None and (not isinstance(title, str) or not 3 <= len(title) <= 300):
            _fail(details, f"{field_prefix}.title", "Incident title must be 3-300 characters")

    if action == "internal.add_timeline":
        summary = params.get("summary")
        if summary is not None and (not isinstance(summary, str) or not 3 <= len(summary) <= 500):
            _fail(details, f"{field_prefix}.summary", "Timeline summary must be 3-500 characters")

    if action == "internal.request_approval":
        ttl = params.get("ttl_seconds")
        if ttl is not None and (not isinstance(ttl, int) or isinstance(ttl, bool) or not 60 <= ttl <= 604800):
            _fail(details, f"{field_prefix}.ttl_seconds", "ttl_seconds must be between 60 and 604800")

    if action == "internal.notify":
        title = params.get("title")
        if title is not None and (not isinstance(title, str) or not 1 <= len(title) <= 240):
            _fail(details, f"{field_prefix}.title", "Notification title must be 1-240 characters")
        if params.get("webhook") and not isinstance(params.get("connector_id", ""), str):
            _fail(details, f"{field_prefix}.connector_id", "connector_id must be a string")

    return params


def _defence_requires_approval(action_type: str) -> bool:
    definition = ACTIONS.get(action_type)
    if definition is None:
        return False
    return definition.approval_required or level_index(definition.min_level) >= level_index("A3")


def validate_definition(
    definition: dict[str, Any],
    *,
    min_autonomy_level: str = "A2",
) -> dict[str, Any]:
    """Validate and normalise a playbook definition.

    Raises ``ValidationFailure`` with per-field details. The returned structure
    has defaults filled so the engine can execute it deterministically.
    """
    details: list[dict[str, Any]] = []
    if min_autonomy_level not in AUTONOMY_LEVELS:
        _fail(details, "min_autonomy_level", "Autonomy level must be A0..A4")
    if not isinstance(definition, dict):
        raise ValidationFailure([{"field": "definition", "message": "Definition must be an object"}])
    if _json_size(definition) > 500_000:
        raise ValidationFailure([{"field": "definition", "message": "Definition exceeds the 500KB limit"}])
    unknown_top = set(definition) - TOP_LEVEL_KEYS
    if unknown_top:
        _fail(details, "definition", f"Unknown definition keys: {', '.join(sorted(unknown_top))}")

    steps = definition.get("steps")
    if not isinstance(steps, list) or not steps:
        raise ValidationFailure(details + [{"field": "definition.steps", "message": "At least one step is required"}])
    if len(steps) > MAX_STEPS:
        raise ValidationFailure(
            details + [{"field": "definition.steps", "message": f"A playbook is limited to {MAX_STEPS} steps"}]
        )

    triggers = definition.get("triggers") or {}
    if not isinstance(triggers, dict):
        _fail(details, "definition.triggers", "Triggers must be an object")
        triggers = {}
    else:
        unknown_triggers = set(triggers) - TRIGGER_KEYS
        if unknown_triggers:
            _fail(details, "definition.triggers", f"Unknown trigger keys: {', '.join(sorted(unknown_triggers))}")
        severities = triggers.get("alert_severity", [])
        if not isinstance(severities, list) or any(str(value).lower() not in SEVERITIES for value in severities):
            _fail(details, "definition.triggers.alert_severity", "alert_severity must be a list of severities")
        rules = triggers.get("rules", [])
        if not isinstance(rules, list):
            _fail(details, "definition.triggers.rules", "rules must be a list of rule identifiers")
        else:
            for rule in rules:
                if not isinstance(rule, str) or len(rule) > 80:
                    _fail(details, "definition.triggers.rules", "Each rule must be a string (max 80 characters)")
                    break

    normalised_steps: list[dict[str, Any]] = []
    seen_keys: set[str] = set()
    approval_scope: dict[str, Any] | None = None
    for index, raw_step in enumerate(steps):
        prefix = f"definition.steps[{index}]"
        if not isinstance(raw_step, dict):
            _fail(details, prefix, "Each step must be an object")
            continue
        unknown = set(raw_step) - STEP_KEYS
        if unknown:
            _fail(details, prefix, f"Unknown step keys: {', '.join(sorted(unknown))}")
            continue
        key = raw_step.get("key")
        if not isinstance(key, str) or not KEY_RE.match(key):
            _fail(details, f"{prefix}.key", "Step key must match ^[a-z][a-z0-9_.-]{0,79}$")
            continue
        if key in seen_keys:
            _fail(details, f"{prefix}.key", f"Duplicate step key: {key}")
            continue
        seen_keys.add(key)
        name = raw_step.get("name")
        if not isinstance(name, str) or not 2 <= len(name) <= 200:
            _fail(details, f"{prefix}.name", "Step name must be 2-200 characters")
            continue
        action = raw_step.get("action")
        if action not in STEP_ACTIONS:
            _fail(details, f"{prefix}.action", f"Unknown or forbidden step action: {action}")
            continue
        on_failure = raw_step.get("on_failure", "abort")
        if on_failure not in ON_FAILURE_POLICIES:
            _fail(details, f"{prefix}.on_failure", "on_failure must be compensate, abort or continue")
        retries = raw_step.get("retries", 0)
        if not isinstance(retries, int) or isinstance(retries, bool) or not 0 <= retries <= 3:
            _fail(details, f"{prefix}.retries", "retries must be an integer between 0 and 3")
            retries = 0
        timeout = raw_step.get("timeout_seconds", 60)
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 3600:
            _fail(details, f"{prefix}.timeout_seconds", "timeout_seconds must be between 1 and 3600")
            timeout = 60
        params = _validate_params(action, raw_step.get("params"), f"{prefix}.params", details)
        condition = _validate_condition(raw_step.get("condition"), f"{prefix}.condition", details)
        compensation = _validate_compensation(raw_step.get("compensation"), f"{prefix}.compensation", details)

        if action == DEFENCE_ACTION:
            action_type = params.get("action_type")
            if isinstance(action_type, str) and _defence_requires_approval(action_type):
                defence_definition = ACTIONS.get(action_type)
                defence_target_type = params.get("target_type") or (
                    defence_definition.target_type if defence_definition else None
                )
                if approval_scope is None:
                    _fail(
                        details,
                        f"{prefix}.params.action_type",
                        f"Defence action '{action_type}' requires a preceding internal.request_approval step",
                    )
                elif approval_scope.get("action_type") != action_type:
                    _fail(
                        details,
                        f"{prefix}.params.action_type",
                        "The approval step authorizes a different action type",
                    )
                elif str(approval_scope.get("target_type")) != str(defence_target_type) or str(
                    approval_scope.get("target_id")
                ) != str(params.get("target_id")):
                    _fail(
                        details,
                        f"{prefix}.params.target_id",
                        "The approval step authorizes a different target",
                    )
                approval_scope = None

        if action == "internal.request_approval":
            approval_action = params.get("action_type")
            approval_definition = ACTIONS.get(approval_action) if isinstance(approval_action, str) else None
            if approval_definition is None or approval_definition.internal:
                _fail(
                    details,
                    f"{prefix}.params.action_type",
                    "internal.request_approval requires a catalogue defensive action_type",
                )
            else:
                approval_target_type = params.get("target_type", approval_definition.target_type)
                approval_target_id = params.get("target_id")
                if approval_target_type != approval_definition.target_type:
                    _fail(
                        details,
                        f"{prefix}.params.target_type",
                        f"Approval target type must be '{approval_definition.target_type}'",
                    )
                if not isinstance(approval_target_id, str) or not approval_target_id:
                    _fail(
                        details,
                        f"{prefix}.params.target_id",
                        "The approval step must bind a target_id",
                    )
                approval_scope = {
                    "action_type": approval_action,
                    "target_type": approval_target_type,
                    "target_id": approval_target_id,
                }

        normalised_steps.append(
            {
                "key": key,
                "name": name,
                "action": action,
                "params": params,
                "condition": condition,
                "on_failure": on_failure,
                "retries": retries,
                "timeout_seconds": timeout,
                "compensation": compensation,
            }
        )

    if details:
        raise ValidationFailure(details)
    return {
        "steps": normalised_steps,
        "triggers": {
            "alert_severity": [str(value).lower() for value in triggers.get("alert_severity", [])],
            "rules": triggers.get("rules", []),
        },
    }


def evaluate_condition(condition: dict[str, Any] | None, context: dict[str, Any]) -> bool:
    """Evaluate a validated condition against a flattened execution context."""
    if not condition:
        return True
    value = _lookup(context, condition["field"])
    op = condition["op"]
    expected = condition.get("value")
    try:
        if op == "exists":
            return value is not None
        if op == "truthy":
            return bool(value)
        if op == "falsy":
            return not bool(value)
        if op == "eq":
            return value == expected
        if op == "ne":
            return value != expected
        if op == "gt":
            return value is not None and value > expected
        if op == "gte":
            return value is not None and value >= expected
        if op == "lt":
            return value is not None and value < expected
        if op == "lte":
            return value is not None and value <= expected
        if op == "in":
            return value in expected
        if op == "not_in":
            return value not in expected
        if op == "contains":
            return expected in value if value is not None else False
        if op == "not_contains":
            return expected not in value if value is not None else True
        if op == "startswith":
            return isinstance(value, str) and value.startswith(str(expected))
        if op == "endswith":
            return isinstance(value, str) and value.endswith(str(expected))
    except (TypeError, ValueError):
        return False
    return False


def _lookup(context: dict[str, Any], path: str) -> Any:
    current: Any = context
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def render_params(value: Any, context: dict[str, Any]) -> Any:
    """Substitute ``${path.to.value}`` placeholders in string params.

    This is intentionally a lookup-only substitution: no expressions, no eval,
    no attribute access.
    """
    if isinstance(value, str):
        if value.startswith("${") and value.endswith("}"):
            return _lookup(context, value[2:-1])
        pattern = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_.-]*)\}")

        def _replace(match: re.Match[str]) -> str:
            resolved = _lookup(context, match.group(1))
            return "" if resolved is None else str(resolved)

        return pattern.sub(_replace, value)
    if isinstance(value, dict):
        return {key: render_params(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [render_params(item, context) for item in value]
    return value


__all__ = [
    "INTERNAL_ACTIONS",
    "STEP_ACTIONS",
    "evaluate_condition",
    "render_params",
    "validate_context",
    "validate_definition",
]
