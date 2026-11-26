"""Authorization policy engine for defensive autonomy.

Separates reasoning (agents) from authority (this engine). Fail-closed: any
missing policy, unknown action, invalid level or engaged kill switch denies the
action. The engine never executes anything.

Deterministic autonomy guardrails (independent of the LLM) live here as pure
parsing plus read-only PostgreSQL evaluation. They are enforced by the broker
before any side effect and are also reflected in dry-run decisions.

Policy ``definition`` guardrail keys (all optional, validated strictly):

===========================  =======  ==========================================
key                          type     semantics
===========================  =======  ==========================================
max_actions_per_hour         int>=0   real executions per org in a rolling hour
max_actions_per_day          int>=0   real executions per org in a rolling 24h
cooldown_seconds             int>=0   minimum gap per action + target
change_freeze_windows        list     ``{start:"HH:MM", end:"HH:MM", days:[0-6]}``
max_blast_radius             int 1-5  ceiling for the action's blast radius
blast_radius                 object   per-action override ``{action: 1..5}``
denied_target_kinds          list     target types / asset kinds that are denied
allowed_target_kinds         list     when set, only these kinds are permitted
===========================  =======  ==========================================

Freeze windows are evaluated in UTC. ``start`` is inclusive and ``end`` is
exclusive; when ``start == end`` the window spans the whole day. When ``start``
is later than ``end`` the window wraps past midnight. ``days`` uses the ISO
weekday (0 = Monday ... 6 = Sunday); omitting it means every day.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, or_, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.models.assets import Asset
from app.models.core import AuditRecord, KillSwitch, Organization, Policy
from app.services.actions import ACTIONS, FORBIDDEN_ACTIONS, ActionDefinition, level_index

# Audit records emitted by the broker for a dispatched (real) action. Both the
# post-dispatch record and the connector-failure record count as one execution
# attempt so retry storms and failures consume the same budget.
EXECUTION_AUDIT_ACTIONS: tuple[str, ...] = ("defence.action.execute", "defence.action.failed")

DEFAULT_MAX_ACTIONS_PER_HOUR = 60
DEFAULT_MAX_ACTIONS_PER_DAY = 500
DEFAULT_COOLDOWN_SECONDS = 0
DEFAULT_MAX_BLAST_RADIUS = 5
MAX_BLAST_RADIUS_LEVEL = 5

# Blast radius is a 1..5 scale: 1 = read-only/enrichment, 2 = single indicator
# or scoped session, 3 = single identity, 4 = host or network segment, 5 =
# wide configuration change. Actions are code-owned; a policy may only lower the
# permitted ceiling or remap an action, never remove it from the catalogue.
BLAST_RADIUS_BY_ACTION: dict[str, int] = {
    "investigation.enrich": 1,
    "evidence.collect": 1,
    "incident.open": 1,
    "notify.webhook": 1,
    "session.revoke": 2,
    "ip.block": 2,
    "ip.unblock": 2,
    "identity.disable": 3,
    "identity.enable": 3,
    "endpoint.isolate": 4,
    "endpoint.unisolate": 4,
    "patch.apply": 4,
    "configuration.restore": 5,
}

_HHMM_RE = re.compile(r"^(?P<hour>[01]\d|2[0-3]):(?P<minute>[0-5]\d)$")


class PolicyDefinitionError(ValueError):
    """Raised when a policy declares an invalid or unsafe guardrail value."""


@dataclass(frozen=True)
class FreezeWindow:
    """One UTC change-freeze window, expressed in minutes since midnight."""

    start_minute: int
    end_minute: int
    days: frozenset[int] | None = None

    def contains(self, moment: datetime) -> bool:
        current = moment if moment.tzinfo is not None else moment.replace(tzinfo=UTC)
        current = current.astimezone(UTC)
        if self.days is not None and current.weekday() not in self.days:
            return False
        minute = current.hour * 60 + current.minute
        if self.start_minute == self.end_minute:
            return True
        if self.start_minute < self.end_minute:
            return self.start_minute <= minute < self.end_minute
        # Window crosses midnight, e.g. 22:00 -> 02:00.
        return minute >= self.start_minute or minute < self.end_minute

    def as_dict(self) -> dict[str, Any]:
        return {
            "start": _format_minute(self.start_minute),
            "end": _format_minute(self.end_minute),
            "days": sorted(self.days) if self.days is not None else None,
        }


@dataclass(frozen=True)
class GuardrailLimits:
    """Parsed, validated guardrail limits for one organization policy."""

    max_actions_per_hour: int = DEFAULT_MAX_ACTIONS_PER_HOUR
    max_actions_per_day: int = DEFAULT_MAX_ACTIONS_PER_DAY
    cooldown_seconds: int = DEFAULT_COOLDOWN_SECONDS
    change_freeze_windows: tuple[FreezeWindow, ...] = ()
    max_blast_radius: int = DEFAULT_MAX_BLAST_RADIUS
    blast_radius: dict[str, int] = field(default_factory=dict)
    denied_target_kinds: frozenset[str] = frozenset()
    allowed_target_kinds: frozenset[str] = frozenset()

    def blast_radius_for(self, action_key: str) -> int:
        return self.blast_radius.get(action_key, BLAST_RADIUS_BY_ACTION.get(action_key, MAX_BLAST_RADIUS_LEVEL))


@dataclass(frozen=True)
class GuardrailEvaluation:
    """Outcome of the deterministic runtime guardrail checks."""

    allowed: bool
    reason: str = ""
    code: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def as_constraints(self) -> dict[str, Any]:
        return {"guardrails": self.details} if self.details else {}


def _format_minute(minute: int) -> str:
    return f"{minute // 60:02d}:{minute % 60:02d}"


def _parse_hhmm(value: str) -> int:
    match = _HHMM_RE.match(value)
    if match is None:
        raise PolicyDefinitionError(f"Freeze window time '{value}' must use HH:MM (00:00-23:59)")
    return int(match.group("hour")) * 60 + int(match.group("minute"))


def _require_int(
    definition: dict[str, Any],
    key: str,
    default: int,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if key not in definition:
        return default
    value = definition[key]
    if isinstance(value, bool) or not isinstance(value, int):
        raise PolicyDefinitionError(f"{key} must be an integer")
    if value < minimum:
        raise PolicyDefinitionError(f"{key} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise PolicyDefinitionError(f"{key} must be <= {maximum}")
    return value


def _string_set(definition: dict[str, Any], key: str) -> frozenset[str]:
    if key not in definition:
        return frozenset()
    value = definition[key]
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise PolicyDefinitionError(f"{key} must be a list of non-empty strings")
    return frozenset(value)


def _freeze_windows(definition: dict[str, Any]) -> tuple[FreezeWindow, ...]:
    key = "change_freeze_windows"
    if key not in definition:
        return ()
    value = definition[key]
    if not isinstance(value, list):
        raise PolicyDefinitionError(f"{key} must be a list")
    windows: list[FreezeWindow] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise PolicyDefinitionError(f"{key}[{index}] must be an object")
        start = item.get("start")
        end = item.get("end")
        if not isinstance(start, str) or not isinstance(end, str):
            raise PolicyDefinitionError(f"{key}[{index}].start/end must be HH:MM strings")
        days_raw = item.get("days")
        days: frozenset[int] | None
        if days_raw is None:
            days = None
        elif isinstance(days_raw, list) and all(
            isinstance(day, int) and not isinstance(day, bool) and 0 <= day <= 6 for day in days_raw
        ):
            days = frozenset(days_raw)
        else:
            raise PolicyDefinitionError(f"{key}[{index}].days must be a list of weekday integers 0-6")
        windows.append(FreezeWindow(_parse_hhmm(start), _parse_hhmm(end), days))
    return tuple(windows)


def _blast_radius_overrides(definition: dict[str, Any]) -> dict[str, int]:
    key = "blast_radius"
    if key not in definition:
        return {}
    value = definition[key]
    if not isinstance(value, dict):
        raise PolicyDefinitionError(f"{key} must be an object mapping actions to levels")
    overrides: dict[str, int] = {}
    for action_key, level in value.items():
        if action_key not in ACTIONS:
            raise PolicyDefinitionError(f"{key} references unknown action '{action_key}'")
        if isinstance(level, bool) or not isinstance(level, int) or not 1 <= level <= MAX_BLAST_RADIUS_LEVEL:
            raise PolicyDefinitionError(f"{key}.{action_key} must be an integer between 1 and 5")
        overrides[action_key] = level
    return overrides


def parse_guardrail_limits(definition: dict[str, Any]) -> GuardrailLimits:
    """Validate the optional guardrail keys; raise on any malformed value.

    Defaults are conservative and never disable determinism: an operator opts in
    to stricter limits, while malformed declarations deny (fail-closed) instead
    of being silently ignored.
    """
    if not isinstance(definition, dict):
        raise PolicyDefinitionError("Policy definition must be a JSON object")
    return GuardrailLimits(
        max_actions_per_hour=_require_int(definition, "max_actions_per_hour", DEFAULT_MAX_ACTIONS_PER_HOUR),
        max_actions_per_day=_require_int(definition, "max_actions_per_day", DEFAULT_MAX_ACTIONS_PER_DAY),
        cooldown_seconds=_require_int(definition, "cooldown_seconds", DEFAULT_COOLDOWN_SECONDS),
        change_freeze_windows=_freeze_windows(definition),
        max_blast_radius=_require_int(
            definition,
            "max_blast_radius",
            DEFAULT_MAX_BLAST_RADIUS,
            minimum=1,
            maximum=MAX_BLAST_RADIUS_LEVEL,
        ),
        blast_radius=_blast_radius_overrides(definition),
        denied_target_kinds=_string_set(definition, "denied_target_kinds"),
        allowed_target_kinds=_string_set(definition, "allowed_target_kinds"),
    )


def _in_freeze_window(moment: datetime, windows: Iterable[FreezeWindow]) -> FreezeWindow | None:
    """Return the first active freeze window for ``moment`` (UTC), if any."""
    for window in windows:
        if window.contains(moment):
            return window
    return None


def _target_kinds(db: Session, org_id: UUID, target_type: str | None, target_id: str | None) -> set[str]:
    """Resolve the target kinds checked by ``denied/allowed_target_kinds``.

    The declared target type is always a kind. When the target id resolves to an
    organization asset, its ``kind`` (endpoint/ot/iot/...) is added so a policy
    that denies ``ot`` cannot be bypassed by labelling the target ``endpoint``.
    """
    kinds: set[str] = {target_type} if target_type else set()
    if not target_id:
        return kinds
    try:
        asset_uuid = UUID(str(target_id))
    except (ValueError, TypeError):
        return kinds
    asset = db.get(Asset, asset_uuid)
    if asset is not None and asset.org_id == org_id:
        kinds.add(asset.kind)
    return kinds


def _execution_count_since(db: Session, org_id: UUID, since: datetime) -> int:
    return int(
        db.execute(
            select(func.count())
            .select_from(AuditRecord)
            .where(
                AuditRecord.org_id == org_id,
                AuditRecord.action.in_(EXECUTION_AUDIT_ACTIONS),
                AuditRecord.created_at >= since,
            )
        ).scalar_one()
    )


def _last_execution_at(db: Session, org_id: UUID, action_key: str, target_id: str | None) -> datetime | None:
    stmt = select(func.max(AuditRecord.created_at)).where(
        AuditRecord.org_id == org_id,
        AuditRecord.action.in_(EXECUTION_AUDIT_ACTIONS),
        func.jsonb_extract_path_text(AuditRecord.payload, "action_type") == action_key,
    )
    if target_id is not None:
        stmt = stmt.where(func.jsonb_extract_path_text(AuditRecord.payload, "target_id") == str(target_id))
    last = db.execute(stmt).scalar_one_or_none()
    if last is None:
        return None
    return last if last.tzinfo is not None else last.replace(tzinfo=UTC)


def _acquire_guardrail_lock(db: Session, org_id: UUID) -> None:
    """Serialize guardrail evaluation per organization inside the transaction.

    Counting committed audit rows without a lock would let two concurrent
    executions both observe the last free slot. The transaction-scoped advisory
    lock makes the budget check race-free; it is released by the broker commit.
    """
    db.execute(
        text("SELECT pg_advisory_xact_lock(hashtext(:key))"),
        {"key": f"hispanshield:guardrails:{org_id}"},
    )


def evaluate_runtime_guardrails(
    db: Session,
    org_id: UUID,
    action: ActionDefinition,
    limits: GuardrailLimits,
    *,
    target_type: str | None = None,
    target_id: str | None = None,
    now: datetime | None = None,
    acquire_lock: bool = False,
) -> GuardrailEvaluation:
    """Run every deterministic guardrail; never raises on a policy verdict.

    Database errors propagate so the caller (broker) can deny and audit the
    failure instead of proceeding.
    """
    moment = now or utcnow()
    moment = moment.replace(tzinfo=UTC) if moment.tzinfo is None else moment.astimezone(UTC)

    if acquire_lock:
        _acquire_guardrail_lock(db, org_id)

    kinds = _target_kinds(db, org_id, target_type, target_id)
    denied_kinds = kinds & set(limits.denied_target_kinds)
    if denied_kinds:
        return GuardrailEvaluation(
            allowed=False,
            reason=f"Target kind is denied by policy: {', '.join(sorted(denied_kinds))}",
            code="target_kind_denied",
            details={
                "code": "target_kind_denied",
                "target_kinds": sorted(kinds),
                "denied_target_kinds": sorted(denied_kinds),
            },
        )
    if limits.allowed_target_kinds and not (kinds & set(limits.allowed_target_kinds)):
        return GuardrailEvaluation(
            allowed=False,
            reason="Target kind is not in the organization allow-list",
            code="target_kind_not_allowed",
            details={
                "code": "target_kind_not_allowed",
                "target_kinds": sorted(kinds),
                "allowed_target_kinds": sorted(limits.allowed_target_kinds),
            },
        )

    blast_radius = limits.blast_radius_for(action.key)
    if blast_radius > limits.max_blast_radius:
        return GuardrailEvaluation(
            allowed=False,
            reason=(f"Action blast radius {blast_radius} exceeds the policy maximum {limits.max_blast_radius}"),
            code="blast_radius_exceeded",
            details={
                "code": "blast_radius_exceeded",
                "action_blast_radius": blast_radius,
                "max_blast_radius": limits.max_blast_radius,
            },
        )

    window = _in_freeze_window(moment, limits.change_freeze_windows)
    if window is not None:
        return GuardrailEvaluation(
            allowed=False,
            reason="A change freeze window is active; state-changing actions are suspended",
            code="change_freeze",
            details={
                "code": "change_freeze",
                "window": window.as_dict(),
                "evaluated_at": moment.isoformat(),
            },
        )

    if limits.cooldown_seconds > 0:
        last = _last_execution_at(db, org_id, action.key, target_id)
        if last is not None:
            elapsed = (moment - last).total_seconds()
            if elapsed < limits.cooldown_seconds:
                retry_after = max(1, math.ceil(limits.cooldown_seconds - elapsed))
                return GuardrailEvaluation(
                    allowed=False,
                    reason=(f"Cooldown active for {action.key} on this target; retry in {retry_after}s"),
                    code="cooldown_active",
                    details={
                        "code": "cooldown_active",
                        "cooldown_seconds": limits.cooldown_seconds,
                        "retry_after_seconds": retry_after,
                    },
                )

    hour_count = _execution_count_since(db, org_id, moment - timedelta(hours=1))
    if hour_count >= limits.max_actions_per_hour:
        return GuardrailEvaluation(
            allowed=False,
            reason=(
                f"Hourly action budget exhausted ({hour_count}/{limits.max_actions_per_hour}); "
                "autonomy is suspended until the window rolls over"
            ),
            code="budget_hour_exhausted",
            details={
                "code": "budget_hour_exhausted",
                "executions_last_hour": hour_count,
                "max_actions_per_hour": limits.max_actions_per_hour,
            },
        )

    day_count = _execution_count_since(db, org_id, moment - timedelta(days=1))
    if day_count >= limits.max_actions_per_day:
        return GuardrailEvaluation(
            allowed=False,
            reason=(
                f"Daily action budget exhausted ({day_count}/{limits.max_actions_per_day}); "
                "autonomy is suspended until the window rolls over"
            ),
            code="budget_day_exhausted",
            details={
                "code": "budget_day_exhausted",
                "executions_last_day": day_count,
                "max_actions_per_day": limits.max_actions_per_day,
            },
        )

    return GuardrailEvaluation(
        allowed=True,
        details={
            "max_actions_per_hour": limits.max_actions_per_hour,
            "max_actions_per_day": limits.max_actions_per_day,
            "blast_radius": blast_radius,
        },
    )


def load_guardrail_limits(db: Session, org_id: UUID) -> GuardrailLimits:
    """Load and validate the active policy guardrails (raises on DB failure)."""
    policy = _active_policy(db, org_id)
    if policy is None:
        return GuardrailLimits()
    if not isinstance(policy.definition, dict):
        raise PolicyDefinitionError("Policy definition must be a JSON object")
    return parse_guardrail_limits(policy.definition)


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    action: ActionDefinition | None
    effective_level: str
    org_max_level: str
    requires_approval: bool
    approved: bool = False
    kill_switch_engaged: bool = False
    risk: str = "unknown"
    reversible: bool = False
    constraints: dict[str, Any] = field(default_factory=dict)
    policy_id: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "action": self.action.key if self.action else None,
            "effective_level": self.effective_level,
            "org_max_level": self.org_max_level,
            "requires_approval": self.requires_approval,
            "approved": self.approved,
            "kill_switch_engaged": self.kill_switch_engaged,
            "risk": self.risk,
            "reversible": self.reversible,
            "constraints": self.constraints,
            "policy_id": self.policy_id,
        }


def _active_policy(db: Session, org_id) -> Policy | None:  # type: ignore[no-untyped-def]
    return db.execute(
        select(Policy)
        .where(Policy.org_id == org_id, Policy.kind == "autonomy", Policy.enabled.is_(True))
        .order_by(Policy.version.desc())
        .limit(1)
    ).scalar_one_or_none()


def _engaged(db: Session, org_id, scope: str, target_id: str | None = None) -> bool:
    query = select(KillSwitch).where(KillSwitch.engaged.is_(True), KillSwitch.scope == scope)
    if scope == "global":
        query = query.where(KillSwitch.org_id.is_(None))
    else:
        query = query.where(or_(KillSwitch.org_id == org_id, KillSwitch.org_id.is_(None)))
    if target_id:
        query = query.where(KillSwitch.target_id == target_id)
    return db.execute(query.limit(1)).scalar_one_or_none() is not None


def evaluate(
    db: Session,
    org: Organization,
    action_type: str,
    *,
    target_type: str | None = None,
    target_id: str | None = None,
    requested_level: str | None = None,
    approved: bool = False,
    dry_run: bool = False,
    now: datetime | None = None,
) -> PolicyDecision:
    org_max = requested_level or org.autonomy_level
    action = ACTIONS.get(action_type)

    if action_type in FORBIDDEN_ACTIONS:
        return PolicyDecision(
            allowed=False,
            reason=f"Action class is forbidden: {FORBIDDEN_ACTIONS[action_type]}",
            action=None,
            effective_level="A4",
            org_max_level=org_max,
            requires_approval=True,
        )
    if action is None:
        return PolicyDecision(
            allowed=False,
            reason="Unknown action: only catalogue actions may be requested",
            action=None,
            effective_level="A4",
            org_max_level=org_max,
            requires_approval=True,
        )

    try:
        policy = _active_policy(db, org.id)
    except SQLAlchemyError:
        return PolicyDecision(
            allowed=False,
            reason="Autonomy policy storage is unavailable; denying by default (fail-closed)",
            action=action,
            effective_level=action.min_level,
            org_max_level=org_max,
            requires_approval=True,
            risk=action.risk,
            reversible=action.reversible,
            constraints={"policy_evaluation_failed": True},
        )
    if policy is not None and not isinstance(policy.definition, dict):
        return PolicyDecision(
            allowed=False,
            reason="Invalid autonomy policy definition: expected a JSON object; denying by default (fail-closed)",
            action=action,
            effective_level=action.min_level,
            org_max_level=org_max,
            requires_approval=True,
            risk=action.risk,
            reversible=action.reversible,
            policy_id=str(policy.id),
            constraints={"guardrail_error": "policy_definition_not_an_object"},
        )
    definition: dict[str, Any] = policy.definition if policy else {}
    policy_id = str(policy.id) if policy else None

    try:
        guardrail_limits = parse_guardrail_limits(definition)
    except PolicyDefinitionError as exc:
        return PolicyDecision(
            allowed=False,
            reason=f"Invalid autonomy policy guardrails: {exc}",
            action=action,
            effective_level=action.min_level,
            org_max_level=org_max,
            requires_approval=True,
            risk=action.risk,
            reversible=action.reversible,
            policy_id=policy_id,
            constraints={"guardrail_error": str(exc)},
        )

    policy_levels: dict[str, str] = definition.get("action_levels", {}) or {}
    denied_actions: list[str] = definition.get("denied_actions", []) or []
    allowed_actions: list[str] = definition.get("allowed_actions", []) or []
    approval_from = str(definition.get("require_approval_from", "A3"))

    constraints: dict[str, Any] = {
        "dry_run": dry_run,
        "target_type": target_type,
        "target_id": target_id,
        "policy_approval_threshold": approval_from,
    }

    effective_required = action.min_level
    if action_type in policy_levels:
        override = str(policy_levels[action_type])
        try:
            # Policy may raise the level; it may never lower the catalogue floor.
            if level_index(override) > level_index(effective_required):
                effective_required = override
            elif level_index(override) < level_index(action.min_level):
                effective_required = action.min_level
        except ValueError:
            return PolicyDecision(
                allowed=False,
                reason="Invalid autonomy level in policy definition",
                action=action,
                effective_level=action.min_level,
                org_max_level=org_max,
                requires_approval=True,
                policy_id=policy_id,
            )

    requires_approval = action.approval_required or level_index(effective_required) >= level_index(approval_from)

    if target_type and target_type != action.target_type:  # noqa: SIM102
        # Incident-scoped actions may target incidents; endpoints/identities are explicit.
        if not (action.target_type in {"incident", "integration"} or target_type in {"incident"}):
            return PolicyDecision(
                allowed=False,
                reason=f"Action expects target type '{action.target_type}', received '{target_type}'",
                action=action,
                effective_level=effective_required,
                org_max_level=org_max,
                requires_approval=requires_approval,
                policy_id=policy_id,
                constraints=constraints,
            )

    if action_type in denied_actions:
        return PolicyDecision(
            allowed=False,
            reason="Action is explicitly denied by organization policy",
            action=action,
            effective_level=effective_required,
            org_max_level=org_max,
            requires_approval=requires_approval,
            policy_id=policy_id,
            constraints=constraints,
        )
    if allowed_actions and action_type not in allowed_actions:
        return PolicyDecision(
            allowed=False,
            reason="Action is not in the organization allow-list",
            action=action,
            effective_level=effective_required,
            org_max_level=org_max,
            requires_approval=requires_approval,
            policy_id=policy_id,
            constraints=constraints,
        )

    # Kill switches: investigation (A0/A1) remains available; all autonomous or
    # state-changing actions (A2+) are blocked while a switch is engaged.
    if level_index(effective_required) >= level_index("A2"):
        for scope in ("global", "organization", "autonomy"):
            if _engaged(db, org.id, scope):
                return PolicyDecision(
                    allowed=False,
                    reason=f"Kill switch engaged ({scope}); cannot execute state-changing action",
                    action=action,
                    effective_level=effective_required,
                    org_max_level=org_max,
                    requires_approval=requires_approval,
                    kill_switch_engaged=True,
                    risk=action.risk,
                    reversible=action.reversible,
                    policy_id=policy_id,
                    constraints=constraints,
                )

    # OT safety: no automated state change against operational technology unless
    # a policy explicitly permits a catalogued, non-safety-critical action.
    if target_type == "asset" and target_id:
        try:
            from uuid import UUID

            asset = db.get(Asset, UUID(target_id))
        except (ValueError, TypeError):
            asset = None
        if asset is not None:
            constraints["asset_kind"] = asset.kind
            constraints["asset_criticality"] = asset.criticality
            constraints["asset_environment"] = asset.environment
            if asset.kind == "ot" and level_index(effective_required) >= level_index("A2"):
                allow_ot = bool(definition.get("allow_ot_automation", False))
                if not (allow_ot and action.ot_allowed):
                    return PolicyDecision(
                        allowed=False,
                        reason="OT assets are passive-monitor-only unless a policy explicitly authorizes a safe action",
                        action=action,
                        effective_level=effective_required,
                        org_max_level=org_max,
                        requires_approval=True,
                        risk=action.risk,
                        reversible=action.reversible,
                        policy_id=policy_id,
                        constraints=constraints,
                    )

    # Deterministic runtime guardrails (budget, cooldown, freeze, blast radius,
    # target kinds). Evaluated before any approval or execution side effect.
    try:
        guardrails = evaluate_runtime_guardrails(
            db,
            org.id,
            action,
            guardrail_limits,
            target_type=target_type,
            target_id=target_id,
            now=now,
        )
    except SQLAlchemyError:
        return PolicyDecision(
            allowed=False,
            reason="Autonomy guardrails could not be evaluated; denying by default (fail-closed)",
            action=action,
            effective_level=effective_required,
            org_max_level=org_max,
            requires_approval=True,
            risk=action.risk,
            reversible=action.reversible,
            policy_id=policy_id,
            constraints={**constraints, "guardrail_error": "policy_evaluation_failed"},
        )
    if not guardrails.allowed:
        return PolicyDecision(
            allowed=False,
            reason=guardrails.reason,
            action=action,
            effective_level=effective_required,
            org_max_level=org_max,
            requires_approval=requires_approval,
            risk=action.risk,
            reversible=action.reversible,
            policy_id=policy_id,
            constraints={**constraints, **guardrails.as_constraints()},
        )

    try:
        within_ceiling = level_index(effective_required) <= level_index(org_max)
    except ValueError:
        return PolicyDecision(
            allowed=False,
            reason="Invalid organization autonomy level",
            action=action,
            effective_level=effective_required,
            org_max_level=org_max,
            requires_approval=True,
            policy_id=policy_id,
        )
    if not within_ceiling:
        return PolicyDecision(
            allowed=False,
            reason=(
                f"Action requires {effective_required} but organization ceiling is {org_max}; "
                "an administrator must raise the autonomy level explicitly"
            ),
            action=action,
            effective_level=effective_required,
            org_max_level=org_max,
            requires_approval=True,
            risk=action.risk,
            reversible=action.reversible,
            policy_id=policy_id,
            constraints=constraints,
        )

    if requires_approval and not approved:
        return PolicyDecision(
            allowed=False,
            reason="Human approval is required before execution",
            action=action,
            effective_level=effective_required,
            org_max_level=org_max,
            requires_approval=True,
            approved=False,
            risk=action.risk,
            reversible=action.reversible,
            policy_id=policy_id,
            constraints=constraints,
        )

    return PolicyDecision(
        allowed=True,
        reason="Authorized by policy",
        action=action,
        effective_level=effective_required,
        org_max_level=org_max,
        requires_approval=requires_approval,
        approved=approved,
        risk=action.risk,
        reversible=action.reversible,
        policy_id=policy_id,
        constraints=constraints,
    )


def active_policy_snapshot(db: Session, org_id) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    policy = _active_policy(db, org_id)
    return {
        "policy_id": str(policy.id) if policy else None,
        "version": policy.version if policy else None,
        "definition": policy.definition if policy else {},
        "evaluated_at": utcnow().isoformat(),
    }
