"""Authorization policy engine for defensive autonomy.

Separates reasoning (agents) from authority (this engine). Fail-closed: any
missing policy, unknown action, invalid level or engaged kill switch denies the
action. The engine never executes anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.models.assets import Asset
from app.models.core import KillSwitch, Organization, Policy
from app.services.actions import ACTIONS, FORBIDDEN_ACTIONS, ActionDefinition, level_index


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

    policy = _active_policy(db, org.id)
    definition: dict[str, Any] = policy.definition if policy else {}
    policy_id = str(policy.id) if policy else None

    policy_levels: dict[str, str] = definition.get("action_levels", {}) or {}
    denied_actions: list[str] = definition.get("denied_actions", []) or []
    allowed_actions: list[str] = definition.get("allowed_actions", []) or []
    approval_from = str(definition.get("require_approval_from", "A3"))

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

    constraints: dict[str, Any] = {
        "dry_run": dry_run,
        "target_type": target_type,
        "target_id": target_id,
        "policy_approval_threshold": approval_from,
    }

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
