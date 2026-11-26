"""Defence domain helpers: kill-switch projection and rollback mapping."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.connectors import Connector
from app.models.core import KillSwitch
from app.services.actions import ACTIONS, FORBIDDEN_ACTIONS

# Only actions with an explicit, idempotent inverse may be rolled back.
ROLLBACK_ACTIONS: dict[str, str] = {
    "endpoint.isolate": "endpoint.unisolate",
    "identity.disable": "identity.enable",
    "ip.block": "ip.unblock",
}


def rollback_action_for(action_type: str) -> str | None:
    return ROLLBACK_ACTIONS.get(action_type)


def effective_kill_switches(db: Session, org_id: UUID) -> dict[str, Any]:
    """Project every engaged switch that can halt autonomy for the tenant."""
    rows = list(
        db.execute(
            select(KillSwitch)
            .where(
                KillSwitch.engaged.is_(True),
                or_(KillSwitch.org_id == org_id, KillSwitch.org_id.is_(None)),
            )
            .order_by(KillSwitch.engaged_at.desc())
        ).scalars()
    )
    connector_names: dict[str, str] = {}
    connector_ids = [row.target_id for row in rows if row.scope == "connector" and row.target_id]
    if connector_ids:
        for connector_id, name in db.execute(
            select(Connector.id, Connector.name).where(Connector.org_id == org_id)
        ).all():
            connector_names[str(connector_id)] = name

    entries = [
        {
            "id": row.id,
            "scope": row.scope,
            "target_id": row.target_id,
            "target_name": connector_names.get(row.target_id or ""),
            "reason": row.reason,
            "engaged_at": row.engaged_at,
        }
        for row in rows
    ]
    global_engaged = any(row["scope"] == "global" for row in entries)
    organization_engaged = any(row["scope"] == "organization" for row in entries)
    autonomy_engaged = any(row["scope"] == "autonomy" for row in entries)
    connectors = [row for row in entries if row["scope"] == "connector"]
    return {
        "org_id": org_id,
        "global_engaged": global_engaged,
        "organization_engaged": organization_engaged,
        "autonomy_engaged": autonomy_engaged,
        "autonomy_halted": global_engaged or organization_engaged or autonomy_engaged,
        "connectors": connectors,
        "switches": entries,
    }


def catalogue_payload(db: Session, org, decision_for) -> dict[str, Any]:  # type: ignore[no-untyped-def]
    actions = []
    for key in sorted(ACTIONS):
        definition = ACTIONS[key]
        decision = decision_for(key)
        actions.append(
            {
                "key": definition.key,
                "label": definition.label,
                "description": definition.description,
                "min_level": definition.min_level,
                "risk": definition.risk,
                "reversible": definition.reversible,
                "target_type": definition.target_type,
                "capability": definition.capability,
                "internal": definition.internal,
                "approval_required": definition.approval_required,
                "ot_allowed": definition.ot_allowed,
                "decision": decision.as_dict(),
            }
        )
    forbidden = [{"key": key, "reason": reason} for key, reason in sorted(FORBIDDEN_ACTIONS.items())]
    return {
        "actions": actions,
        "forbidden": forbidden,
        "org_max_level": org.autonomy_level,
    }


def connector_preview(db: Session, org_id: UUID, action_type: str) -> dict[str, Any] | None:
    """Best-effort connector projection for plan previews (never raises)."""
    definition = ACTIONS.get(action_type)
    if definition is None or definition.internal or not definition.capability:
        return None
    from app.services.connectors.runtime import select_connector

    try:
        connector = select_connector(db, org_id, definition.capability)
    except Exception:  # noqa: BLE001 - previews must not fail the request
        return None
    return {"id": str(connector.id), "name": connector.name, "capability": definition.capability}


__all__ = [
    "ROLLBACK_ACTIONS",
    "catalogue_payload",
    "connector_preview",
    "effective_kill_switches",
    "rollback_action_for",
]
