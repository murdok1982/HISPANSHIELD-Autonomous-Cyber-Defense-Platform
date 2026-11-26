"""Execution broker: the only path from an authorized decision to a live action.

Agents and playbooks cannot call connectors directly for state-changing actions.
The broker re-evaluates policy at execution time, verifies approvals, enforces
connection-scoped kill switches, executes through an adapter and records the
result. It never trusts the requester's assessment of authorization.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from time import perf_counter
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from app.core.audit import append_audit
from app.core.crypto import sha256_hex
from app.core.db import utcnow
from app.core.errors import Forbidden, PolicyDenied, ServiceUnavailable
from app.models.core import Approval, KillSwitch, Organization
from app.models.incidents import Remediation
from app.services.actions import ActionDefinition, get_action
from app.services.connectors.base import AdapterResult, ConnectorError, record_connector_run
from app.services.connectors.runtime import (
    circuit_breaker,
    instantiate_adapter,
    select_connector,
)
from app.services.policy_engine import (
    GuardrailEvaluation,
    PolicyDecision,
    PolicyDefinitionError,
    active_policy_snapshot,
    evaluate,
    evaluate_runtime_guardrails,
    load_guardrail_limits,
)


def canonical_parameters_hash(parameters: dict[str, Any] | None) -> str:
    """Stable hash of an action's parameters, used to bind approvals."""
    encoded = json.dumps(parameters or {}, sort_keys=True, separators=(",", ":"), default=str)
    return sha256_hex(encoded)


@dataclass
class BrokerActor:
    id: str | None
    email: str | None
    ip: str | None = None
    request_id: str | None = None
    user_id: UUID | None = None

    @classmethod
    def from_context(cls, ctx) -> BrokerActor:  # type: ignore[no-untyped-def]
        return cls(
            id=ctx.actor_id,
            email=ctx.actor_email,
            ip=ctx.ip_address,
            request_id=ctx.request_id,
            user_id=ctx.user.id if ctx.user else None,
        )


@dataclass
class BrokerResult:
    action_type: str
    status: str
    decision: PolicyDecision
    connector_id: str | None = None
    output: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    latency_ms: int = 0
    verified: bool = False
    dry_run: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "status": self.status,
            "decision": self.decision.as_dict(),
            "connector_id": self.connector_id,
            "output": self.output,
            "error": self.error,
            "latency_ms": self.latency_ms,
            "verified": self.verified,
            "dry_run": self.dry_run,
        }


def _validate_approval(
    db: Session,
    org: Organization,
    approval_id: UUID | None,
    action_type: str,
    target_type: str,
    target_id: str,
    parameters: dict[str, Any] | None,
) -> Approval | None:
    if approval_id is None:
        return None
    approval = db.execute(select(Approval).where(Approval.id == approval_id).with_for_update()).scalar_one_or_none()
    if approval is None or approval.org_id != org.id:
        raise PolicyDenied("Approval does not exist in this organization")
    if approval.status != "approved":
        raise PolicyDenied("Approval is not in an approved state")
    if approval.expires_at and approval.expires_at < utcnow():
        raise PolicyDenied("Approval has expired")
    payload = approval.payload or {}
    if payload.get("action_type") and payload.get("action_type") != action_type:
        raise PolicyDenied("Approval was granted for a different action type")
    if payload.get("target_type") and payload.get("target_type") != target_type:
        raise PolicyDenied("Approval was granted for a different target type")
    if payload.get("target_id") and str(payload.get("target_id")) != str(target_id):
        raise PolicyDenied("Approval was granted for a different target")
    bound_parameters = payload.get("parameters_hash")
    if bound_parameters and str(bound_parameters) != canonical_parameters_hash(parameters):
        raise PolicyDenied("Approval was granted for different action parameters")
    bound_policy = payload.get("policy_version")
    if bound_policy is not None:
        current_policy = active_policy_snapshot(db, org.id).get("version")
        if current_policy != bound_policy:
            raise PolicyDenied("The autonomy policy changed after this approval was granted")
    if approval.consumed_at is not None:
        raise PolicyDenied("Approval has already been consumed")
    # Single-use approval: consume it under the row lock before any side effect.
    # A failure still consumes it, so the operator must request a fresh approval.
    approval.consumed_at = utcnow()
    db.flush()
    return approval


def _check_connector_kill_switch(db: Session, org_id, connector_id) -> None:  # type: ignore[no-untyped-def]
    switch = db.execute(
        select(KillSwitch).where(
            KillSwitch.engaged.is_(True),
            KillSwitch.scope == "connector",
            KillSwitch.target_id == str(connector_id),
        )
    ).scalar_one_or_none()
    if switch is not None:
        raise PolicyDenied("A kill switch is engaged for this connector")


def _audit_guardrail_denial(
    db: Session,
    *,
    org: Organization,
    actor: BrokerActor,
    action_type: str,
    target_type: str,
    target_id: str,
    guardrail: GuardrailEvaluation,
) -> None:
    try:
        append_audit(
            db,
            org_id=org.id,
            action="defence.guardrail.denied",
            resource_type="remediation",
            resource_id=target_id[:80],
            actor_type="user" if actor.user_id else "system",
            actor_id=actor.id,
            actor_email=actor.email,
            outcome="failure",
            payload={
                "action_type": action_type,
                "target_type": target_type,
                "target_id": target_id,
                "guardrail_code": guardrail.code,
                "reason": guardrail.reason[:500],
                "details": guardrail.details,
            },
            request_id=actor.request_id,
            ip_address=actor.ip,
        )
        db.flush()
    except SQLAlchemyError:
        # A denied action must never be upgraded because auditing failed.
        db.rollback()


def _audit_policy_error(
    db: Session,
    *,
    org: Organization,
    actor: BrokerActor,
    action_type: str,
    error: str,
) -> None:
    try:
        append_audit(
            db,
            org_id=org.id,
            action="defence.policy.error",
            resource_type="policy",
            resource_id=None,
            actor_type="user" if actor.user_id else "system",
            actor_id=actor.id,
            actor_email=actor.email,
            outcome="failure",
            payload={"action_type": action_type, "error": error[:500]},
            request_id=actor.request_id,
            ip_address=actor.ip,
        )
        db.flush()
    except SQLAlchemyError:
        # Fail-closed: the caller still denies even when the audit write fails.
        db.rollback()


def _enforce_guardrails(
    db: Session,
    *,
    org: Organization,
    actor: BrokerActor,
    action_type: str,
    action: ActionDefinition,
    target_type: str,
    target_id: str,
    requested_level: str | None,
    dry_run: bool,
) -> None:
    """Deny before any side effect when a deterministic guardrail blocks the action.

    Runs ahead of approval validation and connector selection so a denied action
    cannot consume an approval, mark a remediation or reach a target system.
    """
    try:
        limits = load_guardrail_limits(db, org.id)
        guardrail = evaluate_runtime_guardrails(
            db,
            org.id,
            action,
            limits,
            target_type=target_type,
            target_id=target_id,
            acquire_lock=True,
        )
    except PolicyDefinitionError as exc:
        _audit_policy_error(db, org=org, actor=actor, action_type=action_type, error=str(exc))
        decision = evaluate(
            db,
            org,
            action_type,
            target_type=target_type,
            target_id=target_id,
            requested_level=requested_level,
            approved=True,
            dry_run=dry_run,
        )
        raise PolicyDenied(decision.reason, details=[decision.as_dict()]) from exc
    except SQLAlchemyError as exc:
        _audit_policy_error(
            db,
            org=org,
            actor=actor,
            action_type=action_type,
            error="policy storage failure while loading guardrails",
        )
        decision = evaluate(
            db,
            org,
            action_type,
            target_type=target_type,
            target_id=target_id,
            requested_level=requested_level,
            approved=True,
            dry_run=dry_run,
        )
        raise PolicyDenied(decision.reason, details=[decision.as_dict()]) from exc

    if guardrail.allowed:
        return

    _audit_guardrail_denial(
        db,
        org=org,
        actor=actor,
        action_type=action_type,
        target_type=target_type,
        target_id=target_id,
        guardrail=guardrail,
    )
    decision = evaluate(
        db,
        org,
        action_type,
        target_type=target_type,
        target_id=target_id,
        requested_level=requested_level,
        approved=True,
        dry_run=dry_run,
    )
    raise PolicyDenied(decision.reason, details=[decision.as_dict()])


def execute_action(
    db: Session,
    *,
    org: Organization,
    actor: BrokerActor,
    action_type: str,
    target_type: str,
    target_id: str,
    parameters: dict[str, Any] | None = None,
    incident_id: UUID | None = None,
    approval_id: UUID | None = None,
    connector_id: UUID | None = None,
    requested_level: str | None = None,
    dry_run: bool = False,
    remediation: Remediation | None = None,
) -> BrokerResult:
    action = get_action(action_type)
    if action is None:
        raise PolicyDenied("Unknown action; only catalogue actions can be executed")
    if action.internal:
        raise PolicyDenied("Internal actions are executed by their owning domain, not the connector broker")

    _enforce_guardrails(
        db,
        org=org,
        actor=actor,
        action_type=action_type,
        action=action,
        target_type=target_type,
        target_id=target_id,
        requested_level=requested_level,
        dry_run=dry_run,
    )

    approval = _validate_approval(db, org, approval_id, action_type, target_type, target_id, parameters)
    decision = evaluate(
        db,
        org,
        action_type,
        target_type=target_type,
        target_id=target_id,
        requested_level=requested_level,
        approved=approval is not None,
        dry_run=dry_run,
    )
    if not decision.allowed:
        raise PolicyDenied(decision.reason, details=[decision.as_dict()])

    capability = action.capability
    assert capability is not None
    connector = select_connector(db, org.id, capability, connector_id=connector_id)
    _check_connector_kill_switch(db, org.id, connector.id)

    adapter = instantiate_adapter(connector)
    breaker_key = f"connector:{connector.id}"
    circuit_breaker.check(breaker_key)

    if dry_run:
        return BrokerResult(
            action_type=action_type,
            status="simulated",
            decision=decision,
            connector_id=str(connector.id),
            output={
                "plan": {
                    "capability": capability,
                    "connector": connector.name,
                    "target_type": target_type,
                    "target_id": target_id,
                    "parameters": parameters or {},
                },
                "note": "Simulation only; no request was sent to the target system",
            },
            verified=True,
            dry_run=True,
        )

    started = perf_counter()
    try:
        result: AdapterResult = adapter.invoke(capability, parameters or {})
    except ConnectorError as exc:
        latency = int((perf_counter() - started) * 1000)
        circuit_breaker.record_failure(breaker_key)
        record_connector_run(
            db,
            connector,
            operation=capability,
            direction="write",
            status="failed",
            latency_ms=latency,
            error=str(exc),
            detail={"action_type": action_type, "target_id": target_id},
            request_id=actor.request_id,
        )
        connector.status = "degraded"
        if remediation is not None:
            remediation.status = "failed"
            remediation.executed_at = utcnow()
        append_audit(
            db,
            org_id=org.id,
            action="defence.action.failed",
            resource_type="remediation",
            resource_id=str(remediation.id) if remediation else target_id,
            actor_type="user" if actor.user_id else "system",
            actor_id=actor.id,
            actor_email=actor.email,
            outcome="failure",
            payload={
                "action_type": action_type,
                "connector": connector.name,
                "target": target_id,
                "error": str(exc)[:500],
            },
            request_id=actor.request_id,
            ip_address=actor.ip,
        )
        db.commit()
        raise ServiceUnavailable("The connector action failed; see the connector audit log") from exc

    latency = int((perf_counter() - started) * 1000)
    circuit_breaker.record_success(breaker_key)

    verified = False
    verification: dict[str, Any] = {}
    if result.ok:
        try:
            verification_result = adapter.verify(capability, parameters or {}, result)
            verified = verification_result.ok
            verification = verification_result.data
        except ConnectorError as exc:
            verification = {"verified": False, "error": str(exc)[:500]}

    record_connector_run(
        db,
        connector,
        operation=capability,
        direction="write",
        status="success" if result.ok else "failed",
        latency_ms=latency,
        error=result.error,
        detail={
            "action_type": action_type,
            "target_type": target_type,
            "target_id": target_id,
            "external_id": result.external_id,
            "verified": verified,
        },
        request_id=actor.request_id,
    )
    connector.status = "healthy" if result.ok else "degraded"

    if remediation is not None:
        remediation.status = "executed" if result.ok else "failed"
        remediation.executed_at = utcnow()
        remediation.executed_by = actor.email or actor.id
        remediation.verification = verification
        remediation.verified_at = utcnow() if verified else None
        remediation.authorization_id = approval.id if approval else remediation.authorization_id

    append_audit(
        db,
        org_id=org.id,
        action="defence.action.execute",
        resource_type="remediation",
        resource_id=str(remediation.id) if remediation else target_id,
        actor_type="user" if actor.user_id else "system",
        actor_id=actor.id,
        actor_email=actor.email,
        outcome="success" if result.ok else "failure",
        payload={
            "action_type": action_type,
            "connector": connector.name,
            "target_type": target_type,
            "target_id": target_id,
            "approval_id": str(approval.id) if approval else None,
            "verified": verified,
            "dry_run": False,
        },
        request_id=actor.request_id,
        ip_address=actor.ip,
    )
    db.commit()

    return BrokerResult(
        action_type=action_type,
        status="executed" if result.ok else "failed",
        decision=decision,
        connector_id=str(connector.id),
        output=result.data,
        error=result.error,
        latency_ms=latency,
        verified=verified,
    )


def rollback_action(
    db: Session,
    *,
    org: Organization,
    actor: BrokerActor,
    remediation: Remediation,
    rollback_action_type: str,
    parameters: dict[str, Any] | None = None,
    connector_id: UUID | None = None,
) -> BrokerResult:
    if remediation.org_id != org.id:
        raise Forbidden("Remediation belongs to a different organization")
    if remediation.status not in {"executed"}:
        raise PolicyDenied("Only executed remediations can be rolled back")
    result = execute_action(
        db,
        org=org,
        actor=actor,
        action_type=rollback_action_type,
        target_type=remediation.target_type,
        target_id=remediation.target_id,
        parameters=parameters or remediation.parameters,
        incident_id=remediation.incident_id,
        connector_id=connector_id,
        remediation=None,
    )
    remediation.rollback_status = "success" if result.status == "executed" else "failed"
    remediation.rollback_output = result.output
    append_audit(
        db,
        org_id=org.id,
        action="defence.action.rollback",
        resource_type="remediation",
        resource_id=str(remediation.id),
        actor_id=actor.id,
        actor_email=actor.email,
        outcome="success" if result.status == "executed" else "failure",
        payload={"rollback_action": rollback_action_type, "target": remediation.target_id},
        request_id=actor.request_id,
        ip_address=actor.ip,
    )
    db.commit()
    return result


__all__ = ["BrokerActor", "BrokerResult", "execute_action", "rollback_action"]
