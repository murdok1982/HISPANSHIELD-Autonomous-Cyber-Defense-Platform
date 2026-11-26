"""Durable SOAR playbook engine.

Execution state lives entirely in PostgreSQL (``playbook_executions`` and
``playbook_steps``), so an interrupted worker can resume by re-reading the
persisted step rows. Step identity is ``step_key``; a step that already
succeeded is never executed twice. State-changing actions are never dispatched
directly: ``defence.execute`` always goes through
``app.services.broker.execute_action`` which re-evaluates policy, approvals and
kill switches at execution time.

Failure semantics:
* ``continue`` - mark the step failed and keep going.
* ``abort`` / ``compensate`` - run declared compensations in reverse order for
  every previously succeeded step, then stop the execution.
"""

from __future__ import annotations

import json
import random
import time
from datetime import timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import append_audit
from app.core.db import utcnow
from app.core.errors import (
    Conflict,
    Forbidden,
    NotFound,
    PolicyDenied,
    ServiceUnavailable,
    ValidationFailure,
)
from app.models.assets import Asset
from app.models.core import Approval, Notification, Organization
from app.models.events import Alert, SecurityEvent
from app.models.incidents import Incident, Playbook, PlaybookExecution, PlaybookStep, Remediation
from app.modules.defence.service import ot_asset_violation
from app.modules.incidents.service import (
    add_timeline_entry,
    create_incident_core,
    normalize_severity,
    parse_uuid,
)
from app.modules.soar.validation import evaluate_condition, render_params, validate_context
from app.services.actions import get_action, level_index
from app.services.broker import BrokerActor, execute_action
from app.services.connectors.base import (
    READ,
    AdapterResult,
    ConnectorError,
    record_connector_run,
)
from app.services.connectors.runtime import circuit_breaker, instantiate_adapter, select_connector
from app.services.policy_engine import evaluate

FINAL_STATUSES = {"succeeded", "completed_with_errors", "failed", "compensated", "denied", "simulated", "cancelled"}
_WRITE_ACTIONS = {"defence.execute"}
_DEFAULT_APPROVAL_TTL = 86_400


def _bounded(value: Any, limit: int = 50_000) -> dict[str, Any]:
    """Return a JSON-safe, size-bounded copy of an output payload."""
    try:
        text = json.dumps(value, default=str, sort_keys=True)
    except (TypeError, ValueError):
        return {"repr": str(value)[:limit]}
    if len(text) > limit:
        return {"truncated": True, "preview": text[:limit]}
    parsed = json.loads(text)
    return parsed if isinstance(parsed, dict) else {"value": parsed}


def _audit(
    db: Session,
    *,
    org_id: UUID,
    actor: BrokerActor,
    action: str,
    resource_type: str,
    resource_id: str,
    outcome: str = "success",
    payload: dict[str, Any] | None = None,
) -> None:
    append_audit(
        db,
        org_id=org_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        actor_type="user" if actor.user_id else "system",
        actor_id=actor.id,
        actor_email=actor.email,
        outcome=outcome,
        payload=payload or {},
        request_id=actor.request_id,
        ip_address=actor.ip,
    )


def ordered_steps(db: Session, execution_id: UUID) -> list[PlaybookStep]:
    """Steps have no ordinal column; the position is persisted in ``input``."""
    steps = list(db.execute(select(PlaybookStep).where(PlaybookStep.execution_id == execution_id)).scalars())
    steps.sort(key=lambda item: (int(item.input.get("position", 0)), item.step_key))
    return steps


def _environment(execution: PlaybookExecution, steps: list[PlaybookStep]) -> dict[str, Any]:
    context = execution.context or {}
    env: dict[str, Any] = {**context}
    env["context"] = context
    env["steps"] = {step.step_key: (step.output or {}) for step in steps}
    env["execution"] = {
        "id": str(execution.id),
        "playbook_id": str(execution.playbook_id),
        "incident_id": str(execution.incident_id) if execution.incident_id else None,
        "dry_run": execution.dry_run,
        "autonomy_level": execution.autonomy_level,
    }
    return env


def create_execution(
    db: Session,
    *,
    org: Organization,
    playbook: Playbook,
    actor: BrokerActor,
    trigger: str,
    context: dict[str, Any] | None = None,
    incident_id: UUID | None = None,
    dry_run: bool = False,
    requested_level: str | None = None,
) -> PlaybookExecution:
    context = validate_context(context or {})
    requested = requested_level or org.autonomy_level
    if level_index(requested) > level_index(org.autonomy_level):
        raise PolicyDenied(
            f"Requested autonomy level {requested} exceeds the organization ceiling {org.autonomy_level}"
        )
    if level_index(playbook.min_autonomy_level) > level_index(org.autonomy_level):
        raise PolicyDenied(
            f"Playbook requires {playbook.min_autonomy_level} but the organization ceiling is {org.autonomy_level}"
        )

    definition = playbook.definition or {}
    steps_definition = definition.get("steps") or []
    if not steps_definition:
        raise ValidationFailure([{"field": "definition.steps", "message": "The playbook has no executable steps"}])

    execution = PlaybookExecution(
        org_id=org.id,
        playbook_id=playbook.id,
        incident_id=incident_id,
        status="pending",
        trigger=trigger[:80],
        context=context,
        autonomy_level=requested,
        dry_run=dry_run,
        requested_by=(actor.email or actor.id or "system")[:64],
    )
    db.add(execution)
    db.flush()

    for position, step_definition in enumerate(steps_definition):
        db.add(
            PlaybookStep(
                execution_id=execution.id,
                step_key=str(step_definition.get("key", f"step-{position}"))[:80],
                name=str(step_definition.get("name", "Step"))[:200],
                status="pending",
                attempts=0,
                input={
                    "position": position,
                    "name": step_definition.get("name"),
                    "action": step_definition.get("action"),
                    "params": step_definition.get("params") or {},
                    "condition": step_definition.get("condition"),
                    "on_failure": step_definition.get("on_failure", "abort"),
                    "retries": step_definition.get("retries", 0),
                    "timeout_seconds": step_definition.get("timeout_seconds", 60),
                    "compensation": step_definition.get("compensation"),
                },
                output={},
                compensation_output={},
            )
        )
    db.flush()
    _audit(
        db,
        org_id=org.id,
        actor=actor,
        action="playbook.execution.created",
        resource_type="playbook_execution",
        resource_id=str(execution.id),
        payload={
            "playbook_id": str(playbook.id),
            "version": playbook.version,
            "trigger": trigger,
            "dry_run": dry_run,
            "incident_id": str(incident_id) if incident_id else None,
        },
    )
    db.commit()
    db.refresh(execution)
    return execution


def _resolve_incident(
    db: Session, execution: PlaybookExecution, org_id: UUID, params: dict[str, Any]
) -> Incident | None:
    candidate = params.get("incident_id") or execution.incident_id
    if not candidate:
        candidate = (execution.context or {}).get("incident_id")
    incident_uuid = parse_uuid(str(candidate)) if candidate else None
    if incident_uuid is None:
        return None
    incident = db.get(Incident, incident_uuid)
    if incident is None or incident.org_id != org_id:
        return None
    return incident


def _investigate(db: Session, org: Organization, execution: PlaybookExecution) -> dict[str, Any]:
    incident = _resolve_incident(db, execution, org.id, {})
    if incident is not None:
        alert_rows = list(
            db.execute(select(Alert).where(Alert.org_id == org.id, Alert.incident_id == incident.id)).scalars()
        )
        event_ids: list[int] = []
        for row in alert_rows:
            for event_id in (row.event_ids or [])[:200]:
                if isinstance(event_id, int) and event_id not in event_ids:
                    event_ids.append(event_id)
        assets = list(
            db.execute(
                select(Asset).where(
                    Asset.org_id == org.id,
                    Asset.id.in_(
                        [uuid for uuid in (parse_uuid(value) for value in incident.affected_asset_ids) if uuid]
                    ),
                )
            ).scalars()
        )
        return {
            "scope": "incident",
            "incident_id": str(incident.id),
            "ref": incident.ref,
            "severity": incident.severity,
            "status": incident.status,
            "alerts": len(alert_rows),
            "related_event_ids": event_ids[:200],
            "assets": [{"id": str(asset.id), "name": asset.name, "kind": asset.kind} for asset in assets],
            "mitre": incident.mitre,
        }
    since = utcnow() - timedelta(hours=24)
    return {
        "scope": "organization",
        "alerts_24h": db.execute(
            select(func.count()).select_from(Alert).where(Alert.org_id == org.id, Alert.created_at >= since)
        ).scalar_one(),
        "events_24h": db.execute(
            select(func.count())
            .select_from(SecurityEvent)
            .where(SecurityEvent.org_id == org.id, SecurityEvent.occurred_at >= since)
        ).scalar_one(),
        "assets": db.execute(select(func.count()).select_from(Asset).where(Asset.org_id == org.id)).scalar_one(),
    }


def _create_incident(
    db: Session, org: Organization, execution: PlaybookExecution, actor: BrokerActor, params: dict[str, Any]
) -> dict[str, Any]:
    existing = _resolve_incident(db, execution, org.id, params)
    if existing is not None:
        execution.incident_id = existing.id
        return {"incident_id": str(existing.id), "ref": existing.ref, "reused": True}

    playbook = db.get(Playbook, execution.playbook_id)
    title = str(params.get("title") or (playbook.name if playbook else "Playbook escalation"))[:300]
    alert = (execution.context or {}).get("alert") if isinstance(execution.context, dict) else None
    severity = params.get("severity") or (alert.get("severity") if isinstance(alert, dict) else None) or "medium"
    severity = normalize_severity(str(severity))
    asset_ids: list[str] = []
    for candidate in params.get("affected_asset_ids") or []:
        asset_uuid = parse_uuid(str(candidate))
        if (
            asset_uuid
            and db.execute(select(Asset.id).where(Asset.id == asset_uuid, Asset.org_id == org.id)).scalar_one_or_none()
        ):
            asset_ids.append(str(asset_uuid))
    incident = create_incident_core(
        db,
        org,
        title=title,
        severity=severity,
        description=params.get("description"),
        priority=params.get("priority") if isinstance(params.get("priority"), int) else None,
        affected_asset_ids=asset_ids,
        created_by=actor.id,
        actor=actor.email or actor.id,
    )
    execution.incident_id = incident.id
    return {"incident_id": str(incident.id), "ref": incident.ref, "reused": False}


def _add_timeline(
    db: Session,
    org: Organization,
    execution: PlaybookExecution,
    actor: BrokerActor,
    params: dict[str, Any],
) -> dict[str, Any]:
    incident = _resolve_incident(db, execution, org.id, params)
    if incident is None:
        raise ValidationFailure(
            [{"field": "incident_id", "message": "internal.add_timeline requires an incident in scope"}]
        )
    summary = str(params.get("summary") or "Playbook step executed")[:500]
    entry = add_timeline_entry(
        db,
        incident,
        kind=str(params.get("kind") or "playbook")[:30],
        summary=summary,
        actor=(actor.email or actor.id or "system:playbook")[:200],
        detail=params.get("detail") or {},
    )
    return {"incident_id": str(incident.id), "timeline_id": str(entry.id), "summary": summary}


def _notify(
    db: Session,
    org: Organization,
    execution: PlaybookExecution,
    actor: BrokerActor,
    params: dict[str, Any],
) -> dict[str, Any]:
    title = str(params.get("title") or "Playbook notification")[:240]
    body = params.get("body")
    user_id = parse_uuid(str(params.get("user_id"))) if params.get("user_id") else None
    notification = Notification(
        org_id=org.id,
        user_id=user_id,
        kind=str(params.get("kind") or "playbook")[:40],
        title=title,
        body=body,
        resource_type="incident" if execution.incident_id else "playbook_execution",
        resource_id=str(execution.incident_id or execution.id),
    )
    db.add(notification)
    db.flush()
    output: dict[str, Any] = {"notification_id": str(notification.id)}
    if params.get("webhook"):
        connector_id = parse_uuid(str(params.get("connector_id"))) if params.get("connector_id") else None
        from app.services.broker import execute_action as broker_execute

        result = broker_execute(
            db,
            org=org,
            actor=actor,
            action_type="notify.webhook",
            target_type="integration",
            target_id=str(params.get("target_id") or "webhook"),
            parameters={"title": title, "body": body or "", "incident_id": str(execution.incident_id or "")},
            incident_id=execution.incident_id,
            connector_id=connector_id,
        )
        output["webhook"] = result.as_dict()
    return output


def _connector_read(
    db: Session,
    org: Organization,
    execution: PlaybookExecution,
    step: PlaybookStep,
    actor: BrokerActor,
    params: dict[str, Any],
) -> dict[str, Any]:
    capability = params.get("capability")
    if not isinstance(capability, str) or not capability:
        raise ValidationFailure([{"field": "capability", "message": "connector.read requires a capability"}])
    connector_id = parse_uuid(str(params.get("connector_id"))) if params.get("connector_id") else None
    connector = select_connector(db, org.id, capability, connector_id=connector_id)
    adapter = instantiate_adapter(connector)
    spec = next((item for item in adapter.capabilities if item.name == capability), None)
    if spec is None:
        raise ValidationFailure([{"field": "capability", "message": "The connector does not declare this capability"}])
    if spec.direction != READ:
        raise Forbidden("connector.read can only invoke read-only capabilities")

    breaker_key = f"connector:{connector.id}"
    circuit_breaker.check(breaker_key)
    started = time.perf_counter()
    try:
        result: AdapterResult = adapter.invoke(capability, params.get("params") or {})
    except ConnectorError as exc:
        latency = int((time.perf_counter() - started) * 1000)
        circuit_breaker.record_failure(breaker_key)
        record_connector_run(
            db,
            connector,
            operation=capability,
            direction="read",
            status="failed",
            latency_ms=latency,
            error=str(exc),
            detail={"step_key": step.step_key, "playbook_execution_id": str(execution.id)},
            request_id=actor.request_id,
        )
        db.commit()
        raise
    latency = int((time.perf_counter() - started) * 1000)
    circuit_breaker.record_success(breaker_key)
    record_connector_run(
        db,
        connector,
        operation=capability,
        direction="read",
        status="success",
        latency_ms=latency,
        detail={"step_key": step.step_key, "playbook_execution_id": str(execution.id)},
        request_id=actor.request_id,
    )
    db.commit()
    return {
        "connector_id": str(connector.id),
        "connector": connector.name,
        "capability": capability,
        "data": result.data,
        "latency_ms": latency,
    }


def _defence_execute(
    db: Session,
    org: Organization,
    execution: PlaybookExecution,
    step: PlaybookStep,
    actor: BrokerActor,
    params: dict[str, Any],
    last_approval_id: UUID | None,
) -> dict[str, Any]:
    action_type = params.get("action_type")
    action = get_action(str(action_type)) if isinstance(action_type, str) else None
    if action is None or action.internal:
        raise ValidationFailure([{"field": "action_type", "message": "defence.execute requires a catalogue action"}])
    target_type = str(params.get("target_type") or action.target_type)
    target_id = str(params.get("target_id") or "")
    if not target_id:
        raise ValidationFailure([{"field": "target_id", "message": "defence.execute requires a target_id"}])
    parameters = params.get("parameters") or {}
    if not isinstance(parameters, dict):
        raise ValidationFailure([{"field": "parameters", "message": "Action parameters must be an object"}])
    connector_id = parse_uuid(str(params.get("connector_id"))) if params.get("connector_id") else None
    requested_level = params.get("requested_level")
    if requested_level and level_index(str(requested_level)) > level_index(org.autonomy_level):
        _audit(
            db,
            org_id=org.id,
            actor=actor,
            action="defence.action.denied",
            resource_type="playbook_execution",
            resource_id=str(execution.id),
            outcome="failure",
            payload={
                "step_key": step.step_key,
                "reason": "requested_level_exceeds_ceiling",
                "requested_level": requested_level,
                "org_max_level": org.autonomy_level,
            },
        )
        db.commit()
        raise PolicyDenied(
            f"Requested autonomy level {requested_level} exceeds the organization ceiling {org.autonomy_level}"
        )

    violation = ot_asset_violation(db, org.id, str(action_type), target_id)
    if violation:
        _audit(
            db,
            org_id=org.id,
            actor=actor,
            action="defence.action.denied",
            resource_type="playbook_execution",
            resource_id=str(execution.id),
            outcome="failure",
            payload={"step_key": step.step_key, "reason": violation, "target_id": target_id},
        )
        db.commit()
        raise PolicyDenied(violation)

    existing = list(
        db.execute(
            select(Remediation).where(
                Remediation.org_id == org.id,
                Remediation.execution_id == execution.id,
                Remediation.action_type == action_type,
                Remediation.status == "executed",
            )
        ).scalars()
    )
    for record in existing:
        if (record.parameters or {}).get("_step_key") == step.step_key:
            return {
                "remediation_id": str(record.id),
                "idempotent": True,
                "action_type": action_type,
                "verification": record.verification,
            }

    decision = evaluate(
        db,
        org,
        str(action_type),
        target_type=target_type,
        target_id=target_id,
        requested_level=requested_level,
        approved=last_approval_id is not None,
    )
    if not decision.allowed:
        _audit(
            db,
            org_id=org.id,
            actor=actor,
            action="defence.action.denied",
            resource_type="playbook_execution",
            resource_id=str(execution.id),
            outcome="failure",
            payload={"step_key": step.step_key, "action_type": action_type, "reason": decision.reason},
        )
        db.commit()
        raise PolicyDenied(decision.reason, details=[decision.as_dict()])

    remediation = Remediation(
        org_id=org.id,
        incident_id=execution.incident_id,
        execution_id=execution.id,
        action_type=str(action_type),
        target_type=target_type,
        target_id=target_id[:300],
        parameters={**parameters, "_step_key": step.step_key},
        status="pending",
        risk_level=decision.risk,
        autonomy_level=decision.effective_level,
        authorization_id=last_approval_id,
    )
    db.add(remediation)
    db.flush()

    try:
        result = execute_action(
            db,
            org=org,
            actor=actor,
            action_type=str(action_type),
            target_type=target_type,
            target_id=target_id,
            parameters=parameters,
            incident_id=execution.incident_id,
            approval_id=last_approval_id,
            connector_id=connector_id,
            requested_level=requested_level,
            remediation=remediation,
        )
    except PolicyDenied:
        remediation.status = "denied"
        db.commit()
        raise
    except ServiceUnavailable:
        remediation.status = "failed"
        db.commit()
        raise
    return {
        "remediation_id": str(remediation.id),
        "status": result.status,
        "verified": result.verified,
        "verification": result.output,
        "connector_id": result.connector_id,
    }


def _dispatch(
    db: Session,
    *,
    org: Organization,
    execution: PlaybookExecution,
    step: PlaybookStep,
    action: str,
    params: dict[str, Any],
    actor: BrokerActor,
    last_approval_id: UUID | None,
) -> tuple[dict[str, Any], bool]:
    """Execute one action. Returns ``(output, paused_for_approval)``."""
    if action == "internal.investigate":
        return _investigate(db, org, execution), False
    if action == "internal.create_incident":
        return _create_incident(db, org, execution, actor, params), False
    if action == "internal.add_timeline":
        return _add_timeline(db, org, execution, actor, params), False
    if action == "internal.notify":
        return _notify(db, org, execution, actor, params), False
    if action == "internal.request_approval":
        approval = Approval(
            org_id=org.id,
            request_type="playbook_step",
            resource_type="playbook_execution",
            resource_id=str(execution.id),
            payload={
                "playbook_id": str(execution.playbook_id),
                "execution_id": str(execution.id),
                "step_key": step.step_key,
                "action_type": params.get("action_type"),
                "target_type": params.get("target_type"),
                "target_id": params.get("target_id"),
                "parameters": params.get("parameters") or {},
                "incident_id": str(execution.incident_id) if execution.incident_id else None,
                "justification": params.get("justification"),
            },
            status="pending",
            requested_by=(actor.email or actor.id or "system")[:64],
            requested_by_user_id=actor.user_id,
            expires_at=utcnow() + timedelta(seconds=int(params.get("ttl_seconds") or _DEFAULT_APPROVAL_TTL)),
        )
        db.add(approval)
        db.flush()
        execution.approval_id = approval.id
        _audit(
            db,
            org_id=org.id,
            actor=actor,
            action="playbook.approval.requested",
            resource_type="approval",
            resource_id=str(approval.id),
            payload={
                "execution_id": str(execution.id),
                "step_key": step.step_key,
                "action_type": params.get("action_type"),
                "target_id": params.get("target_id"),
            },
        )
        return {"approval_id": str(approval.id), "status": "pending"}, True
    if action == "connector.read":
        return _connector_read(db, org, execution, step, actor, params), False
    if action == "defence.execute":
        return _defence_execute(db, org, execution, step, actor, params, last_approval_id), False
    raise ValidationFailure([{"field": "action", "message": f"Unsupported playbook action: {action}"}])


def _retryable(exc: Exception) -> bool:
    if isinstance(exc, ConnectorError):
        return exc.retryable
    return isinstance(exc, TimeoutError)


def _backoff(attempt: int) -> None:
    delay = min(2.0, 0.05 * (2**attempt))
    time.sleep(delay + random.uniform(0, 0.05))


def _plan_step(db: Session, org: Organization, step: PlaybookStep, env: dict[str, Any]) -> dict[str, Any]:
    action = step.input.get("action")
    params = render_params(step.input.get("params") or {}, env)
    plan: dict[str, Any] = {"action": action, "would_execute": True, "params": params}
    if action == "defence.execute":
        action_type = params.get("action_type")
        requested_level = params.get("requested_level")
        if requested_level and level_index(str(requested_level)) > level_index(org.autonomy_level):
            plan["would_execute"] = False
            plan["reason"] = "requested_level_exceeds_ceiling"
            plan["requested_level"] = requested_level
            return _bounded(plan)
        violation = ot_asset_violation(db, org.id, str(action_type), str(params.get("target_id") or ""))
        if violation:
            plan["would_execute"] = False
            plan["reason"] = violation
            return _bounded(plan)
        action_definition = get_action(str(action_type)) if isinstance(action_type, str) else None
        target_type = params.get("target_type") or (action_definition.target_type if action_definition else None)
        decision = evaluate(
            db,
            org,
            str(action_type),
            target_type=target_type,
            target_id=str(params.get("target_id") or ""),
            requested_level=requested_level,
            approved=False,
            dry_run=True,
        )
        plan["decision"] = decision.as_dict()
        plan["approval_required"] = decision.requires_approval
        plan["would_execute"] = decision.allowed
    elif action == "internal.request_approval":
        plan["note"] = "An approval request would pause the execution"
    elif action == "internal.create_incident":
        plan["note"] = "An incident would be created unless one is already in scope"
    elif action == "connector.read":
        plan["note"] = "Read-only connector invocation"
    return _bounded(plan)


def _compensate(
    db: Session,
    *,
    org: Organization,
    execution: PlaybookExecution,
    steps: list[PlaybookStep],
    actor: BrokerActor,
    env: dict[str, Any],
) -> str:
    compensated_any = False
    for candidate in reversed(steps):
        if candidate.status != "succeeded":
            continue
        compensation = candidate.input.get("compensation")
        if not compensation:
            continue
        action = compensation.get("action")
        params = render_params(compensation.get("params") or {}, env)
        try:
            output, _paused = _dispatch(
                db,
                org=org,
                execution=execution,
                step=candidate,
                action=action,
                params=params if isinstance(params, dict) else {},
                actor=actor,
                last_approval_id=None,
            )
            candidate.compensation_status = "succeeded"
            candidate.compensation_output = _bounded(output)
            compensated_any = True
            outcome = "success"
        except Exception as exc:  # noqa: BLE001 - compensation must record every failure
            candidate.compensation_status = "failed"
            candidate.compensation_output = {"error": str(exc)[:1000]}
            outcome = "failure"
        _audit(
            db,
            org_id=org.id,
            actor=actor,
            action="playbook.step.compensated",
            resource_type="playbook_step",
            resource_id=str(candidate.id),
            outcome=outcome,
            payload={"step_key": candidate.step_key, "compensation_action": action},
        )
        db.commit()
    return "compensated" if compensated_any else "failed"


def _terminate(
    db: Session,
    *,
    org: Organization,
    execution: PlaybookExecution,
    steps: list[PlaybookStep],
    actor: BrokerActor,
    env: dict[str, Any],
    status: str,
    error: str,
) -> PlaybookExecution:
    execution.status = status
    execution.error = error[:4000] or None
    execution.finished_at = utcnow()
    db.flush()
    _audit(
        db,
        org_id=org.id,
        actor=actor,
        action="playbook.execution.finished",
        resource_type="playbook_execution",
        resource_id=str(execution.id),
        outcome="success"
        if status in {"succeeded", "completed_with_errors", "compensated", "simulated"}
        else "failure",
        payload={"status": status, "error": error[:500]},
    )
    db.commit()
    return execution


def _run_dry(
    db: Session,
    *,
    org: Organization,
    execution: PlaybookExecution,
    steps: list[PlaybookStep],
    actor: BrokerActor,
) -> PlaybookExecution:
    execution.status = "running"
    execution.started_at = execution.started_at or utcnow()
    db.flush()
    for step in steps:
        env = _environment(execution, steps)
        condition = step.input.get("condition")
        if not evaluate_condition(condition, env):
            step.status = "skipped"
            step.output = {"reason": "condition_false"}
            step.finished_at = utcnow()
            db.flush()
            continue
        step.status = "would_execute"
        step.output = _plan_step(db, org, step, env)
        step.finished_at = utcnow()
        db.flush()
        _audit(
            db,
            org_id=org.id,
            actor=actor,
            action="playbook.step.simulated",
            resource_type="playbook_step",
            resource_id=str(step.id),
            payload={"step_key": step.step_key, "action": step.input.get("action")},
        )
    db.commit()
    return _terminate(
        db,
        org=org,
        execution=execution,
        steps=steps,
        actor=actor,
        env={},
        status="simulated",
        error="",
    )


def _execute_steps(
    db: Session,
    *,
    org: Organization,
    execution: PlaybookExecution,
    actor: BrokerActor,
) -> PlaybookExecution:
    steps = ordered_steps(db, execution.id)
    if execution.status == "waiting_approval":
        execution.status = "running"
        db.flush()
    last_approval_id: UUID | None = None
    for step in steps:
        if step.input.get("action") == "internal.request_approval" and step.status == "succeeded":
            recorded = (step.output or {}).get("approval_id")
            if recorded:
                last_approval_id = parse_uuid(str(recorded))

    for step in steps:
        if step.status in {"succeeded", "skipped", "would_execute"}:
            continue
        if step.status == "waiting_approval":
            approval = db.get(Approval, execution.approval_id) if execution.approval_id else None
            if approval is None:
                step.status = "failed"
                step.error = "The approval request no longer exists"
                step.finished_at = utcnow()
                return _terminate(
                    db,
                    org=org,
                    execution=execution,
                    steps=steps,
                    actor=actor,
                    env=_environment(execution, steps),
                    status="denied",
                    error=step.error,
                )
            if approval.expires_at and approval.expires_at < utcnow() and approval.status == "pending":
                approval.status = "expired"
                db.flush()
            if approval.status == "pending":
                execution.status = "waiting_approval"
                db.commit()
                return execution
            if approval.status == "approved":
                step.status = "succeeded"
                step.error = None
                step.finished_at = utcnow()
                last_approval_id = approval.id
                db.flush()
                _audit(
                    db,
                    org_id=org.id,
                    actor=actor,
                    action="playbook.step.approved",
                    resource_type="playbook_step",
                    resource_id=str(step.id),
                    payload={"step_key": step.step_key, "approval_id": str(approval.id)},
                )
                db.commit()
                continue
            step.status = "failed"
            step.error = f"Approval {approval.status}"
            step.finished_at = utcnow()
            db.flush()
            return _terminate(
                db,
                org=org,
                execution=execution,
                steps=steps,
                actor=actor,
                env=_environment(execution, steps),
                status="denied",
                error=step.error,
            )
        if step.status == "failed":
            continue

        env = _environment(execution, steps)
        if not evaluate_condition(step.input.get("condition"), env):
            step.status = "skipped"
            step.output = {"reason": "condition_false"}
            step.finished_at = utcnow()
            db.flush()
            _audit(
                db,
                org_id=org.id,
                actor=actor,
                action="playbook.step.skipped",
                resource_type="playbook_step",
                resource_id=str(step.id),
                payload={"step_key": step.step_key},
            )
            db.commit()
            continue

        action = str(step.input.get("action") or "")
        rendered = render_params(step.input.get("params") or {}, env)
        params = rendered if isinstance(rendered, dict) else {}
        retries = int(step.input.get("retries", 0))
        timeout_seconds = int(step.input.get("timeout_seconds", 60))
        on_failure = str(step.input.get("on_failure", "abort"))

        step.status = "running"
        step.started_at = step.started_at or utcnow()
        db.flush()
        db.commit()

        base_attempts = step.attempts or 0
        failure: Exception | None = None
        for attempt in range(retries + 1):
            step.attempts = base_attempts + attempt + 1
            started_monotonic = time.monotonic()
            try:
                output, paused = _dispatch(
                    db,
                    org=org,
                    execution=execution,
                    step=step,
                    action=action,
                    params=params,
                    actor=actor,
                    last_approval_id=last_approval_id,
                )
                elapsed = time.monotonic() - started_monotonic
                if action == "connector.read" and elapsed > timeout_seconds:
                    raise TimeoutError(f"Connector read exceeded {timeout_seconds}s")
                if paused:
                    step.status = "waiting_approval"
                    step.output = _bounded(output)
                    execution.status = "waiting_approval"
                    db.flush()
                    db.commit()
                    return execution
                output = _bounded(output)
                if elapsed > timeout_seconds and action in _WRITE_ACTIONS:
                    output["timeout_exceeded"] = True
                output["duration_ms"] = int(elapsed * 1000)
                step.status = "succeeded"
                step.output = output
                step.error = None
                step.finished_at = utcnow()
                db.flush()
                _audit(
                    db,
                    org_id=org.id,
                    actor=actor,
                    action="playbook.step.succeeded",
                    resource_type="playbook_step",
                    resource_id=str(step.id),
                    payload={
                        "step_key": step.step_key,
                        "action": action,
                        "attempts": step.attempts,
                        "execution_id": str(execution.id),
                    },
                )
                db.commit()
                failure = None
                break
            except Exception as exc:  # noqa: BLE001 - every failure is persisted and audited
                failure = exc
                db.rollback()
                refreshed_step = db.get(PlaybookStep, step.id)
                if refreshed_step is not None:
                    step = refreshed_step
                step.attempts = base_attempts + attempt + 1
                if _retryable(exc) and attempt < retries:
                    _backoff(attempt)
                    continue
                break

        if failure is None:
            continue

        step.status = "failed"
        step.error = str(failure)[:2000]
        step.finished_at = utcnow()
        db.flush()
        _audit(
            db,
            org_id=org.id,
            actor=actor,
            action="playbook.step.failed",
            resource_type="playbook_step",
            resource_id=str(step.id),
            outcome="failure",
            payload={
                "step_key": step.step_key,
                "action": action,
                "attempts": step.attempts,
                "error": str(failure)[:500],
                "on_failure": on_failure,
            },
        )
        db.commit()
        if on_failure == "continue":
            continue
        if on_failure == "compensate":
            status = _compensate(
                db,
                org=org,
                execution=execution,
                steps=steps,
                actor=actor,
                env=_environment(execution, steps),
            )
        else:
            status = "failed"
        return _terminate(
            db,
            org=org,
            execution=execution,
            steps=steps,
            actor=actor,
            env=_environment(execution, steps),
            status=status,
            error=str(failure)[:4000],
        )

    failed_steps = [step for step in steps if step.status == "failed"]
    return _terminate(
        db,
        org=org,
        execution=execution,
        steps=steps,
        actor=actor,
        env=_environment(execution, steps),
        status="completed_with_errors" if failed_steps else "succeeded",
        error="",
    )


def run_execution(db: Session, execution: PlaybookExecution, actor: BrokerActor) -> PlaybookExecution:
    """Start or continue a pending/running execution."""
    if execution.status in FINAL_STATUSES:
        return execution
    org = db.get(Organization, execution.org_id)
    if org is None:
        raise NotFound("Organization")
    if execution.dry_run:
        steps = ordered_steps(db, execution.id)
        return _run_dry(db, org=org, execution=execution, steps=steps, actor=actor)
    if execution.status == "waiting_approval":
        return _resume(db, org=org, execution=execution, actor=actor, raise_on_pending=False)
    if execution.status == "pending":
        execution.status = "running"
        execution.started_at = utcnow()
        db.flush()
        _audit(
            db,
            org_id=org.id,
            actor=actor,
            action="playbook.execution.started",
            resource_type="playbook_execution",
            resource_id=str(execution.id),
            payload={"playbook_id": str(execution.playbook_id), "trigger": execution.trigger},
        )
        db.commit()
    return _execute_steps(db, org=org, execution=execution, actor=actor)


def _resume(
    db: Session,
    *,
    org: Organization,
    execution: PlaybookExecution,
    actor: BrokerActor,
    raise_on_pending: bool,
) -> PlaybookExecution:
    approval = db.get(Approval, execution.approval_id) if execution.approval_id else None
    if approval is None:
        execution.status = "failed"
        execution.error = "Execution is waiting for an approval that no longer exists"
        execution.finished_at = utcnow()
        db.commit()
        return execution
    if approval.expires_at and approval.expires_at < utcnow() and approval.status == "pending":
        approval.status = "expired"
        db.flush()
    if approval.status == "pending":
        if raise_on_pending:
            db.commit()
            raise Conflict("The approval request is still pending")
        execution.status = "waiting_approval"
        db.commit()
        return execution
    _audit(
        db,
        org_id=org.id,
        actor=actor,
        action="playbook.execution.resumed",
        resource_type="playbook_execution",
        resource_id=str(execution.id),
        payload={"approval_id": str(approval.id), "approval_status": approval.status},
    )
    db.commit()
    return _execute_steps(db, org=org, execution=execution, actor=actor)


def resume_execution(db: Session, execution: PlaybookExecution, actor: BrokerActor) -> PlaybookExecution:
    """Resume a waiting execution. Pending approvals are a 409."""
    if execution.status != "waiting_approval":
        raise Conflict("The execution is not waiting for approval")
    org = db.get(Organization, execution.org_id)
    if org is None:
        raise NotFound("Organization")
    return _resume(db, org=org, execution=execution, actor=actor, raise_on_pending=True)


def simulate_playbook(
    db: Session,
    *,
    org: Organization,
    playbook: Playbook,
    context: dict[str, Any] | None,
    incident_id: UUID | None = None,
) -> dict[str, Any]:
    """Evaluate conditions and policy without creating executions or rows."""
    context = validate_context(context or {})
    env: dict[str, Any] = {**context, "context": context}
    if incident_id:
        incident = db.get(Incident, incident_id)
        if incident is None or incident.org_id != org.id:
            raise NotFound("Incident")
        env["incident"] = {
            "id": str(incident.id),
            "ref": incident.ref,
            "severity": incident.severity,
            "status": incident.status,
            "priority": incident.priority,
            "affected_asset_ids": incident.affected_asset_ids,
        }
    plan: list[dict[str, Any]] = []
    definition = playbook.definition or {}
    for position, step in enumerate(definition.get("steps") or []):
        condition = step.get("condition")
        should_run = evaluate_condition(condition, env)
        entry: dict[str, Any] = {
            "position": position,
            "key": step.get("key"),
            "name": step.get("name"),
            "action": step.get("action"),
            "would_execute": should_run,
            "condition_matched": should_run,
        }
        if not should_run:
            entry["reason"] = "condition_false"
            plan.append(entry)
            continue
        params = render_params(step.get("params") or {}, env)
        entry["params"] = params if isinstance(params, dict) else {}
        if step.get("action") == "defence.execute" and isinstance(params, dict):
            action_definition = get_action(str(params.get("action_type")))
            requested_level = params.get("requested_level")
            if requested_level and level_index(str(requested_level)) > level_index(org.autonomy_level):
                entry["would_execute"] = False
                entry["reason"] = "requested_level_exceeds_ceiling"
                entry["requested_level"] = requested_level
                plan.append(entry)
                continue
            violation = ot_asset_violation(
                db, org.id, str(params.get("action_type")), str(params.get("target_id") or "")
            )
            if violation:
                entry["would_execute"] = False
                entry["reason"] = violation
                plan.append(entry)
                continue
            decision = evaluate(
                db,
                org,
                str(params.get("action_type")),
                target_type=params.get("target_type") or (action_definition.target_type if action_definition else None),
                target_id=str(params.get("target_id") or ""),
                requested_level=requested_level,
                approved=False,
                dry_run=True,
            )
            entry["decision"] = decision.as_dict()
            entry["would_execute"] = decision.allowed
            entry["approval_required"] = decision.requires_approval
        plan.append(entry)
    return {
        "playbook_id": str(playbook.id),
        "version": playbook.version,
        "status": playbook.status,
        "autonomy_level": org.autonomy_level,
        "steps": plan,
        "summary": {
            "steps": len(plan),
            "would_execute": sum(1 for item in plan if item["would_execute"]),
            "skipped": sum(1 for item in plan if not item["condition_matched"]),
        },
    }


def _claim(db: Session, limit: int) -> list[PlaybookExecution]:
    claimed: list[PlaybookExecution] = []
    stale_before = utcnow() - timedelta(minutes=5)
    runnable = list(
        db.execute(
            select(PlaybookExecution)
            .where(
                (PlaybookExecution.status == "pending")
                | ((PlaybookExecution.status == "running") & (PlaybookExecution.started_at < stale_before))
            )
            .order_by(PlaybookExecution.started_at.asc())
            .limit(limit)
            .with_for_update(skip_locked=True)
        ).scalars()
    )
    claimed.extend(runnable)
    remaining = limit - len(claimed)
    if remaining > 0:
        waiting = list(
            db.execute(
                select(PlaybookExecution)
                .join(Approval, Approval.id == PlaybookExecution.approval_id)
                .where(
                    PlaybookExecution.status == "waiting_approval",
                    Approval.status.in_(["approved", "rejected", "expired"]),
                )
                .order_by(PlaybookExecution.started_at.asc())
                .limit(remaining)
                .with_for_update(skip_locked=True)
            ).scalars()
        )
        claimed.extend(waiting)
    return claimed


def worker_run_once(db: Session, limit: int = 10) -> dict[str, Any]:
    """Claim and advance durable executions. Safe to run repeatedly."""
    actor = BrokerActor(id="system:playbook-worker", email=None)
    executions = _claim(db, max(1, min(limit, 100)))
    db.commit()
    processed = 0
    failed = 0
    for execution in executions:
        processed += 1
        try:
            advance_execution(db, execution, actor)
        except Exception as exc:  # noqa: BLE001 - worker must survive a poisoned execution
            db.rollback()
            failed += 1
            stale = db.get(PlaybookExecution, execution.id)
            if stale is not None and stale.status not in FINAL_STATUSES:
                stale.status = "failed"
                stale.error = f"Worker failure: {exc}"[:4000]
                stale.finished_at = utcnow()
                _audit(
                    db,
                    org_id=stale.org_id,
                    actor=actor,
                    action="playbook.execution.worker_failure",
                    resource_type="playbook_execution",
                    resource_id=str(stale.id),
                    outcome="failure",
                    payload={"error": str(exc)[:500]},
                )
                db.commit()
    return {"claimed": len(executions), "processed": processed, "failed": failed}


def advance_execution(db: Session, execution: PlaybookExecution, actor: BrokerActor) -> PlaybookExecution:
    return run_execution(db, execution, actor)


__all__ = [
    "advance_execution",
    "create_execution",
    "ordered_steps",
    "resume_execution",
    "run_execution",
    "simulate_playbook",
    "worker_run_once",
]
