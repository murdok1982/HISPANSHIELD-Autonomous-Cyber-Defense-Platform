"""MCP governance service: discovery, human approval, guarded execution and audit."""

from __future__ import annotations

import json
import time
from datetime import timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import append_audit, redact
from app.core.crypto import sha256_hex
from app.core.db import utcnow
from app.core.errors import (
    Conflict,
    NotFound,
    PolicyDenied,
    RateLimited,
    ServiceUnavailable,
    ValidationFailure,
)
from app.models.ai import AgentRun
from app.models.connectors import MCPServer, MCPTool, ToolExecution
from app.models.core import Approval
from app.modules.mcp.client import JsonRpcClient, JsonRpcError, validate_arguments
from app.services.llm.safety import scan_injection, strip_control_chars

MAX_RESULT_CHARS = 50_000
DISCOVERY_TIMEOUT_SECONDS = 20
MCP_APPROVAL_REQUEST_TYPE = "mcp_tool_approval"
MCP_APPROVAL_SCHEMA_VERSION = 1


def _approval_snapshot(server: MCPServer, tool: MCPTool) -> dict[str, Any]:
    """Canonical, hashable view of everything a human approval covers."""
    return {
        "schema_version": MCP_APPROVAL_SCHEMA_VERSION,
        "org_id": str(tool.org_id),
        "server_id": str(server.id),
        "server_name": server.name,
        "server_endpoint": server.endpoint,
        "server_version": server.version,
        "tool_id": str(tool.id),
        "tool_name": tool.name,
        "tool_version": tool.version,
        "input_schema": tool.input_schema or {},
    }


def mcp_approval_fingerprint(server: MCPServer, tool: MCPTool) -> str:
    """sha256 over the canonical approval scope (server + tool + schema + version)."""
    return sha256_hex(json.dumps(_approval_snapshot(server, tool), sort_keys=True, separators=(",", ":"), default=str))


def _active_tool_approval(db: Session, tool: MCPTool) -> Approval | None:
    return db.execute(
        select(Approval)
        .where(
            Approval.org_id == tool.org_id,
            Approval.request_type == MCP_APPROVAL_REQUEST_TYPE,
            Approval.resource_type == "mcp_tool",
            Approval.resource_id == str(tool.id),
            Approval.status == "approved",
        )
        .order_by(Approval.decided_at.desc().nullslast(), Approval.created_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def _approval_changes(approval: Approval, server: MCPServer, tool: MCPTool) -> list[str]:
    stored = approval.payload or {}
    current = _approval_snapshot(server, tool)
    tracked = (
        "schema_version",
        "org_id",
        "server_id",
        "server_name",
        "server_endpoint",
        "server_version",
        "tool_id",
        "tool_name",
        "tool_version",
        "input_schema",
    )
    return [field for field in tracked if stored.get(field) != current[field]]


def _deny_drifted_execution(
    db: Session,
    tool: MCPTool,
    *,
    server: MCPServer,
    arguments: dict[str, Any],
    actor: str | None,
    agent_run_id: UUID | None,
    approval: Approval,
    changes: list[str],
) -> None:
    current_fingerprint = mcp_approval_fingerprint(server, tool)
    approved_fingerprint = (approval.payload or {}).get("fingerprint")
    reason = (
        "MCP tool approval no longer matches the current definition (changed: "
        f"{', '.join(changes)}); re-approve the tool after review"
    )
    _execution_record(
        db,
        tool,
        arguments=arguments,
        status="denied",
        latency_ms=0,
        created_by=actor,
        agent_run_id=agent_run_id,
        error=reason,
    )
    append_audit(
        db,
        org_id=tool.org_id,
        action="mcp.tool.execution.denied",
        resource_type="mcp_tool",
        resource_id=str(tool.id),
        actor_type="user" if actor else "system",
        actor_id=actor,
        outcome="failure",
        payload={
            "reason": "approval_drift",
            "changed": changes,
            "approval_id": str(approval.id),
            "approved_fingerprint": approved_fingerprint,
            "current_fingerprint": current_fingerprint,
            "server_id": str(server.id),
            "server_name": server.name,
            "server_endpoint": server.endpoint,
            "tool_name": tool.name,
            "tool_version": tool.version,
        },
    )
    db.commit()
    raise PolicyDenied(
        reason,
        details=[{"field": field, "message": "Changed since the approval was granted"} for field in changes],
    )


MALFORMED_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {},
    "additionalProperties": False,
    "x-hispanshield-malformed": True,
}


def _normalise_schema(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        return dict(MALFORMED_SCHEMA)
    if "properties" in raw and not isinstance(raw["properties"], dict):
        return dict(MALFORMED_SCHEMA)
    if "required" in raw and not isinstance(raw["required"], list):
        return dict(MALFORMED_SCHEMA)
    return raw


def _tool_metadata(raw: dict[str, Any]) -> dict[str, Any] | None:
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    raw_annotations = raw.get("annotations")
    annotations: dict[Any, Any] = raw_annotations if isinstance(raw_annotations, dict) else {}
    risk = "medium"
    if annotations.get("destructiveHint") is True:
        risk = "high"
    elif annotations.get("readOnlyHint") is True:
        risk = "low"
    description = raw.get("description")
    input_schema = raw.get("inputSchema")
    output_schema = raw.get("outputSchema")
    version = raw.get("version")
    return {
        "name": name.strip()[:160],
        "description": (str(description)[:2000] if description is not None else None),
        "input_schema": _normalise_schema(input_schema),
        "output_schema": output_schema if isinstance(output_schema, dict) else {},
        "version": str(version)[:40] if version is not None else None,
        "risk_level": risk,
    }


def discover_server(db: Session, server: MCPServer) -> dict[str, Any]:
    if not server.endpoint:
        raise ValidationFailure([{"field": "endpoint", "message": "MCP server has no endpoint"}])
    client = JsonRpcClient(server.endpoint, timeout=DISCOVERY_TIMEOUT_SECONDS)
    try:
        init = client.initialize()
        raw_tools = client.list_tools()
    except JsonRpcError as exc:
        server.status = "error"
        db.flush()
        raise ServiceUnavailable(f"MCP discovery failed: {str(exc)[:300]}", code="mcp_discovery_failed") from exc

    protocol_version = init.get("protocolVersion")
    raw_server_info = init.get("serverInfo")
    server_info: dict[Any, Any] = raw_server_info if isinstance(raw_server_info, dict) else {}
    discovered: dict[str, dict[str, Any]] = {}
    for raw in raw_tools:
        metadata = _tool_metadata(raw)
        if metadata is not None:
            discovered.setdefault(metadata["name"], metadata)

    created = 0
    updated = 0
    tools: list[MCPTool] = []
    for name, metadata in discovered.items():
        tool = db.execute(
            select(MCPTool).where(MCPTool.server_id == server.id, MCPTool.name == name)
        ).scalar_one_or_none()
        if tool is None:
            tool = MCPTool(
                org_id=server.org_id,
                server_id=server.id,
                name=name,
                version=metadata["version"],
                description=metadata["description"],
                input_schema=metadata["input_schema"],
                output_schema=metadata["output_schema"],
                risk_level=metadata["risk_level"],
                permissions_required=[],
                enabled=False,
                approved=False,
                timeout_seconds=30,
                max_calls_per_hour=60,
            )
            db.add(tool)
            created += 1
        else:
            tool.version = metadata["version"] or tool.version
            tool.description = metadata["description"] or tool.description
            tool.input_schema = metadata["input_schema"]
            tool.output_schema = metadata["output_schema"]
            tool.risk_level = metadata["risk_level"]
            # Approval state is never granted by discovery.
            updated += 1
        tools.append(tool)

    if isinstance(server_info.get("version"), str):
        server.version = server_info["version"][:40]
    server.capabilities = {
        "protocol_version": protocol_version if isinstance(protocol_version, str) else None,
        "server_info": server_info,
        "tool_names": sorted(discovered.keys()),
        "tool_count": len(discovered),
        "discovered_at": utcnow().isoformat(),
    }
    server.status = "discovered"
    db.flush()
    return {
        "protocol_version": protocol_version if isinstance(protocol_version, str) else None,
        "server_info": server_info,
        "discovered": len(discovered),
        "created": created,
        "updated": updated,
        "tools": tools,
    }


def approve_server(db: Session, server: MCPServer, actor: str) -> MCPServer:
    server.enabled = True
    server.approved_by = actor[:64]
    server.approved_at = utcnow()
    server.status = "approved"
    db.flush()
    return server


def approve_tool(
    db: Session,
    tool: MCPTool,
    server: MCPServer,
    *,
    approved: bool,
    timeout_seconds: int | None,
    max_calls_per_hour: int | None,
    actor: str | None = None,
    decided_by: UUID | None = None,
) -> MCPTool:
    if approved and not (server.enabled and server.approved_at is not None):
        raise Conflict("The MCP server must be approved before its tools can be approved")
    # Every (re-)approval supersedes previous snapshots, so only the latest
    # human decision can authorize a call.
    previous = list(
        db.execute(
            select(Approval).where(
                Approval.org_id == tool.org_id,
                Approval.request_type == MCP_APPROVAL_REQUEST_TYPE,
                Approval.resource_type == "mcp_tool",
                Approval.resource_id == str(tool.id),
                Approval.status == "approved",
            )
        ).scalars()
    )
    for record in previous:
        record.status = "superseded"
    if approved:
        fingerprint = mcp_approval_fingerprint(server, tool)
        snapshot = _approval_snapshot(server, tool)
        approval = Approval(
            org_id=tool.org_id,
            request_type=MCP_APPROVAL_REQUEST_TYPE,
            resource_type="mcp_tool",
            resource_id=str(tool.id),
            payload={**snapshot, "fingerprint": fingerprint},
            status="approved",
            requested_by=(actor or "unknown")[:64],
            requested_by_user_id=decided_by,
            decided_by=decided_by,
            decided_at=utcnow(),
            reason="Approved MCP tool bound to server, tool, version and input schema",
        )
        db.add(approval)
        db.flush()
    tool.approved = approved
    tool.enabled = approved
    if timeout_seconds is not None:
        tool.timeout_seconds = timeout_seconds
    if max_calls_per_hour is not None:
        tool.max_calls_per_hour = max_calls_per_hour
    db.flush()
    return tool


def _execution_record(
    db: Session,
    tool: MCPTool,
    *,
    arguments: dict[str, Any],
    status: str,
    latency_ms: int,
    created_by: str | None,
    agent_run_id: UUID | None,
    result: dict[str, Any] | None = None,
    error: str | None = None,
) -> ToolExecution:
    execution = ToolExecution(
        org_id=tool.org_id,
        tool_id=tool.id,
        agent_run_id=agent_run_id,
        tool_name=tool.name,
        arguments_redacted=redact(arguments),
        result_redacted=result or {},
        status=status,
        error=(error or "")[:2000] or None,
        latency_ms=latency_ms,
        created_by=created_by,
    )
    db.add(execution)
    db.flush()
    return execution


def _sanitize_result(result: Any) -> dict[str, Any]:
    serialized = json.dumps(result, ensure_ascii=False, default=str)
    stripped = strip_control_chars(serialized)
    truncated = len(stripped) > MAX_RESULT_CHARS
    if truncated:
        stripped = stripped[:MAX_RESULT_CHARS]
    verdict = scan_injection(stripped)
    try:
        parsed: Any = json.loads(stripped)
    except (TypeError, ValueError):
        parsed = {"text": stripped}
    return {
        "result": parsed,
        "injection_suspected": verdict.suspected,
        "injection_matches": verdict.matches,
        "truncated": truncated,
    }


def _require_current_approval(
    db: Session,
    tool: MCPTool,
    server: MCPServer,
    *,
    arguments: dict[str, Any],
    actor: str | None,
    agent_run_id: UUID | None,
) -> Approval:
    """Recompute the approval fingerprint and reject any post-approval drift."""
    if tool.org_id != server.org_id:
        raise PolicyDenied("MCP tool and server belong to different organizations")
    approval = _active_tool_approval(db, tool)
    if approval is None:
        reason = "MCP tool has no active approval binding; re-approve the tool after review"
        _execution_record(
            db,
            tool,
            arguments=arguments,
            status="denied",
            latency_ms=0,
            created_by=actor,
            agent_run_id=agent_run_id,
            error=reason,
        )
        append_audit(
            db,
            org_id=tool.org_id,
            action="mcp.tool.execution.denied",
            resource_type="mcp_tool",
            resource_id=str(tool.id),
            actor_type="user" if actor else "system",
            actor_id=actor,
            outcome="failure",
            payload={"reason": "approval_missing", "server_id": str(server.id), "tool_name": tool.name},
        )
        db.commit()
        raise PolicyDenied(reason)
    changes = _approval_changes(approval, server, tool)
    stored_fingerprint = (approval.payload or {}).get("fingerprint")
    if stored_fingerprint != mcp_approval_fingerprint(server, tool) and not changes:
        changes = ["approval_fingerprint"]
    if changes:
        _deny_drifted_execution(
            db,
            tool,
            server=server,
            arguments=arguments,
            actor=actor,
            agent_run_id=agent_run_id,
            approval=approval,
            changes=changes,
        )
    return approval


def execute_tool(
    db: Session,
    tool: MCPTool,
    server: MCPServer,
    arguments: dict[str, Any],
    *,
    actor: str | None,
    agent_run_id: UUID | None = None,
) -> dict[str, Any]:
    if not server.enabled or server.approved_at is None:
        raise PolicyDenied("MCP server is not enabled and approved")
    if not tool.enabled or not tool.approved:
        raise PolicyDenied("MCP tool is not enabled and approved")
    _require_current_approval(
        db,
        tool,
        server,
        arguments=arguments,
        actor=actor,
        agent_run_id=agent_run_id,
    )
    if agent_run_id is not None:
        run = db.get(AgentRun, agent_run_id)
        if run is None or run.org_id != tool.org_id:
            raise NotFound("Agent run")

    errors = validate_arguments(tool.input_schema, arguments)
    if errors:
        raise ValidationFailure([{"field": "arguments", "message": message} for message in errors])

    window_start = utcnow() - timedelta(hours=1)
    recent_calls = db.execute(
        select(func.count())
        .select_from(ToolExecution)
        .where(ToolExecution.tool_id == tool.id, ToolExecution.created_at >= window_start)
    ).scalar_one()
    if int(recent_calls) >= tool.max_calls_per_hour:
        raise RateLimited(3600)

    if not server.endpoint:
        raise ServiceUnavailable("MCP server has no endpoint configured", code="mcp_unavailable")
    client = JsonRpcClient(server.endpoint, timeout=tool.timeout_seconds)
    started = time.perf_counter()
    try:
        result = client.call_tool(tool.name, arguments)
    except JsonRpcError as exc:
        latency_ms = int((time.perf_counter() - started) * 1000)
        timed_out = "timed out" in str(exc).lower()
        _execution_record(
            db,
            tool,
            arguments=arguments,
            status="timeout" if timed_out else "error",
            latency_ms=latency_ms,
            created_by=actor,
            agent_run_id=agent_run_id,
            error=str(exc),
        )
        if timed_out:
            raise ServiceUnavailable("MCP tool timed out", code="tool_timeout") from exc
        raise ServiceUnavailable(f"MCP tool failed: {str(exc)[:300]}", code="tool_error") from exc

    latency_ms = int((time.perf_counter() - started) * 1000)
    sanitized = _sanitize_result(result)
    execution = _execution_record(
        db,
        tool,
        arguments=arguments,
        status="success",
        latency_ms=latency_ms,
        created_by=actor,
        agent_run_id=agent_run_id,
        result=sanitized,
    )
    return {
        "execution_id": execution.id,
        "tool_id": tool.id,
        "tool_name": tool.name,
        "status": "success",
        "latency_ms": latency_ms,
        "injection_suspected": sanitized["injection_suspected"],
        "injection_matches": sanitized["injection_matches"],
        "truncated": sanitized["truncated"],
        "result": sanitized["result"],
        "error": None,
    }


__all__ = [
    "MCP_APPROVAL_REQUEST_TYPE",
    "approve_server",
    "approve_tool",
    "discover_server",
    "execute_tool",
    "mcp_approval_fingerprint",
]
