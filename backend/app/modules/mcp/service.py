"""MCP governance service: discovery, human approval, guarded execution and audit."""

from __future__ import annotations

import json
import time
from datetime import timedelta
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import redact
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
from app.modules.mcp.client import JsonRpcClient, JsonRpcError, validate_arguments
from app.services.llm.safety import scan_injection, strip_control_chars

MAX_RESULT_CHARS = 50_000
DISCOVERY_TIMEOUT_SECONDS = 20


def _tool_metadata(raw: dict[str, Any]) -> dict[str, Any] | None:
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        return None
    annotations = raw.get("annotations") if isinstance(raw.get("annotations"), dict) else {}
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
        "input_schema": input_schema if isinstance(input_schema, dict) else {},
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
    server_info = init.get("serverInfo") if isinstance(init.get("serverInfo"), dict) else {}
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
) -> MCPTool:
    if approved and not (server.enabled and server.approved_at is not None):
        raise Conflict("The MCP server must be approved before its tools can be approved")
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


__all__ = ["approve_server", "approve_tool", "discover_server", "execute_tool"]
