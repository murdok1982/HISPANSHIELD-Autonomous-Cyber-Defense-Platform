"""MCP server registry, human approvals, tool discovery and guarded execution."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, or_, select

from app.core.deps import RequestContext, require_permission
from app.core.errors import Conflict, Forbidden, NotFound
from app.core.schemas import Page, paginate
from app.models.connectors import MCPServer, MCPTool, ToolExecution
from app.modules.mcp.client import JsonRpcError, validate_endpoint
from app.modules.mcp.schemas import (
    MCPDiscoverOut,
    MCPExecutionOut,
    MCPServerCreate,
    MCPServerOut,
    MCPServerPatch,
    MCPToolApprove,
    MCPToolExecute,
    MCPToolOut,
    ToolExecutionOut,
)
from app.modules.mcp.service import (
    approve_server,
    approve_tool,
    discover_server,
    execute_tool,
    mcp_approval_fingerprint,
)

router = APIRouter(prefix="/mcp", tags=["MCP Governance"])


def _require_human(ctx: RequestContext) -> str:
    if ctx.api_token is not None or ctx.user is None:
        raise Forbidden("MCP approval requires an interactive human session")
    return ctx.actor_email or ctx.actor_id or "human"


def _get_server(ctx: RequestContext, server_id: UUID) -> MCPServer:
    server = ctx.db.get(MCPServer, server_id)
    if server is None or server.org_id != ctx.org.id:
        raise NotFound("MCP server")
    return server


def _get_tool(ctx: RequestContext, tool_id: UUID) -> tuple[MCPTool, MCPServer]:
    row = ctx.db.execute(
        select(MCPTool, MCPServer).join(MCPServer, MCPServer.id == MCPTool.server_id).where(MCPTool.id == tool_id)
    ).first()
    if row is None:
        raise NotFound("MCP tool")
    tool, server = row
    if tool.org_id != ctx.org.id or server.org_id != ctx.org.id:
        raise NotFound("MCP tool")
    return tool, server


@router.get("/servers", response_model=Page[MCPServerOut], summary="List MCP servers")
def list_servers(
    ctx: RequestContext = Depends(require_permission("mcp:read")),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    q: str | None = Query(default=None, max_length=120),
    status: str | None = Query(default=None, pattern="^(discovered|approved|error|disabled)$"),
) -> Page[MCPServerOut]:
    stmt = select(MCPServer).where(MCPServer.org_id == ctx.org.id).order_by(MCPServer.name)
    if q:
        stmt = stmt.where(func.lower(MCPServer.name).like(f"%{q.lower()}%"))
    if status:
        stmt = stmt.where(MCPServer.status == status)
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[MCPServerOut](**paginate([MCPServerOut.model_validate(row) for row in rows], total, page, page_size))


@router.post("/servers", response_model=MCPServerOut, status_code=201, summary="Register an MCP server")
def create_server(
    payload: MCPServerCreate, ctx: RequestContext = Depends(require_permission("mcp:write"))
) -> MCPServerOut:
    duplicate = ctx.db.execute(
        select(MCPServer).where(MCPServer.org_id == ctx.org.id, MCPServer.name == payload.name.strip())
    ).scalar_one_or_none()
    if duplicate is not None:
        raise Conflict("An MCP server with this name already exists")
    try:
        endpoint = validate_endpoint(payload.endpoint)
    except JsonRpcError as exc:
        from app.core.errors import ValidationFailure

        raise ValidationFailure([{"field": "endpoint", "message": str(exc)}]) from exc
    server = MCPServer(
        org_id=ctx.org.id,
        name=payload.name.strip(),
        transport="http",
        endpoint=endpoint,
        version=payload.version,
        trust_level=payload.trust_level,
        status="discovered",
        enabled=False,
        capabilities={},
    )
    ctx.db.add(server)
    ctx.db.flush()
    ctx.audit(
        action="mcp.server.create",
        resource_type="mcp_server",
        resource_id=str(server.id),
        payload={"name": server.name, "trust_level": server.trust_level, "transport": server.transport},
    )
    ctx.db.commit()
    ctx.db.refresh(server)
    return MCPServerOut.model_validate(server)


@router.get("/servers/{server_id}", response_model=MCPServerOut, summary="Read an MCP server")
def get_server(server_id: UUID, ctx: RequestContext = Depends(require_permission("mcp:read"))) -> MCPServerOut:
    return MCPServerOut.model_validate(_get_server(ctx, server_id))


@router.patch("/servers/{server_id}", response_model=MCPServerOut, summary="Update an MCP server")
def update_server(
    server_id: UUID,
    payload: MCPServerPatch,
    ctx: RequestContext = Depends(require_permission("mcp:write")),
) -> MCPServerOut:
    server = _get_server(ctx, server_id)
    changes = payload.model_dump(exclude_unset=True)
    if "endpoint" in changes and changes["endpoint"] is not None:
        try:
            changes["endpoint"] = validate_endpoint(changes["endpoint"])
        except JsonRpcError as exc:
            from app.core.errors import ValidationFailure

            raise ValidationFailure([{"field": "endpoint", "message": str(exc)}]) from exc
    for field in ("name", "endpoint", "version", "trust_level"):
        if field in changes and changes[field] is not None:
            setattr(server, field, changes[field])
    if "endpoint" in changes and changes["endpoint"] is not None:
        # A changed endpoint invalidates the previous human approval.
        server.enabled = False
        server.approved_at = None
        server.approved_by = None
        server.status = "discovered"
    ctx.audit(
        action="mcp.server.update",
        resource_type="mcp_server",
        resource_id=str(server.id),
        payload={"fields": sorted(changes.keys())},
    )
    ctx.db.commit()
    ctx.db.refresh(server)
    return MCPServerOut.model_validate(server)


@router.delete("/servers/{server_id}", status_code=204, response_class=Response, summary="Delete an MCP server")
def delete_server(server_id: UUID, ctx: RequestContext = Depends(require_permission("mcp:write"))) -> Response:
    server = _get_server(ctx, server_id)
    ctx.audit(
        action="mcp.server.delete",
        resource_type="mcp_server",
        resource_id=str(server.id),
        payload={"name": server.name},
    )
    ctx.db.delete(server)
    ctx.db.commit()
    return Response(status_code=204)


@router.post("/servers/{server_id}/discover", response_model=MCPDiscoverOut, summary="Discover tools via JSON-RPC")
def discover(server_id: UUID, ctx: RequestContext = Depends(require_permission("mcp:write"))) -> MCPDiscoverOut:
    server = _get_server(ctx, server_id)
    try:
        result = discover_server(ctx.db, server)
    except Exception:
        ctx.db.commit()
        raise
    ctx.audit(
        action="mcp.server.discover",
        resource_type="mcp_server",
        resource_id=str(server.id),
        payload={"discovered": result["discovered"], "created": result["created"], "updated": result["updated"]},
    )
    ctx.db.commit()
    ctx.db.refresh(server)
    return MCPDiscoverOut(
        server_id=server.id,
        protocol_version=result["protocol_version"],
        server_info=result["server_info"],
        discovered=result["discovered"],
        created=result["created"],
        updated=result["updated"],
        tools=[MCPToolOut.model_validate(tool) for tool in result["tools"]],
    )


@router.post("/servers/{server_id}/approve", response_model=MCPServerOut, summary="Approve an MCP server")
def approve(server_id: UUID, ctx: RequestContext = Depends(require_permission("mcp:write"))) -> MCPServerOut:
    actor = _require_human(ctx)
    server = _get_server(ctx, server_id)
    approve_server(ctx.db, server, actor)
    ctx.audit(
        action="mcp.server.approve",
        resource_type="mcp_server",
        resource_id=str(server.id),
        payload={"name": server.name, "approved_by": actor},
    )
    ctx.db.commit()
    ctx.db.refresh(server)
    return MCPServerOut.model_validate(server)


@router.get("/servers/{server_id}/tools", response_model=list[MCPToolOut], summary="List a server's discovered tools")
def list_server_tools(
    server_id: UUID, ctx: RequestContext = Depends(require_permission("mcp:read"))
) -> list[MCPToolOut]:
    server = _get_server(ctx, server_id)
    rows = list(ctx.db.execute(select(MCPTool).where(MCPTool.server_id == server.id).order_by(MCPTool.name)).scalars())
    return [MCPToolOut.model_validate(tool) for tool in rows]


@router.get("/tools", response_model=Page[MCPToolOut], summary="List MCP tools")
def list_tools(
    ctx: RequestContext = Depends(require_permission("mcp:read")),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    server_id: UUID | None = Query(default=None),
    approved: bool | None = Query(default=None),
    q: str | None = Query(default=None, max_length=160),
) -> Page[MCPToolOut]:
    stmt = select(MCPTool).where(MCPTool.org_id == ctx.org.id).order_by(MCPTool.name)
    if server_id:
        stmt = stmt.where(MCPTool.server_id == server_id)
    if approved is not None:
        stmt = stmt.where(MCPTool.approved.is_(approved))
    if q:
        stmt = stmt.where(
            or_(func.lower(MCPTool.name).like(f"%{q.lower()}%"), func.lower(MCPTool.description).like(f"%{q.lower()}%"))
        )
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[MCPToolOut](**paginate([MCPToolOut.model_validate(row) for row in rows], total, page, page_size))


@router.get("/tools/{tool_id}", response_model=MCPToolOut, summary="Read an MCP tool")
def get_tool(tool_id: UUID, ctx: RequestContext = Depends(require_permission("mcp:read"))) -> MCPToolOut:
    tool, _server = _get_tool(ctx, tool_id)
    return MCPToolOut.model_validate(tool)


@router.post("/tools/{tool_id}/approve", response_model=MCPToolOut, summary="Approve an MCP tool")
def approve_tool_endpoint(
    tool_id: UUID,
    payload: MCPToolApprove = MCPToolApprove(),
    ctx: RequestContext = Depends(require_permission("mcp:write")),
) -> MCPToolOut:
    actor = _require_human(ctx)
    tool, server = _get_tool(ctx, tool_id)
    approve_tool(
        ctx.db,
        tool,
        server,
        approved=payload.approved,
        timeout_seconds=payload.timeout_seconds,
        max_calls_per_hour=payload.max_calls_per_hour,
        actor=actor,
        decided_by=ctx.user.id if ctx.user else None,
    )
    ctx.audit(
        action="mcp.tool.approve" if payload.approved else "mcp.tool.revoke",
        resource_type="mcp_tool",
        resource_id=str(tool.id),
        payload={
            "name": tool.name,
            "server_id": str(server.id),
            "timeout_seconds": tool.timeout_seconds,
            "max_calls_per_hour": tool.max_calls_per_hour,
            "approval_fingerprint": mcp_approval_fingerprint(server, tool) if payload.approved else None,
        },
    )
    ctx.db.commit()
    ctx.db.refresh(tool)
    return MCPToolOut.model_validate(tool)


@router.post("/tools/{tool_id}/execute", response_model=MCPExecutionOut, summary="Execute an approved MCP tool")
def execute_mcp_tool(
    tool_id: UUID,
    payload: MCPToolExecute,
    ctx: RequestContext = Depends(require_permission("mcp:execute")),
) -> MCPExecutionOut:
    tool, server = _get_tool(ctx, tool_id)
    try:
        result = execute_tool(
            ctx.db,
            tool,
            server,
            payload.arguments,
            actor=ctx.actor_id,
            agent_run_id=payload.agent_run_id,
        )
    except Exception:
        # Persist the failed execution record / denial context before surfacing the error.
        ctx.db.commit()
        raise
    ctx.audit(
        action="mcp.tool.execute",
        resource_type="mcp_tool",
        resource_id=str(tool.id),
        payload={
            "name": tool.name,
            "server_id": str(server.id),
            "injection_suspected": result["injection_suspected"],
            "truncated": result["truncated"],
            "latency_ms": result["latency_ms"],
        },
    )
    ctx.db.commit()
    return MCPExecutionOut(**result)


@router.get(
    "/tools/{tool_id}/executions",
    response_model=Page[ToolExecutionOut],
    summary="Read tool execution audit entries",
)
def list_tool_executions(
    tool_id: UUID,
    ctx: RequestContext = Depends(require_permission("mcp:read")),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
) -> Page[ToolExecutionOut]:
    tool, _server = _get_tool(ctx, tool_id)
    stmt = (
        select(ToolExecution)
        .where(ToolExecution.tool_id == tool.id, ToolExecution.org_id == ctx.org.id)
        .order_by(ToolExecution.created_at.desc())
    )
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[ToolExecutionOut](
        **paginate([ToolExecutionOut.model_validate(row) for row in rows], total, page, page_size)
    )


__all__ = ["router"]
