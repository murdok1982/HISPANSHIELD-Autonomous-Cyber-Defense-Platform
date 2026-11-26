"""Agent catalogue, bounded synchronous runs, run history and grounded chat."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select

from app.core.db import utcnow
from app.core.deps import RequestContext, require_permission
from app.core.errors import Conflict, Forbidden, NotFound
from app.core.schemas import Page, paginate
from app.models.ai import Agent, AgentMessage, AgentRun
from app.models.incidents import Incident
from app.modules.agents.schemas import (
    AgentChatRequest,
    AgentChatResponse,
    AgentMessageOut,
    AgentOut,
    AgentRunDetail,
    AgentRunOut,
    AgentRunRequest,
)
from app.modules.agents.seed import agent_view, resolve_agent, seed_agent_catalog
from app.services.agents.chat import chat
from app.services.agents.orchestrator import run_agent

router = APIRouter(prefix="/agents", tags=["Autonomous Agents"])


def _run_out(run: AgentRun, agent_code: str) -> AgentRunOut:
    return AgentRunOut(
        id=run.id,
        agent_id=run.agent_id,
        agent_code=agent_code,
        incident_id=run.incident_id,
        task=run.task,
        status=run.status,
        autonomy_level=run.autonomy_level,
        input=run.input or {},
        output=run.output or {},
        evidence=list(run.evidence or []),
        model_id=run.model_id,
        started_at=run.started_at,
        finished_at=run.finished_at,
        error=run.error,
        created_by=run.created_by,
    )


def _run_detail(ctx: RequestContext, run: AgentRun, agent_code: str) -> AgentRunDetail:
    messages = list(
        ctx.db.execute(
            select(AgentMessage)
            .where(AgentMessage.run_id == run.id)
            .order_by(AgentMessage.created_at.asc(), AgentMessage.id.asc())
        ).scalars()
    )
    tools = [message for message in messages if message.role == "tool"]
    citations: list[dict] = []
    for message in messages:
        for citation in message.citations or []:
            if citation not in citations:
                citations.append(citation)
    base = _run_out(run, agent_code)
    return AgentRunDetail(
        **base.model_dump(),
        messages=[AgentMessageOut.model_validate(message) for message in messages],
        tools=[AgentMessageOut.model_validate(message) for message in tools],
        citations=citations,
        tool_calls=len(tools),
    )


def _get_run(ctx: RequestContext, run_id: UUID) -> tuple[AgentRun, Agent]:
    row = ctx.db.execute(
        select(AgentRun, Agent)
        .join(Agent, Agent.id == AgentRun.agent_id)
        .where(AgentRun.id == run_id, AgentRun.org_id == ctx.org.id)
    ).first()
    if row is None:
        raise NotFound("Agent run")
    return row[0], row[1]


@router.get("", response_model=list[AgentOut], summary="Read the agent catalogue")
def list_agents(
    ctx: RequestContext = Depends(require_permission("ai:read")),
    q: str | None = Query(default=None, max_length=120),
    capability: str | None = Query(default=None, max_length=80),
) -> list[AgentOut]:
    stmt = select(Agent).where(or_(Agent.org_id == ctx.org.id, Agent.org_id.is_(None))).order_by(Agent.code)
    rows = list(ctx.db.execute(stmt).scalars())
    if not rows:
        seed_agent_catalog(ctx.db, None)
        ctx.db.commit()
        rows = list(ctx.db.execute(stmt).scalars())

    by_code: dict[str, Agent] = {}
    for agent in rows:
        existing = by_code.get(agent.code)
        # Organization-specific definitions override the platform catalogue.
        if existing is None or (existing.org_id is None and agent.org_id is not None):
            by_code[agent.code] = agent
    agents = sorted(by_code.values(), key=lambda item: item.code)
    if q:
        needle = q.lower()
        agents = [
            agent
            for agent in agents
            if needle in agent.code.lower()
            or needle in agent.name.lower()
            or any(needle in capability.lower() for capability in (agent.capabilities or []))
        ]
    if capability:
        agents = [agent for agent in agents if capability in (agent.capabilities or [])]
    return [AgentOut(**agent_view(agent)) for agent in agents]


@router.get("/runs", response_model=Page[AgentRunOut], summary="List agent runs")
def list_runs(
    ctx: RequestContext = Depends(require_permission("ai:read")),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    agent_code: str | None = Query(default=None, max_length=60),
    status: str | None = Query(default=None, pattern="^(queued|running|completed|failed|canceled)$"),
    incident_id: UUID | None = Query(default=None),
) -> Page[AgentRunOut]:
    stmt = (
        select(AgentRun, Agent.code)
        .join(Agent, Agent.id == AgentRun.agent_id)
        .where(AgentRun.org_id == ctx.org.id)
        .order_by(AgentRun.started_at.desc())
    )
    if agent_code:
        stmt = stmt.where(Agent.code == agent_code)
    if status:
        stmt = stmt.where(AgentRun.status == status)
    if incident_id:
        stmt = stmt.where(AgentRun.incident_id == incident_id)
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).all()
    items = [_run_out(run, agent_code_value) for run, agent_code_value in rows]
    return Page[AgentRunOut](**paginate(items, total, page, page_size))


@router.get("/runs/{run_id}", response_model=AgentRunDetail, summary="Read an agent run with its full trail")
def get_run(run_id: UUID, ctx: RequestContext = Depends(require_permission("ai:read"))) -> AgentRunDetail:
    run, agent = _get_run(ctx, run_id)
    return _run_detail(ctx, run, agent.code)


@router.post("/runs/{run_id}/cancel", response_model=AgentRunOut, summary="Cancel a queued agent run")
def cancel_run(run_id: UUID, ctx: RequestContext = Depends(require_permission("ai:use"))) -> AgentRunOut:
    run, agent = _get_run(ctx, run_id)
    if run.status != "queued":
        raise Conflict("Only queued runs can be canceled")
    run.status = "canceled"
    run.finished_at = utcnow()
    run.output = {
        **(run.output or {}),
        "summary": "Run canceled before execution.",
        "analysis_mode": "canceled",
        "autonomy": f"{run.autonomy_level} observation only",
    }
    ctx.audit(
        action="agent.run.cancel",
        resource_type="agent_run",
        resource_id=str(run.id),
        payload={"agent_code": agent.code},
    )
    ctx.db.commit()
    ctx.db.refresh(run)
    return _run_out(run, agent.code)


@router.post("/chat", response_model=AgentChatResponse, summary="Stateless grounded Q&A with citations")
def agent_chat(
    payload: AgentChatRequest, ctx: RequestContext = Depends(require_permission("ai:use"))
) -> AgentChatResponse:
    result = chat(
        ctx.db,
        ctx.org.id,
        payload.message,
        top_k=payload.top_k,
        use_llm=payload.use_llm,
        request_id=ctx.request_id,
    )
    ctx.audit(
        action="agent.chat",
        resource_type="agent_run",
        payload={
            "analysis_mode": result["analysis_mode"],
            "citations": len(result["citations"]),
            "retrieved": result["retrieved"],
        },
    )
    ctx.db.commit()
    return AgentChatResponse(**result)


@router.get("/{code}", response_model=AgentOut, summary="Read one agent catalogue entry")
def get_agent(code: str, ctx: RequestContext = Depends(require_permission("ai:read"))) -> AgentOut:
    agent = resolve_agent(ctx.db, ctx.org.id, code)
    if agent is None:
        # Materialize the immutable catalogue on first access so operators can
        # inspect a role before a deployment has run the seed script.
        seed_agent_catalog(ctx.db, None)
        ctx.db.commit()
        agent = resolve_agent(ctx.db, ctx.org.id, code)
    if agent is None:
        raise NotFound("Agent")
    return AgentOut(**agent_view(agent))


@router.post("/{code}/runs", response_model=AgentRunDetail, status_code=201, summary="Execute an agent run")
def create_run(
    code: str,
    payload: AgentRunRequest,
    ctx: RequestContext = Depends(require_permission("ai:use")),
) -> AgentRunDetail:
    agent = resolve_agent(ctx.db, ctx.org.id, code)
    if agent is None:
        raise NotFound("Agent")
    if not agent.enabled:
        raise Conflict("This agent is disabled")
    if agent.max_autonomy not in {"A0", "A1", "A2"}:
        raise Forbidden("Agent autonomy exceeds the observation-only envelope")
    if payload.incident_id:
        incident = ctx.db.get(Incident, payload.incident_id)
        if incident is None or incident.org_id != ctx.org.id:
            raise NotFound("Incident")

    run = AgentRun(
        org_id=ctx.org.id,
        agent_id=agent.id,
        incident_id=payload.incident_id,
        task=payload.task.strip(),
        status="queued",
        autonomy_level=agent.max_autonomy,
        input={"context": payload.context, "use_llm": payload.use_llm},
        output={},
        evidence=[],
        created_by=ctx.actor_id,
    )
    ctx.db.add(run)
    ctx.db.flush()

    try:
        run_agent(
            ctx.db,
            run=run,
            agent=agent,
            org=ctx.org,
            use_llm=payload.use_llm,
            request_id=ctx.request_id,
        )
    except Exception as exc:
        run.status = "failed"
        run.error = str(exc)[:1000]
        run.finished_at = utcnow()
        ctx.audit(
            action="agent.run.execute",
            resource_type="agent_run",
            resource_id=str(run.id),
            outcome="failure",
            payload={"agent_code": agent.code, "error": str(exc)[:300]},
        )
        ctx.db.commit()
        raise

    ctx.audit(
        action="agent.run.execute",
        resource_type="agent_run",
        resource_id=str(run.id),
        payload={
            "agent_code": agent.code,
            "status": run.status,
            "analysis_mode": (run.output or {}).get("analysis_mode"),
            "tool_calls": (run.output or {}).get("tool_calls"),
            "incident_id": str(run.incident_id) if run.incident_id else None,
        },
    )
    ctx.db.commit()
    ctx.db.refresh(run)
    return _run_detail(ctx, run, agent.code)


__all__ = ["router"]
