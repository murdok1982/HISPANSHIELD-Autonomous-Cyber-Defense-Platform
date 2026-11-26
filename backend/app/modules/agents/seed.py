"""Idempotent seeding and resolution of the agent catalogue."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.models.ai import Agent
from app.modules.agents.catalog import AGENT_CATALOG, AGENTS_BY_CODE, AgentSpec


def _find_agent(db: Session, code: str, org_id: UUID | None) -> Agent | None:
    stmt = select(Agent).where(Agent.code == code)
    stmt = stmt.where(Agent.org_id.is_(None) if org_id is None else Agent.org_id == org_id)
    return db.execute(stmt).scalar_one_or_none()


def _apply(agent: Agent, spec: AgentSpec) -> None:
    agent.name = spec.name
    agent.description = spec.description
    agent.capabilities = list(spec.capabilities)
    agent.allowed_tools = list(spec.allowed_tools)
    agent.max_autonomy = spec.max_autonomy
    agent.system_prompt = spec.system_prompt


def seed_agent_catalog(db: Session, org_id: UUID | None = None) -> dict[str, Any]:
    """Create or refresh catalogue rows. Existing ``enabled`` flags are preserved."""
    created = 0
    updated = 0
    for spec in AGENT_CATALOG:
        agent = _find_agent(db, spec.code, org_id)
        if agent is None:
            agent = Agent(org_id=org_id, code=spec.code, enabled=True)
            _apply(agent, spec)
            db.add(agent)
            created += 1
        else:
            _apply(agent, spec)
            updated += 1
    db.flush()
    return {"created": created, "updated": updated, "total": len(AGENT_CATALOG)}


def resolve_agent(db: Session, org_id: UUID, code: str) -> Agent | None:
    """Organization-specific rows override the platform catalogue."""
    organization_agent = _find_agent(db, code, org_id)
    if organization_agent is not None:
        return organization_agent
    return _find_agent(db, code, None)


def seed_all_organizations(db: Session) -> dict[str, Any]:
    from app.models.core import Organization

    global_stats = seed_agent_catalog(db, None)
    organizations = list(db.execute(select(Organization).where(Organization.deleted_at.is_(None))).scalars())
    per_org = 0
    for organization in organizations:
        seed_agent_catalog(db, organization.id)
        per_org += 1
    db.flush()
    return {"global": global_stats, "organizations": per_org, "seeded_at": utcnow().isoformat()}


def agent_view(agent: Agent) -> dict[str, Any]:
    return {
        "id": str(agent.id),
        "org_id": str(agent.org_id) if agent.org_id else None,
        "code": agent.code,
        "name": agent.name,
        "description": agent.description,
        "capabilities": list(agent.capabilities or []),
        "allowed_tools": list(agent.allowed_tools or []),
        "max_autonomy": agent.max_autonomy,
        "system_prompt": agent.system_prompt,
        "enabled": agent.enabled,
        "catalog_available": agent.code in AGENTS_BY_CODE,
        "created_at": agent.created_at,
        "updated_at": agent.updated_at,
    }


seed_agents = seed_agent_catalog
seed_catalog = seed_agent_catalog

__all__ = [
    "agent_view",
    "resolve_agent",
    "seed_agent_catalog",
    "seed_agents",
    "seed_all_organizations",
    "seed_catalog",
]
