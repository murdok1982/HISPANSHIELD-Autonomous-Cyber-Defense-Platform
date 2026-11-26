"""Pydantic contracts for the agent catalogue, runs and grounded chat."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field, field_validator

from app.core.schemas import ORMModel, StrictModel

MAX_CONTEXT_BYTES = 16_000


class AgentOut(StrictModel):
    id: UUID
    org_id: UUID | None
    code: str
    name: str
    description: str | None
    capabilities: list[str]
    allowed_tools: list[str]
    max_autonomy: str
    system_prompt: str | None
    enabled: bool
    catalog_available: bool
    created_at: datetime
    updated_at: datetime


class AgentRunRequest(StrictModel):
    task: str = Field(min_length=5, max_length=4000)
    incident_id: UUID | None = None
    context: dict[str, Any] = Field(default_factory=dict)
    use_llm: bool = True

    @field_validator("context")
    @classmethod
    def _bounded_context(cls, value: dict[str, Any]) -> dict[str, Any]:
        try:
            serialized = json.dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError) as exc:
            raise ValueError("context must be JSON serializable") from exc
        if len(serialized) > MAX_CONTEXT_BYTES:
            raise ValueError(f"context exceeds {MAX_CONTEXT_BYTES} bytes")
        # Normalise to JSON-native values so persistence cannot fail later.
        return json.loads(serialized)


class AgentMessageOut(ORMModel):
    id: UUID
    role: str
    content: str
    tool_name: str | None
    tool_input: dict[str, Any]
    tool_output: dict[str, Any]
    citations: list[dict[str, Any]]
    created_at: datetime


class AgentRunOut(StrictModel):
    id: UUID
    agent_id: UUID
    agent_code: str
    incident_id: UUID | None
    task: str
    status: str
    autonomy_level: str
    input: dict[str, Any]
    output: dict[str, Any]
    evidence: list[dict[str, Any]]
    model_id: UUID | None
    started_at: datetime
    finished_at: datetime | None
    error: str | None
    created_by: str | None


class AgentRunDetail(AgentRunOut):
    messages: list[AgentMessageOut]
    tools: list[AgentMessageOut]
    citations: list[dict[str, Any]]
    tool_calls: int


class AgentChatRequest(StrictModel):
    message: str = Field(min_length=2, max_length=4000)
    top_k: int = Field(default=5, ge=1, le=10)
    use_llm: bool = True


class AgentChatResponse(StrictModel):
    answer: str
    citations: list[dict[str, Any]]
    analysis_mode: str
    model: str | None
    retrieved: int
    generated_at: datetime | str
