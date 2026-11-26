"""Pydantic contracts for MCP server governance and tool execution."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field, field_validator

from app.core.schemas import ORMModel, StrictModel


class MCPServerCreate(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    transport: str = Field(default="http", pattern="^http$")
    endpoint: str = Field(min_length=8, max_length=500)
    version: str | None = Field(default=None, max_length=40)
    trust_level: str = Field(default="untrusted", pattern="^(untrusted|limited|trusted)$")


class MCPServerPatch(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    endpoint: str | None = Field(default=None, min_length=8, max_length=500)
    version: str | None = Field(default=None, max_length=40)
    trust_level: str | None = Field(default=None, pattern="^(untrusted|limited|trusted)$")


class MCPServerOut(ORMModel):
    id: UUID
    org_id: UUID
    name: str
    transport: str
    endpoint: str | None
    version: str | None
    trust_level: str
    status: str
    enabled: bool
    approved_by: str | None
    approved_at: datetime | None
    capabilities: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class MCPToolOut(ORMModel):
    id: UUID
    org_id: UUID
    server_id: UUID
    name: str
    version: str | None
    description: str | None
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    risk_level: str
    permissions_required: list[str]
    enabled: bool
    approved: bool
    timeout_seconds: int
    max_calls_per_hour: int
    created_at: datetime
    updated_at: datetime


class MCPDiscoverOut(StrictModel):
    server_id: UUID
    protocol_version: str | None
    server_info: dict[str, Any]
    discovered: int
    created: int
    updated: int
    tools: list[MCPToolOut]


class MCPToolApprove(StrictModel):
    approved: bool = True
    timeout_seconds: int | None = Field(default=None, ge=1, le=120)
    max_calls_per_hour: int | None = Field(default=None, ge=1, le=10_000)


class MCPToolExecute(StrictModel):
    arguments: dict[str, Any] = Field(default_factory=dict)
    agent_run_id: UUID | None = None

    @field_validator("arguments")
    @classmethod
    def _bounded_arguments(cls, value: dict[str, Any]) -> dict[str, Any]:
        import json

        try:
            serialized = json.dumps(value, ensure_ascii=False, default=str)
        except (TypeError, ValueError) as exc:
            raise ValueError("arguments must be JSON serializable") from exc
        if len(serialized) > 16_384:
            raise ValueError("arguments exceed 16384 bytes")
        return json.loads(serialized)


class MCPExecutionOut(StrictModel):
    execution_id: UUID
    tool_id: UUID
    tool_name: str
    status: str
    latency_ms: int
    injection_suspected: bool
    injection_matches: list[str]
    truncated: bool
    result: Any
    error: str | None = None


class ToolExecutionOut(ORMModel):
    id: UUID
    org_id: UUID
    tool_id: UUID | None
    agent_run_id: UUID | None
    tool_name: str
    arguments_redacted: dict[str, Any]
    result_redacted: dict[str, Any]
    status: str
    error: str | None
    latency_ms: int | None
    created_by: str | None
    created_at: datetime
