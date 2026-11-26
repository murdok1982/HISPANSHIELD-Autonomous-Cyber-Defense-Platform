"""Pydantic contracts for the AI gateway, model registry, evaluation and RAG."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import Field, field_validator, model_validator

from app.core.schemas import ORMModel, StrictModel

PROVIDER_KIND = r"^(ollama|vllm|llamacpp|openai_compatible)$"
TASK_PATTERN = r"^[a-z][a-z0-9_.-]{1,59}$"


def _bounded_json_dict(value: dict[str, Any]) -> dict[str, Any]:
    import json

    try:
        serialized = json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError) as exc:
        raise ValueError("Value must be JSON serializable") from exc
    if len(serialized) > 16_384:
        raise ValueError("JSON object exceeds 16384 bytes")
    return json.loads(serialized)


class ProviderCreate(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    kind: str = Field(pattern=PROVIDER_KIND)
    base_url: str = Field(min_length=8, max_length=500)
    default_model: str | None = Field(default=None, min_length=1, max_length=160)
    api_key: str | None = Field(default=None, min_length=1, max_length=500)
    is_local: bool = True
    enabled: bool = True
    config: dict[str, Any] = Field(default_factory=dict)
    scope: Literal["organization", "platform"] = "organization"

    @field_validator("config")
    @classmethod
    def _bound_config(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _bounded_json_dict(value)


class ProviderPatch(StrictModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    kind: str | None = Field(default=None, pattern=PROVIDER_KIND)
    base_url: str | None = Field(default=None, min_length=8, max_length=500)
    default_model: str | None = Field(default=None, min_length=1, max_length=160)
    api_key: str | None = Field(default=None, min_length=1, max_length=500)
    clear_api_key: bool = False
    is_local: bool | None = None
    enabled: bool | None = None
    config: dict[str, Any] | None = None

    @field_validator("config")
    @classmethod
    def _bound_config(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return None if value is None else _bounded_json_dict(value)


class ProviderOut(ORMModel):
    id: UUID
    org_id: UUID | None
    name: str
    kind: str
    base_url: str
    default_model: str | None
    is_local: bool
    enabled: bool
    health_status: str
    last_health_at: datetime | None
    last_health_error: str | None
    last_error: str | None = None
    config: dict[str, Any]
    has_api_key: bool
    created_at: datetime
    updated_at: datetime


class ProviderHealthOut(StrictModel):
    provider_id: UUID
    healthy: bool
    health_status: str
    error: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
    checked_at: datetime


class ModelCreate(StrictModel):
    provider_id: UUID
    name: str = Field(min_length=1, max_length=160)
    display_name: str | None = Field(default=None, max_length=160)
    task_tags: list[str] = Field(default_factory=list, max_length=20)
    context_window: int = Field(default=8192, ge=256, le=2_000_000)
    max_output_tokens: int = Field(default=2048, ge=1, le=200_000)
    status: str = Field(default="available", pattern="^(available|disabled|deprecated)$")

    @field_validator("task_tags")
    @classmethod
    def _valid_tags(cls, value: list[str]) -> list[str]:
        import re

        pattern = re.compile(TASK_PATTERN)
        cleaned: list[str] = []
        for tag in value:
            if not pattern.match(tag):
                raise ValueError(f"Invalid task tag: {tag}")
            if tag not in cleaned:
                cleaned.append(tag)
        return cleaned

    @model_validator(mode="after")
    def _output_within_context(self) -> ModelCreate:
        if self.max_output_tokens > self.context_window:
            raise ValueError("max_output_tokens must not exceed context_window")
        return self


class ModelPatch(StrictModel):
    display_name: str | None = Field(default=None, max_length=160)
    task_tags: list[str] | None = Field(default=None, max_length=20)
    context_window: int | None = Field(default=None, ge=256, le=2_000_000)
    max_output_tokens: int | None = Field(default=None, ge=1, le=200_000)
    status: str | None = Field(default=None, pattern="^(available|disabled|deprecated)$")

    @field_validator("task_tags")
    @classmethod
    def _valid_tags(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        return ModelCreate._valid_tags(value)


class ModelOut(ORMModel):
    id: UUID
    provider_id: UUID
    provider_name: str | None = None
    name: str
    display_name: str | None
    task_tags: list[str]
    context_window: int
    max_output_tokens: int
    status: str
    evaluation: dict[str, Any]
    created_at: datetime
    updated_at: datetime


class ModelDiscoverOut(StrictModel):
    provider_id: UUID
    provider_name: str
    discovered: int
    created: int
    updated: int
    models: list[ModelOut]


class MessageIn(StrictModel):
    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=1, max_length=32000)


class CompleteRequest(StrictModel):
    task: str = Field(default="chat", pattern=TASK_PATTERN)
    prompt: str | None = Field(default=None, min_length=1, max_length=32000)
    messages: list[MessageIn] | None = Field(default=None, min_length=1, max_length=50)
    model: str | None = Field(default=None, min_length=1, max_length=160)
    max_tokens: int | None = Field(default=None, ge=1, le=32768)
    temperature: float = Field(default=0.2, ge=0.0, le=2.0)
    expect_json: bool = False

    @model_validator(mode="after")
    def _exactly_one_input(self) -> CompleteRequest:
        if (self.prompt is None) == (self.messages is None):
            raise ValueError("Provide exactly one of 'prompt' or 'messages'")
        return self


class UsageOut(StrictModel):
    prompt_tokens: int
    completion_tokens: int


class CompleteResponse(StrictModel):
    content: str
    model: str
    provider_id: UUID
    provider_name: str
    task: str
    usage: UsageOut
    latency_ms: int
    invocation_id: UUID
    parsed: Any | None = None
    parse_error: str | None = None


class EmbeddingsRequest(StrictModel):
    input: str | list[str]
    model: str | None = Field(default=None, min_length=1, max_length=160)

    @field_validator("input")
    @classmethod
    def _bound_inputs(cls, value: str | list[str]) -> str | list[str]:
        items = [value] if isinstance(value, str) else value
        if not items:
            raise ValueError("At least one input is required")
        if len(items) > 32:
            raise ValueError("At most 32 inputs are allowed per request")
        for item in items:
            if not isinstance(item, str) or not item.strip():
                raise ValueError("Embedding inputs must be non-empty strings")
            if len(item) > 20000:
                raise ValueError("Embedding input exceeds 20000 characters")
        return value


class EmbeddingsResponse(StrictModel):
    model: str
    provider_id: UUID
    provider_name: str
    dimension: int
    embeddings: list[list[float]]
    usage: UsageOut


class EvaluationCase(StrictModel):
    name: str = Field(min_length=1, max_length=120)
    prompt: str = Field(min_length=5, max_length=8000)
    max_tokens: int | None = Field(default=None, ge=16, le=4096)
    expect_json: bool = False
    required_keys: list[str] = Field(default_factory=list, max_length=20)

    @field_validator("required_keys")
    @classmethod
    def _bound_keys(cls, value: list[str]) -> list[str]:
        if any(len(key) > 120 for key in value):
            raise ValueError("required_keys entries must be at most 120 characters")
        return value

    require_citation: bool = False
    should_refuse: bool = False
    injection_canary: str | None = Field(default=None, max_length=80)


class EvaluateRequest(StrictModel):
    cases: list[EvaluationCase] | None = Field(default=None, max_length=20)


class KnowledgeDocumentCreate(StrictModel):
    title: str = Field(min_length=1, max_length=300)
    source: str = Field(min_length=1, max_length=500)
    kind: str = Field(default="runbook", pattern="^(runbook|playbook|policy|sop|reference|other)$")
    version: str = Field(default="1", min_length=1, max_length=40)
    text: str = Field(min_length=10, max_length=200_000)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def _bound_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _bounded_json_dict(value)


class KnowledgeDocumentPatch(StrictModel):
    title: str | None = Field(default=None, min_length=1, max_length=300)
    source: str | None = Field(default=None, min_length=1, max_length=500)
    kind: str | None = Field(default=None, pattern="^(runbook|playbook|policy|sop|reference|other)$")
    version: str | None = Field(default=None, min_length=1, max_length=40)
    text: str | None = Field(default=None, min_length=10, max_length=200_000)
    metadata: dict[str, Any] | None = None

    @field_validator("metadata")
    @classmethod
    def _bound_metadata(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        return None if value is None else _bounded_json_dict(value)


class KnowledgeDocumentOut(StrictModel):
    id: UUID
    org_id: UUID
    title: str
    source: str
    kind: str
    version: str
    checksum: str
    metadata: dict[str, Any]
    chunk_count: int
    created_at: datetime
    updated_at: datetime


class KnowledgeChunkOut(StrictModel):
    id: UUID
    ordinal: int
    text: str
    tokens: int
    embedding_model: str
    embedding_dimension: int


class KnowledgeDocumentDetail(KnowledgeDocumentOut):
    text: str
    chunks: list[KnowledgeChunkOut]


class KnowledgeSearchRequest(StrictModel):
    query: str = Field(min_length=2, max_length=1000)
    top_k: int = Field(default=5, ge=1, le=10)
    kinds: list[str] | None = Field(default=None, max_length=6)


class CitationOut(StrictModel):
    document_id: str
    title: str
    source: str
    chunk_id: str
    snippet: str
    score: float


class SearchResultOut(CitationOut):
    kind: str
    ordinal: int
    checksum: str
    version: str
    updated_at: str | None = None


class KnowledgeSearchResponse(StrictModel):
    query: str
    results: list[SearchResultOut]
    citations: list[CitationOut]
    count: int
    embedding_models: list[str]
    scanned_chunks: int
