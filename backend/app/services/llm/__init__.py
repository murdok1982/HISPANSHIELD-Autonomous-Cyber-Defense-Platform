"""Local-first LLM gateway services."""

from app.services.llm.base import ChatResult, HealthResult, ProviderError
from app.services.llm.router import (
    CompletionResult,
    EmbeddingResult,
    check_provider_health,
    client_for,
    complete,
    discover_models,
    embeddings,
    healthy_provider_summary,
)
from app.services.llm.safety import (
    SafetyVerdict,
    compose_messages,
    looks_like_refusal,
    neutralize,
    redact_prompt,
    scan_injection,
    wrap_untrusted_data,
)

__all__ = [
    "ChatResult",
    "CompletionResult",
    "EmbeddingResult",
    "HealthResult",
    "ProviderError",
    "SafetyVerdict",
    "check_provider_health",
    "client_for",
    "complete",
    "compose_messages",
    "discover_models",
    "embeddings",
    "healthy_provider_summary",
    "looks_like_refusal",
    "neutralize",
    "redact_prompt",
    "scan_injection",
    "wrap_untrusted_data",
]
