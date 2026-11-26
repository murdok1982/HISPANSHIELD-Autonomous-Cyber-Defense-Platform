"""Synchronous inference endpoints: chat completion and embeddings."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.core.deps import RequestContext, require_permission
from app.core.errors import ServiceUnavailable, ValidationFailure
from app.modules.ai.schemas import (
    CompleteRequest,
    CompleteResponse,
    EmbeddingsRequest,
    EmbeddingsResponse,
    UsageOut,
)
from app.services.llm.router import complete, embeddings
from app.services.llm.safety import scan_injection

router = APIRouter(tags=["AI Gateway"])


@router.post("/complete", response_model=CompleteResponse, summary="Route a completion to a healthy local model")
def create_completion(
    payload: CompleteRequest, ctx: RequestContext = Depends(require_permission("ai:use"))
) -> CompleteResponse:
    messages = (
        [{"role": message.role, "content": message.content} for message in payload.messages]
        if payload.messages
        else [{"role": "user", "content": payload.prompt or ""}]
    )
    if not messages:
        raise ValidationFailure([{"field": "messages", "message": "At least one message is required"}])

    try:
        result = complete(
            ctx.db,
            org_id=ctx.org.id,
            task=payload.task,
            messages=messages,
            model_name=payload.model,
            max_tokens=payload.max_tokens,
            temperature=payload.temperature,
            expect_json=payload.expect_json,
            request_id=ctx.request_id,
        )
    except ServiceUnavailable:
        # Persist the invocation error and provider health degradation before returning 503.
        ctx.db.commit()
        raise

    flagged = scan_injection(result.content)
    ctx.audit(
        action="ai.complete",
        resource_type="ai_invocation",
        resource_id=str(result.invocation_id),
        payload={
            "task": result.task,
            "model": result.model,
            "provider_id": str(result.provider_id),
            "prompt_tokens": result.prompt_tokens,
            "completion_tokens": result.completion_tokens,
            "output_flagged": flagged.suspected,
        },
    )
    ctx.db.commit()
    return CompleteResponse(
        content=result.content,
        model=result.model,
        provider_id=result.provider_id,
        provider_name=result.provider_name,
        task=result.task,
        usage=UsageOut(prompt_tokens=result.prompt_tokens, completion_tokens=result.completion_tokens),
        latency_ms=result.latency_ms,
        invocation_id=result.invocation_id,
        parsed=result.parsed,
        parse_error=result.parse_error,
    )


@router.post("/embeddings", response_model=EmbeddingsResponse, summary="Generate embeddings with a healthy model")
def create_embeddings(
    payload: EmbeddingsRequest, ctx: RequestContext = Depends(require_permission("ai:use"))
) -> EmbeddingsResponse:
    inputs = [payload.input] if isinstance(payload.input, str) else list(payload.input)
    try:
        result = embeddings(
            ctx.db,
            org_id=ctx.org.id,
            inputs=inputs,
            model_name=payload.model,
            request_id=ctx.request_id,
        )
    except ServiceUnavailable:
        ctx.db.commit()
        raise

    dimension = len(result.embeddings[0]) if result.embeddings else 0
    ctx.audit(
        action="ai.embeddings",
        resource_type="ai_invocation",
        resource_id=str(result.invocation_id),
        payload={"model": result.model, "inputs": len(inputs), "dimension": dimension},
    )
    ctx.db.commit()
    return EmbeddingsResponse(
        model=result.model,
        provider_id=result.provider_id,
        provider_name=result.provider_name,
        dimension=dimension,
        embeddings=result.embeddings,
        usage=UsageOut(prompt_tokens=result.prompt_tokens, completion_tokens=0),
    )


__all__ = ["router"]
