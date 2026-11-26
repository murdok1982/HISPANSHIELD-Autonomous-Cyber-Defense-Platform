"""AI usage analytics and gateway health/readiness."""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select

from app.core.db import utcnow
from app.core.deps import RequestContext, require_permission
from app.models.ai import AIInvocation, AIModel, AIProvider, KnowledgeChunk, KnowledgeDocument
from app.services.llm.router import healthy_provider_summary

router = APIRouter(tags=["AI Gateway"])


def _percentile(values: list[int], ratio: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * ratio))))
    return ordered[index]


def _empty_bucket() -> dict[str, Any]:
    return {"count": 0, "success": 0, "error": 0, "prompt_tokens": 0, "completion_tokens": 0, "latencies": []}


def _finalize(bucket: dict[str, Any]) -> dict[str, Any]:
    latencies = bucket.pop("latencies")
    count = bucket["count"]
    bucket["avg_latency_ms"] = round(sum(latencies) / count, 1) if count else 0.0
    bucket["p95_latency_ms"] = _percentile(latencies, 0.95)
    return bucket


@router.get("/usage", summary="Invocation statistics by task, model and status")
def usage(
    ctx: RequestContext = Depends(require_permission("ai:read")),
    days: int = Query(default=7, ge=1, le=90),
) -> dict[str, Any]:
    since = utcnow() - timedelta(days=days)
    rows = list(
        ctx.db.execute(
            select(AIInvocation)
            .where(AIInvocation.org_id == ctx.org.id, AIInvocation.created_at >= since)
            .order_by(AIInvocation.created_at.desc())
            .limit(50_000)
        ).scalars()
    )
    totals = _empty_bucket()
    by_task: dict[str, dict[str, Any]] = defaultdict(_empty_bucket)
    by_model: dict[str, dict[str, Any]] = defaultdict(_empty_bucket)
    by_status: dict[str, int] = defaultdict(int)

    for row in rows:
        for bucket in (totals, by_task[row.task], by_model[row.model]):
            bucket["count"] += 1
            bucket["success" if row.status == "success" else "error"] += 1
            bucket["prompt_tokens"] += row.prompt_tokens
            bucket["completion_tokens"] += row.completion_tokens
            bucket["latencies"].append(row.latency_ms)
        by_status[row.status] += 1

    finalized_totals = _finalize(totals)
    return {
        "window_days": days,
        "since": since.isoformat(),
        "totals": finalized_totals,
        "by_task": {name: _finalize(bucket) for name, bucket in sorted(by_task.items())},
        "by_model": {name: _finalize(bucket) for name, bucket in sorted(by_model.items())},
        "by_status": dict(by_status),
        "invocations": len(rows),
    }


@router.get("/health", summary="AI gateway availability and recent error rate")
def ai_health(ctx: RequestContext = Depends(require_permission("ai:read"))) -> dict[str, Any]:
    summary = healthy_provider_summary(ctx.db, ctx.org.id)
    since = utcnow() - timedelta(hours=24)
    invocation_rows = ctx.db.execute(
        select(AIInvocation.status, func.count())
        .where(AIInvocation.org_id == ctx.org.id, AIInvocation.created_at >= since)
        .group_by(AIInvocation.status)
    ).all()
    invocation_counts = {str(status): int(count) for status, count in invocation_rows}
    total_invocations = sum(invocation_counts.values())
    errors = invocation_counts.get("error", 0)

    model_counts = ctx.db.execute(
        select(AIModel.status, func.count())
        .join(AIProvider, AIProvider.id == AIModel.provider_id)
        .where(or_(AIProvider.org_id == ctx.org.id, AIProvider.org_id.is_(None)))
        .group_by(AIModel.status)
    ).all()
    knowledge_documents = ctx.db.execute(
        select(func.count()).select_from(KnowledgeDocument).where(KnowledgeDocument.org_id == ctx.org.id)
    ).scalar_one()
    knowledge_chunks = ctx.db.execute(
        select(func.count()).select_from(KnowledgeChunk).where(KnowledgeChunk.org_id == ctx.org.id)
    ).scalar_one()

    return {
        "status": "ok" if summary["available"] else "degraded",
        "ai_available": summary["available"],
        "generated_at": utcnow().isoformat(),
        **summary,
        "models": {str(status): int(count) for status, count in model_counts},
        "knowledge": {"documents": int(knowledge_documents), "chunks": int(knowledge_chunks)},
        "invocations_24h": {
            "total": total_invocations,
            "by_status": invocation_counts,
            "error_rate": round(errors / total_invocations, 4) if total_invocations else 0.0,
        },
    }


__all__ = ["router"]
