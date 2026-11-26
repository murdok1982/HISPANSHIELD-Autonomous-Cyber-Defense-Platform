"""Tenant-scoped hybrid retrieval (cosine + lexical keyword overlap) with citations."""

from __future__ import annotations

from datetime import UTC
from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import ServiceUnavailable
from app.models.ai import KnowledgeChunk, KnowledgeDocument
from app.services.llm.base import ProviderError
from app.services.llm.router import embeddings as provider_embeddings
from app.services.llm.safety import neutralize
from app.services.rag.embeddings import (
    LOCAL_MODEL_LABEL,
    cosine_similarity,
    embed_text,
    keyword_score,
    tokenize,
)

MAX_SCANNED_CHUNKS = 20_000
MAX_SNIPPET_CHARS = 400


def _query_vector(
    db: Session,
    org_id: UUID,
    model_label: str,
    query: str,
    cache: dict[str, list[float] | None],
) -> list[float] | None:
    if model_label in cache:
        return cache[model_label]
    if model_label == LOCAL_MODEL_LABEL:
        cache[model_label] = embed_text(query)
        return cache[model_label]
    if model_label.startswith("provider:"):
        model_name = model_label.split(":", 1)[1]
        try:
            result = provider_embeddings(db, org_id=org_id, inputs=[query], model_name=model_name, task="search")
        except (ServiceUnavailable, ProviderError):
            cache[model_label] = None
            return None
        vector = result.embeddings[0] if result.embeddings else None
        cache[model_label] = vector
        return vector
    cache[model_label] = None
    return None


def _snippet(text: str) -> str:
    bounded = neutralize(text or "", max_chars=MAX_SNIPPET_CHARS)
    if len(bounded) >= MAX_SNIPPET_CHARS:
        return bounded.rstrip()[:MAX_SNIPPET_CHARS]
    return bounded


def search_knowledge(
    db: Session,
    org_id: UUID,
    query: str,
    *,
    top_k: int = 5,
    kinds: list[str] | None = None,
) -> dict[str, Any]:
    """Search only the caller's organization; cross-tenant rows are never loaded."""
    top_k = max(1, min(int(top_k), 10))
    stmt = (
        select(KnowledgeChunk, KnowledgeDocument)
        .join(KnowledgeDocument, KnowledgeDocument.id == KnowledgeChunk.document_id)
        .where(
            KnowledgeChunk.org_id == org_id,
            KnowledgeDocument.org_id == org_id,
        )
        .order_by(KnowledgeChunk.document_id, KnowledgeChunk.ordinal)
        .limit(MAX_SCANNED_CHUNKS)
    )
    if kinds:
        stmt = stmt.where(KnowledgeDocument.kind.in_(kinds))
    rows = db.execute(stmt).all()

    query_tokens = tokenize(query)
    cache: dict[str, list[float] | None] = {}
    scored: list[dict[str, Any]] = []
    used_models: set[str] = set()

    for chunk, document in rows:
        label = chunk.embedding_model or LOCAL_MODEL_LABEL
        vector = _query_vector(db, org_id, label, query, cache)
        if not vector or not chunk.embedding:
            continue
        used_models.add(label)
        similarity = cosine_similarity(vector, [float(value) for value in chunk.embedding])
        lexical = keyword_score(query_tokens, chunk.text)
        score = (0.7 * similarity) + (0.3 * lexical)
        if score <= 0:
            continue
        scored.append(
            {
                "document_id": str(document.id),
                "title": document.title,
                "source": document.source,
                "kind": document.kind,
                "chunk_id": str(chunk.id),
                "ordinal": chunk.ordinal,
                "snippet": _snippet(chunk.text),
                "score": round(score, 6),
                "checksum": document.checksum,
                "version": document.version,
                "updated_at": document.updated_at.astimezone(UTC).isoformat() if document.updated_at else None,
            }
        )

    scored.sort(key=lambda item: (-item["score"], item["document_id"], item["chunk_id"]))
    results = scored[:top_k]
    citations = [
        {
            "document_id": item["document_id"],
            "title": item["title"],
            "source": item["source"],
            "chunk_id": item["chunk_id"],
            "snippet": item["snippet"],
            "score": item["score"],
        }
        for item in results
    ]
    return {
        "query": query,
        "results": results,
        "citations": citations,
        "count": len(results),
        "embedding_models": sorted(used_models),
        "scanned_chunks": len(rows),
    }


__all__ = ["MAX_SCANNED_CHUNKS", "search_knowledge"]
