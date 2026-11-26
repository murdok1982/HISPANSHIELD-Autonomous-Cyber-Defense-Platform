"""Deterministic local embeddings plus optional provider-backed embeddings.

The default 384-dimension hashed bag-of-words vector requires no external
service, is stable across restarts and processes, and is L2-normalised so that
cosine similarity is a plain dot product. It is *not* a semantic model; it is a
auditable lexical baseline that never leaves the deployment.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.models.ai import AIModel, AIProvider
from app.services.llm.base import ProviderError
from app.services.llm.router import embeddings as provider_embeddings

LOCAL_MODEL_LABEL = "local-hash-v1"
DEFAULT_DIMENSION = 384
_TOKEN = re.compile(r"[0-9a-záéíóúüñ]+", re.IGNORECASE)


def tokenize(text: str) -> list[str]:
    return [token.lower() for token in _TOKEN.findall(text or "")]


def embed_text(text: str, dimension: int = DEFAULT_DIMENSION) -> list[float]:
    if dimension < 8:
        raise ValueError("embedding dimension must be at least 8")
    counts = Counter(tokenize(text))
    vector = [0.0] * dimension
    for token, count in counts.items():
        digest = hashlib.sha256(token.encode("utf-8")).digest()
        index = int.from_bytes(digest[:4], "big") % dimension
        sign = 1.0 if digest[4] & 1 else -1.0
        vector[index] += sign * (1.0 + math.log(count))
    norm = math.sqrt(sum(value * value for value in vector))
    if norm:
        vector = [value / norm for value in vector]
    return vector


def embed_texts(texts: list[str], dimension: int = DEFAULT_DIMENSION) -> list[list[float]]:
    return [embed_text(text, dimension=dimension) for text in texts]


def cosine_similarity(left: list[float], right: list[float]) -> float:
    if not left or not right or len(left) != len(right):
        return 0.0
    left_norm = math.sqrt(sum(value * value for value in left))
    right_norm = math.sqrt(sum(value * value for value in right))
    if not left_norm or not right_norm:
        return 0.0
    dot = sum(a * b for a, b in zip(left, right, strict=False))
    return max(-1.0, min(1.0, dot / (left_norm * right_norm)))


def keyword_score(query_tokens: list[str], text: str) -> float:
    query_set = {token for token in query_tokens if len(token) > 2}
    if not query_set:
        return 0.0
    chunk_tokens = set(tokenize(text))
    matched = len(query_set & chunk_tokens)
    return matched / len(query_set)


class LocalEmbeddingBackend:
    model_label = LOCAL_MODEL_LABEL
    dimension = DEFAULT_DIMENSION

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        return embed_texts(texts, dimension=self.dimension)


class ProviderEmbeddingBackend:
    def __init__(self, db: Session, org_id: UUID, model_name: str) -> None:
        self._db = db
        self._org_id = org_id
        self._model_name = model_name
        self.model_label = f"provider:{model_name}"
        self.dimension = 0

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        result = provider_embeddings(self._db, org_id=self._org_id, inputs=texts, model_name=self._model_name)
        vectors = result.embeddings
        if not vectors:
            raise ProviderError("Provider returned no embeddings")
        self.dimension = len(vectors[0])
        return vectors


def resolve_embedding_backend(db: Session, org_id: UUID) -> LocalEmbeddingBackend | ProviderEmbeddingBackend:
    """Prefer a configured healthy embedding model, otherwise use the local baseline."""
    row = db.execute(
        select(AIProvider, AIModel)
        .join(AIModel, AIModel.provider_id == AIProvider.id)
        .where(
            AIProvider.enabled.is_(True),
            AIProvider.health_status == "healthy",
            AIModel.status == "available",
            AIModel.task_tags.contains(["embedding"]),
            or_(AIProvider.org_id == org_id, AIProvider.org_id.is_(None)),
        )
        .order_by(AIProvider.name, AIModel.name)
        .limit(1)
    ).first()
    if row is None:
        return LocalEmbeddingBackend()
    return ProviderEmbeddingBackend(db, org_id, row[1].name)


__all__ = [
    "DEFAULT_DIMENSION",
    "LOCAL_MODEL_LABEL",
    "LocalEmbeddingBackend",
    "ProviderEmbeddingBackend",
    "cosine_similarity",
    "embed_text",
    "embed_texts",
    "keyword_score",
    "resolve_embedding_backend",
    "tokenize",
]
