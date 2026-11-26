"""Knowledge-document ingestion, replacement and deletion with cascade semantics."""

from __future__ import annotations

from math import ceil
from typing import Any
from uuid import UUID

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from app.core.crypto import sha256_hex
from app.core.errors import ServiceUnavailable
from app.models.ai import KnowledgeChunk, KnowledgeDocument
from app.services.llm.base import ProviderError
from app.services.rag.chunking import chunk_text
from app.services.rag.embeddings import LocalEmbeddingBackend, resolve_embedding_backend


def chunk_count(db: Session, document_id: UUID) -> int:
    return int(
        db.execute(
            select(func.count()).select_from(KnowledgeChunk).where(KnowledgeChunk.document_id == document_id)
        ).scalar_one()
    )


def _embed(chunks: list[str], db: Session, org_id: UUID) -> tuple[list[list[float]], str]:
    backend = resolve_embedding_backend(db, org_id)
    try:
        vectors = backend.embed_batch(chunks)
        if len(vectors) != len(chunks) or any(not vector for vector in vectors):
            raise ProviderError("Embedding provider returned an incomplete batch")
        return vectors, backend.model_label
    except (ProviderError, ServiceUnavailable):
        local = LocalEmbeddingBackend()
        return local.embed_batch(chunks), local.model_label


def _build_chunks(db: Session, org_id: UUID, document_id: UUID, text: str) -> int:
    pieces = chunk_text(text)
    vectors, model_label = _embed(pieces, db, org_id)
    for ordinal, (piece, vector) in enumerate(zip(pieces, vectors, strict=True)):
        db.add(
            KnowledgeChunk(
                document_id=document_id,
                org_id=org_id,
                ordinal=ordinal,
                text=piece,
                embedding=[float(value) for value in vector],
                embedding_model=model_label,
                tokens=max(1, ceil(len(piece) / 4)),
            )
        )
    db.flush()
    return len(pieces)


def ingest_document(
    db: Session,
    org_id: UUID,
    *,
    title: str,
    source: str,
    kind: str,
    version: str,
    text: str,
    metadata: dict[str, Any] | None = None,
    created_by: str | None = None,
) -> KnowledgeDocument:
    document = KnowledgeDocument(
        org_id=org_id,
        title=title.strip(),
        source=source.strip(),
        kind=kind,
        version=version.strip(),
        checksum=sha256_hex(text),
        text=text,
        metadata_json=metadata or {},
        created_by=created_by,
    )
    db.add(document)
    db.flush()
    _build_chunks(db, org_id, document.id, text)
    return document


def replace_document_text(db: Session, document: KnowledgeDocument, text: str) -> int:
    db.execute(delete(KnowledgeChunk).where(KnowledgeChunk.document_id == document.id))
    document.text = text
    document.checksum = sha256_hex(text)
    db.flush()
    return _build_chunks(db, document.org_id, document.id, text)


def delete_document(db: Session, document: KnowledgeDocument) -> None:
    db.execute(delete(KnowledgeChunk).where(KnowledgeChunk.document_id == document.id))
    db.delete(document)


def document_view(db: Session, document: KnowledgeDocument, *, include_chunks: bool = False) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": str(document.id),
        "org_id": str(document.org_id),
        "title": document.title,
        "source": document.source,
        "kind": document.kind,
        "version": document.version,
        "checksum": document.checksum,
        "metadata": document.metadata_json,
        "chunk_count": chunk_count(db, document.id),
        "created_at": document.created_at,
        "updated_at": document.updated_at,
    }
    if include_chunks:
        chunks = list(
            db.execute(
                select(KnowledgeChunk).where(KnowledgeChunk.document_id == document.id).order_by(KnowledgeChunk.ordinal)
            ).scalars()
        )
        payload["text"] = document.text
        payload["chunks"] = [
            {
                "id": str(chunk.id),
                "ordinal": chunk.ordinal,
                "text": chunk.text,
                "tokens": chunk.tokens,
                "embedding_model": chunk.embedding_model,
                "embedding_dimension": len(chunk.embedding or []),
            }
            for chunk in chunks
        ]
    return payload


__all__ = [
    "chunk_count",
    "delete_document",
    "document_view",
    "ingest_document",
    "replace_document_text",
]
