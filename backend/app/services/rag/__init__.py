"""Local RAG: chunking, deterministic embeddings and tenant-scoped retrieval."""

from app.services.rag.chunking import DEFAULT_MAX_CHARS, DEFAULT_OVERLAP, chunk_text, split_sentences
from app.services.rag.embeddings import (
    DEFAULT_DIMENSION,
    LOCAL_MODEL_LABEL,
    LocalEmbeddingBackend,
    ProviderEmbeddingBackend,
    cosine_similarity,
    embed_text,
    embed_texts,
    keyword_score,
    resolve_embedding_backend,
    tokenize,
)
from app.services.rag.retrieval import search_knowledge
from app.services.rag.service import (
    chunk_count,
    delete_document,
    document_view,
    ingest_document,
    replace_document_text,
)

__all__ = [
    "DEFAULT_DIMENSION",
    "DEFAULT_MAX_CHARS",
    "DEFAULT_OVERLAP",
    "LOCAL_MODEL_LABEL",
    "LocalEmbeddingBackend",
    "ProviderEmbeddingBackend",
    "chunk_count",
    "chunk_text",
    "cosine_similarity",
    "delete_document",
    "document_view",
    "embed_text",
    "embed_texts",
    "ingest_document",
    "keyword_score",
    "replace_document_text",
    "resolve_embedding_backend",
    "search_knowledge",
    "split_sentences",
    "tokenize",
]
