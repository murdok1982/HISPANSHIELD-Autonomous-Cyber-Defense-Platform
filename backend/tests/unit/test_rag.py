"""Unit tests for chunking, deterministic embeddings and hybrid scoring."""

from __future__ import annotations

import math

from app.services.rag.chunking import DEFAULT_MAX_CHARS, chunk_text, split_sentences
from app.services.rag.embeddings import (
    DEFAULT_DIMENSION,
    LOCAL_MODEL_LABEL,
    LocalEmbeddingBackend,
    cosine_similarity,
    embed_text,
    embed_texts,
    keyword_score,
    tokenize,
)


def _long_text(sentences: int = 30) -> str:
    return " ".join(
        f"Sentence number {index} documents the verified containment procedure for incident {index}."
        for index in range(sentences)
    )


def test_chunk_text_respects_max_size() -> None:
    chunks = chunk_text(_long_text(), max_chars=DEFAULT_MAX_CHARS, overlap=120)
    assert len(chunks) > 2
    assert all(0 < len(chunk) <= DEFAULT_MAX_CHARS for chunk in chunks)


def test_chunk_text_keeps_overlap_between_chunks() -> None:
    chunks = chunk_text(_long_text(40), max_chars=500, overlap=120)
    assert len(chunks) >= 3
    assert chunks[1][:40] in chunks[0]
    assert chunks[2][:40] in chunks[1]


def test_chunk_text_short_input_single_chunk() -> None:
    text = "Collect volatile memory. Preserve the disk image. Record the chain of custody."
    assert chunk_text(text) == [text]


def test_chunk_text_hard_splits_oversized_token() -> None:
    chunks = chunk_text("A" * 2500, max_chars=600, overlap=50)
    assert len(chunks) >= 4
    assert all(len(chunk) <= 600 for chunk in chunks)


def test_split_sentences_bounds() -> None:
    sentences = split_sentences("First sentence. Second sentence!\n\nThird question?")
    assert sentences == ["First sentence.", "Second sentence!", "Third question?"]


def test_embedding_is_deterministic() -> None:
    text = "Credential compromise runbook with containment and verification steps."
    assert embed_text(text) == embed_text(text)
    assert embed_texts([text]) == [embed_text(text)]


def test_embedding_dimension_and_l2_norm() -> None:
    vector = embed_text("incident response playbook")
    assert len(vector) == DEFAULT_DIMENSION
    norm = math.sqrt(sum(value * value for value in vector))
    assert norm == 1.0


def test_empty_text_yields_zero_vector() -> None:
    vector = embed_text("")
    assert len(vector) == DEFAULT_DIMENSION
    assert all(value == 0.0 for value in vector)


def test_similar_texts_score_higher_than_unrelated() -> None:
    query = embed_text("incident response containment runbook")
    related = embed_text("incident response containment procedure runbook")
    unrelated = embed_text("banana smoothie recipe with tropical fruit")
    assert cosine_similarity(query, related) > cosine_similarity(query, unrelated)


def test_keyword_score() -> None:
    tokens = tokenize("firewall deny rule")
    assert keyword_score(tokens, "The firewall deny rule was applied") == 1.0
    assert keyword_score(tokens, "Antivirus signature updated") == 0.0
    assert keyword_score([], "anything") == 0.0


def test_local_backend_label_and_batch() -> None:
    backend = LocalEmbeddingBackend()
    vectors = backend.embed_batch(["alpha", "beta"])
    assert backend.model_label == LOCAL_MODEL_LABEL
    assert len(vectors) == 2
    assert all(len(vector) == DEFAULT_DIMENSION for vector in vectors)
    assert vectors[0] != vectors[1]


def test_cosine_handles_mismatched_dimensions() -> None:
    assert cosine_similarity([1.0, 0.0], [1.0, 0.0, 0.0]) == 0.0
    assert cosine_similarity([], [1.0]) == 0.0
