"""Sentence-aware chunking for the local knowledge base."""

from __future__ import annotations

import re

from app.services.llm.safety import strip_control_chars

DEFAULT_MAX_CHARS = 800
DEFAULT_OVERLAP = 120
_SENTENCE_BOUNDARY = re.compile(r"(?<=[.!?])\s+|\n{2,}")


def _hard_split(unit: str, max_chars: int) -> list[str]:
    pieces: list[str] = []
    remaining = unit.strip()
    while len(remaining) > max_chars:
        window = remaining[:max_chars]
        cut = window.rfind(" ")
        if cut < max_chars // 2:
            cut = max_chars
        pieces.append(remaining[:cut].strip())
        remaining = remaining[cut:].strip()
    if remaining:
        pieces.append(remaining)
    return pieces


def split_sentences(text: str) -> list[str]:
    blocks = _SENTENCE_BOUNDARY.split(strip_control_chars(text or ""))
    sentences: list[str] = []
    for block in blocks:
        cleaned = " ".join(block.split())
        if cleaned:
            sentences.append(cleaned)
    return sentences


def chunk_text(
    text: str,
    *,
    max_chars: int = DEFAULT_MAX_CHARS,
    overlap: int = DEFAULT_OVERLAP,
) -> list[str]:
    """Split text into <= ``max_chars`` chunks, preferring sentence boundaries.

    A tail of the previous chunk (up to ``overlap`` characters) is prepended to
    the next chunk to preserve context across boundaries. Chunks never exceed
    ``max_chars``.
    """
    if max_chars < 50:
        raise ValueError("max_chars must be at least 50")
    overlap = max(0, min(overlap, max_chars // 2))
    units: list[str] = []
    for sentence in split_sentences(text):
        if len(sentence) <= max_chars:
            units.append(sentence)
        else:
            units.extend(_hard_split(sentence, max_chars))

    chunks: list[str] = []
    current = ""
    for unit in units:
        candidate = unit if not current else f"{current} {unit}"
        if len(candidate) <= max_chars:
            current = candidate
            continue

        if current:
            chunks.append(current.strip())
        overlap_text = current[-overlap:].strip() if current and overlap else ""
        room = max_chars - len(unit) - 1
        if overlap_text and room > 20:
            overlap_text = overlap_text[-min(overlap, room) :].strip()
            current = f"{overlap_text} {unit}"
        else:
            current = unit

    if current.strip():
        chunks.append(current.strip())
    return [chunk for chunk in chunks if chunk]


__all__ = ["DEFAULT_MAX_CHARS", "DEFAULT_OVERLAP", "chunk_text", "split_sentences"]
