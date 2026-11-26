"""Forensic evidence ingestion: safe naming, magic-byte sniffing, hashing.

Design notes
------------
* Files are written outside the web root under ``HS_EVIDENCE_DIR`` (default
  ``data/evidence``) and addressed by an opaque UUID name. The original
  client-supplied filename is never used on disk.
* Content is sniffed from the first bytes before the file is accepted, so a
  ``.png`` that actually contains plain text is rejected. Only a fixed
  allow-list of evidence formats is accepted.
* SHA-256 is computed while streaming, so arbitrarily large uploads never have
  to fit in memory; the configured limit is enforced *during* the copy.
* ``resolve_storage_path`` refuses traversal and symlink escapes, and
  ``verify_file`` re-hashes the stored bytes so any later tampering is
  detectable. The forensics export agent should only need ``verify_file``.
"""

from __future__ import annotations

import hashlib
import os
import re
import unicodedata
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO
from urllib.parse import quote

from app.core.errors import AppError, ValidationFailure

MAX_EVIDENCE_BYTES = 25 * 1024 * 1024
_CHUNK_SIZE = 64 * 1024
_SNIFF_BYTES = 1024
_MAX_FILENAME = 120

# extension -> canonical content type
_ALLOWED_TYPES: dict[str, str] = {
    "txt": "text/plain",
    "log": "text/plain",
    "json": "application/json",
    "pcap": "application/vnd.tcpdump.pcap",
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "pdf": "application/pdf",
    "zip": "application/zip",
}

_TEXT_EXTENSIONS = {"txt", "log", "json"}

_MAGIC_SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"%PDF-", "pdf"),
    (b"\xff\xd8\xff", "jpg"),
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),
    (b"PK\x07\x08", "zip"),
    (b"\xd4\xc3\xb2\xa1", "pcap"),
    (b"\xa1\xb2\xc3\xd4", "pcap"),
    (b"\x4d\x3c\xb2\xa1", "pcap"),
    (b"\xa1\xb2\x3c\x4d", "pcap"),
    (b"\x0a\x0d\x0d\x0a", "pcap"),
)


@dataclass(frozen=True)
class StoredEvidence:
    storage_path: str
    sha256: str
    size_bytes: int
    content_type: str
    kind: str
    safe_filename: str


def evidence_root() -> Path:
    """Directory that holds evidence files (outside the static web root)."""
    configured = os.environ.get("HS_EVIDENCE_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    data_dir = os.environ.get("HS_DATA_DIR", "data")
    return (Path(data_dir).expanduser() / "evidence").resolve()


def sanitize_filename(name: str | None, fallback: str = "evidence") -> str:
    """Return a filesystem-safe, ASCII-only basename.

    Directory components, control characters, whitespace and everything outside
    ``[A-Za-z0-9._-]`` are removed. The result is never empty and can never be
    ``.``/``..``.
    """
    raw = (name or "").replace("\\", "/")
    base = raw.rsplit("/", 1)[-1]
    base = unicodedata.normalize("NFKD", base).encode("ascii", "ignore").decode("ascii")
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base)
    base = base.strip("._-")[:_MAX_FILENAME]
    return base or fallback


def _extension(name: str) -> str:
    suffix = Path(name).suffix.lower().lstrip(".")
    return suffix if len(suffix) <= 10 else ""


def _sniff(head: bytes, extension: str) -> tuple[str, str]:
    """Return ``(kind, content_type)`` or raise ``ValidationFailure``."""
    if extension not in _ALLOWED_TYPES:
        raise ValidationFailure(
            [
                {
                    "field": "file",
                    "message": ("Unsupported evidence type. Allowed extensions: " + ", ".join(sorted(_ALLOWED_TYPES))),
                }
            ]
        )

    if extension in _TEXT_EXTENSIONS:
        if b"\x00" in head:
            raise ValidationFailure([{"field": "file", "message": "Binary content in a text evidence file"}])
        try:
            text = head.decode("utf-8")
        except UnicodeDecodeError as exc:
            # A chunk boundary can split a multibyte sequence; accept the valid
            # prefix when the failure is at the end of the sniffed buffer.
            if exc.end >= len(head) - 3:
                try:
                    text = head[: exc.start].decode("utf-8")
                except UnicodeDecodeError as inner:
                    raise ValidationFailure(
                        [{"field": "file", "message": "Text evidence must be valid UTF-8"}]
                    ) from inner
            else:
                raise ValidationFailure([{"field": "file", "message": "Text evidence must be valid UTF-8"}]) from exc
        if extension == "json":
            stripped = text.lstrip()
            if stripped and not stripped.startswith(("{", "[")):
                raise ValidationFailure(
                    [{"field": "file", "message": "JSON evidence must start with an object or array"}]
                )
        return extension, _ALLOWED_TYPES[extension]

    for signature, kind in _MAGIC_SIGNATURES:
        if head.startswith(signature):
            # jpeg is an alias of jpg on disk.
            if kind == "jpg" and extension in {"jpg", "jpeg"}:
                return "jpg", _ALLOWED_TYPES["jpg"]
            if extension == kind:
                return kind, _ALLOWED_TYPES[extension]
            raise ValidationFailure(
                [
                    {
                        "field": "file",
                        "message": f"File content ({kind}) does not match the declared extension ({extension})",
                    }
                ]
            )

    raise ValidationFailure(
        [{"field": "file", "message": f"Could not verify the magic bytes for a {extension} evidence file"}]
    )


def _part_path(target: Path) -> Path:
    return target.with_name(f".{target.name}.{uuid.uuid4().hex}.part")


def store_evidence_stream(
    stream: BinaryIO,
    *,
    original_filename: str | None,
    org_id: str | uuid.UUID,
    incident_id: str | uuid.UUID,
    max_bytes: int = MAX_EVIDENCE_BYTES,
) -> StoredEvidence:
    """Persist an evidence stream under ``<root>/<org>/<incident>/``.

    Raises ``AppError(file_too_large, 413)`` when the limit is exceeded and
    ``ValidationFailure`` for unsupported or spoofed content.
    """
    safe_name = sanitize_filename(original_filename)
    extension = _extension(safe_name)
    if not extension:
        raise ValidationFailure([{"field": "file", "message": "Evidence files must declare an extension"}])

    storage_dir = evidence_root() / str(org_id) / str(incident_id)
    storage_dir.mkdir(parents=True, exist_ok=True)
    target = storage_dir / f"{uuid.uuid4().hex}.{extension}"
    part = _part_path(target)

    digest = hashlib.sha256()
    size = 0
    head = b""
    try:
        with part.open("wb") as handle:
            while True:
                chunk = stream.read(_CHUNK_SIZE)
                if not chunk:
                    break
                if isinstance(chunk, str):  # defensive: callers must open binary
                    chunk = chunk.encode("utf-8")
                size += len(chunk)
                if size > max_bytes:
                    raise AppError(
                        "file_too_large",
                        f"Evidence exceeds the maximum size of {max_bytes} bytes",
                        413,
                    )
                if len(head) < _SNIFF_BYTES:
                    head += chunk[: _SNIFF_BYTES - len(head)]
                digest.update(chunk)
                handle.write(chunk)
            if size == 0:
                raise ValidationFailure([{"field": "file", "message": "The evidence file is empty"}])
        kind, content_type = _sniff(head, extension)
        os.chmod(part, 0o640)
        part.replace(target)
    except Exception:
        part.unlink(missing_ok=True)
        raise

    relative = target.relative_to(evidence_root()).as_posix()
    return StoredEvidence(
        storage_path=relative,
        sha256=digest.hexdigest(),
        size_bytes=size,
        content_type=content_type,
        kind=kind,
        safe_filename=safe_name,
    )


def resolve_storage_path(storage_path: str) -> Path:
    """Resolve a stored relative path, refusing traversal and symlink escapes."""
    if not storage_path or "\x00" in storage_path:
        raise AppError("invalid_storage_path", "Evidence storage path is invalid", 500)
    root = evidence_root()
    candidate = (root / storage_path).resolve()
    if not candidate.is_relative_to(root):
        raise AppError("invalid_storage_path", "Evidence storage path escapes the evidence root", 500)
    if not candidate.is_file():
        raise FileNotFoundError(storage_path)
    return candidate


def verify_file(path: str | Path, expected_sha256: str) -> dict[str, object]:
    """Re-hash a stored file and compare it with the recorded digest."""
    file_path = Path(path)
    digest = hashlib.sha256()
    size = 0
    with file_path.open("rb") as handle:
        while chunk := handle.read(_CHUNK_SIZE):
            digest.update(chunk)
            size += len(chunk)
    actual = digest.hexdigest()
    return {
        "verified": actual == expected_sha256,
        "expected_sha256": expected_sha256,
        "actual_sha256": actual,
        "size_bytes": size,
    }


def content_disposition(filename: str) -> str:
    """Build a non-injectable ``Content-Disposition`` value."""
    safe = sanitize_filename(filename)
    ascii_fallback = re.sub(r"[^A-Za-z0-9._-]", "_", safe) or "evidence"
    return f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{quote(safe)}"


__all__ = [
    "MAX_EVIDENCE_BYTES",
    "StoredEvidence",
    "content_disposition",
    "evidence_root",
    "resolve_storage_path",
    "sanitize_filename",
    "store_evidence_stream",
    "verify_file",
]
