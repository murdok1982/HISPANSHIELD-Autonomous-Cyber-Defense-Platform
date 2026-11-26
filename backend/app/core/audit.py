"""Append-only, hash-chained audit trail.

Each record's hash covers the previous hash, the organization, actor, action,
resource, outcome, a canonical JSON payload and — for records written with the
current scheme — the request correlation metadata (``request_id``,
``ip_address``, ``user_agent``) plus the covered ``actor_email``.

Hash-scheme versioning keeps existing chains verifiable. Version ``v1`` is the
original canonical document (no request metadata). Version ``v2`` — the only
scheme used for new writes — adds an explicit ``audit-v2`` marker and the
request metadata, so a v1 record can never be mistaken for a v2 one. The
verifier recomputes both schemes and accepts whichever the stored hash matches;
tampering with any v2-covered field therefore breaks verification, while legacy
v1 records keep validating against their original field set.

Writes take a per-organization transactional advisory lock so concurrent
requests cannot fork the chain.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.crypto import sha256_hex
from app.core.db import utcnow
from app.models.core import AuditRecord

AUDIT_HASH_VERSION = 2
LEGACY_AUDIT_HASH_VERSION = 1
AUDIT_SCHEME_MARKER = "audit-v2"

_SENSITIVE_KEYS = {
    "password",
    "password_hash",
    "secret",
    "token",
    "token_hash",
    "api_key",
    "apikey",
    "authorization",
    "cookie",
    "set-cookie",
    "private_key",
    "client_secret",
    "hmac_secret",
    "mfa_secret",
    "otp",
    "credential",
}


def redact(value: Any, depth: int = 0) -> Any:
    """Recursively redact secret-bearing keys before persisting audit payloads."""
    if depth > 8:
        return "[truncated]"
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if any(secret in str(key).lower() for secret in _SENSITIVE_KEYS):
                result[str(key)] = "[redacted]"
            else:
                result[str(key)] = redact(item, depth + 1)
        return result
    if isinstance(value, list):
        return [redact(item, depth + 1) for item in value[:100]]
    if isinstance(value, bytes):
        return f"<{len(value)} bytes>"
    if isinstance(value, str) and len(value) > 4000:
        return value[:4000] + "…"
    return value


def _canonical_payload(
    org_id: UUID | None,
    actor_type: str,
    actor_id: str | None,
    actor_email: str | None,
    action: str,
    resource_type: str,
    resource_id: str | None,
    outcome: str,
    payload: dict[str, Any],
    created_at: datetime,
    *,
    version: int = AUDIT_HASH_VERSION,
    request_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> str:
    """Serialize the exact field set covered by a given hash-scheme version.

    ``version=1`` reproduces the original document byte-for-byte so historical
    hashes remain valid. ``version>=2`` adds an explicit scheme marker and the
    request correlation fields.
    """
    document: dict[str, Any] = {
        "org_id": str(org_id) if org_id else None,
        "actor_type": actor_type,
        "actor_id": actor_id,
        "actor_email": actor_email,
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "outcome": outcome,
        "payload": payload,
        "created_at": created_at.astimezone(UTC).isoformat(),
    }
    if version >= 2:
        document["scheme"] = AUDIT_SCHEME_MARKER
        document["request_id"] = request_id
        document["ip_address"] = ip_address
        document["user_agent"] = user_agent
    return json.dumps(
        document,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _hash_for_version(record: AuditRecord, previous: str | None, version: int) -> str:
    canonical = _canonical_payload(
        record.org_id,
        record.actor_type,
        record.actor_id,
        record.actor_email,
        record.action,
        record.resource_type,
        record.resource_id,
        record.outcome,
        record.payload or {},
        record.created_at,
        version=version,
        request_id=record.request_id,
        ip_address=record.ip_address,
        user_agent=record.user_agent,
    )
    return sha256_hex((previous or "") + canonical)


def append_audit(
    db: Session,
    *,
    org_id: UUID | None,
    action: str,
    resource_type: str,
    resource_id: str | None = None,
    actor_type: str = "user",
    actor_id: str | None = None,
    actor_email: str | None = None,
    outcome: str = "success",
    payload: dict[str, Any] | None = None,
    request_id: str | None = None,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> AuditRecord:
    # Serialize chain extension per organization (or global chain when org is NULL).
    lock_key = f"audit:{org_id or 'global'}"
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": lock_key})
    last_hash = db.execute(
        select(AuditRecord.hash)
        .where(AuditRecord.org_id.is_(None) if org_id is None else AuditRecord.org_id == org_id)
        .order_by(AuditRecord.created_at.desc(), AuditRecord.id.desc())
        .limit(1)
    ).scalar_one_or_none()

    created_at = utcnow()
    safe_payload = redact(payload or {})
    # Hash exactly the values that are persisted, otherwise column truncation
    # would make legitimate records unverifiable.
    stored_actor_email = (actor_email or "")[:255] or None
    stored_request_id = (request_id or "")[:64] or None
    stored_ip = (ip_address or "")[:64] or None
    stored_user_agent = (user_agent or "")[:400] or None
    canonical = _canonical_payload(
        org_id,
        actor_type,
        actor_id,
        stored_actor_email,
        action,
        resource_type,
        resource_id,
        outcome,
        safe_payload,
        created_at,
        version=AUDIT_HASH_VERSION,
        request_id=stored_request_id,
        ip_address=stored_ip,
        user_agent=stored_user_agent,
    )
    record = AuditRecord(
        org_id=org_id,
        actor_type=actor_type,
        actor_id=actor_id,
        actor_email=stored_actor_email,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        request_id=stored_request_id,
        ip_address=stored_ip,
        user_agent=stored_user_agent,
        payload=safe_payload,
        prev_hash=last_hash,
        hash=sha256_hex((last_hash or "") + canonical),
        created_at=created_at,
    )
    db.add(record)
    db.flush()
    return record


def verify_audit_chain(db: Session, org_id: UUID | None) -> dict[str, Any]:
    """Recompute the chain and report the first divergence, if any.

    Both hash schemes are accepted: the current v2 scheme is tried first, then
    the legacy v1 scheme. A record is valid only when its stored hash matches a
    recomputation under one scheme *and* its ``prev_hash`` links to the previous
    accepted hash.
    """
    stmt = (
        select(AuditRecord)
        .where(AuditRecord.org_id.is_(None) if org_id is None else AuditRecord.org_id == org_id)
        .order_by(AuditRecord.created_at.asc(), AuditRecord.id.asc())
        .execution_options(populate_existing=True)
    )
    records = list(db.execute(stmt).scalars())
    previous: str | None = None
    checked = 0
    schemes = {"v1": 0, "v2": 0}
    for record in records:
        if record.prev_hash != previous:
            return {
                "valid": False,
                "checked": checked,
                "broken_at": str(record.id),
                "expected_hash": _hash_for_version(record, previous, AUDIT_HASH_VERSION),
                "stored_hash": record.hash,
                "reason": "prev_hash mismatch",
            }
        expected_v2 = _hash_for_version(record, previous, AUDIT_HASH_VERSION)
        if record.hash == expected_v2:
            schemes["v2"] += 1
        else:
            expected_v1 = _hash_for_version(record, previous, LEGACY_AUDIT_HASH_VERSION)
            if record.hash != expected_v1:
                return {
                    "valid": False,
                    "checked": checked,
                    "broken_at": str(record.id),
                    "expected_hash": expected_v2,
                    "stored_hash": record.hash,
                    "reason": "hash mismatch",
                }
            schemes["v1"] += 1
        previous = record.hash
        checked += 1
    return {
        "valid": True,
        "checked": checked,
        "head": previous,
        "broken_at": None,
        "schemes": schemes,
    }


def audit_ref(value: uuid.UUID | str | None) -> str | None:
    return str(value) if value else None
