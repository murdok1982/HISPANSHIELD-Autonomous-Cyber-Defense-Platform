"""Append-only, hash-chained audit trail.

Each record's hash covers the previous hash, the organization, actor, action,
resource, outcome and a canonical JSON payload. Writes take a per-organization
transactional advisory lock so concurrent requests cannot fork the chain.
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
) -> str:
    return json.dumps(
        {
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
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


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
    canonical = _canonical_payload(
        org_id,
        actor_type,
        actor_id,
        actor_email,
        action,
        resource_type,
        resource_id,
        outcome,
        safe_payload,
        created_at,
    )
    record = AuditRecord(
        org_id=org_id,
        actor_type=actor_type,
        actor_id=actor_id,
        actor_email=actor_email,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        outcome=outcome,
        request_id=request_id,
        ip_address=ip_address,
        user_agent=(user_agent or "")[:400] or None,
        payload=safe_payload,
        prev_hash=last_hash,
        hash=sha256_hex((last_hash or "") + canonical),
        created_at=created_at,
    )
    db.add(record)
    db.flush()
    return record


def verify_audit_chain(db: Session, org_id: UUID | None) -> dict[str, Any]:
    """Recompute the chain and report the first divergence, if any."""
    stmt = (
        select(AuditRecord)
        .where(AuditRecord.org_id.is_(None) if org_id is None else AuditRecord.org_id == org_id)
        .order_by(AuditRecord.created_at.asc(), AuditRecord.id.asc())
    )
    records = list(db.execute(stmt).scalars())
    previous: str | None = None
    checked = 0
    for record in records:
        canonical = _canonical_payload(
            record.org_id,
            record.actor_type,
            record.actor_id,
            record.actor_email,
            record.action,
            record.resource_type,
            record.resource_id,
            record.outcome,
            record.payload,
            record.created_at,
        )
        expected = sha256_hex((previous or "") + canonical)
        if record.prev_hash != previous or record.hash != expected:
            return {
                "valid": False,
                "checked": checked,
                "broken_at": str(record.id),
                "expected_hash": expected,
                "stored_hash": record.hash,
                "reason": "prev_hash mismatch" if record.prev_hash != previous else "hash mismatch",
            }
        previous = record.hash
        checked += 1
    return {"valid": True, "checked": checked, "head": previous, "broken_at": None}


def audit_ref(value: uuid.UUID | str | None) -> str | None:
    return str(value) if value else None
