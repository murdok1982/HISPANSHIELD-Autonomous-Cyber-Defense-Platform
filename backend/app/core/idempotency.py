"""Idempotency-Key support for mutating JSON endpoints.

The key is scoped to ``(organization, actor, key)``. A second request with the
same key and identical payload replays the stored response; a different payload
or path is rejected instead of silently executing twice. A concurrent request
that arrives while the first one is still running receives ``409`` with
``Retry-After``.

Limitations are explicit: the wrapper cannot make arbitrary side effects
exactly-once if the wrapped function commits and then raises. Endpoint
functions must commit only after their business operation succeeded.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from collections.abc import Callable
from datetime import timedelta
from typing import Any, TypeVar

from fastapi.encoders import jsonable_encoder
from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from app.core.db import utcnow
from app.core.deps import RequestContext
from app.core.errors import Conflict, ValidationFailure
from app.models.operations import (
    IDEMPOTENCY_COMPLETED,
    IDEMPOTENCY_IN_PROGRESS,
    IdempotencyRecord,
)

T = TypeVar("T")

KEY_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{8,128}$")
TTL = timedelta(hours=24)
STALE_IN_PROGRESS = timedelta(minutes=5)
MAX_REPLAY_BYTES = 1_000_000


def validate_key(value: str | None) -> str | None:
    if value is None:
        return None
    key = value.strip()
    if not KEY_PATTERN.match(key):
        raise ValidationFailure(
            [
                {
                    "field": "Idempotency-Key",
                    "message": "Use 8-128 characters from A-Z a-z 0-9 _ . : -",
                }
            ]
        )
    return key


def fingerprint(payload: Any) -> str:
    raw = json.dumps(jsonable_encoder(payload), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _scope(ctx: RequestContext, key: str) -> tuple[uuid.UUID, str, str]:
    actor = ctx.actor_id or "anonymous"
    return ctx.org.id, actor[:80], key


def execute(
    ctx: RequestContext,
    key: str | None,
    *,
    method: str,
    path: str,
    payload: Any,
    fn: Callable[[], T],
    replay_status: int = 200,
) -> tuple[T | dict[str, Any], bool]:
    """Run ``fn`` at most once per key. Returns ``(body, replayed)``."""
    validated = validate_key(key)
    if validated is None:
        return fn(), False

    org_id, actor_key, idem_key = _scope(ctx, validated)
    request_hash = fingerprint(payload)
    now = utcnow()

    # Expired rows are dead weight and must not block a new attempt.
    ctx.db.execute(
        delete(IdempotencyRecord).where(
            IdempotencyRecord.org_id == org_id,
            IdempotencyRecord.actor_key == actor_key,
            IdempotencyRecord.idempotency_key == idem_key,
            IdempotencyRecord.expires_at <= now,
        )
    )
    insert_stmt = (
        pg_insert(IdempotencyRecord)
        .values(
            id=uuid.uuid4(),
            org_id=org_id,
            actor_key=actor_key,
            idempotency_key=idem_key,
            method=method[:10],
            path=path[:300],
            request_hash=request_hash,
            status=IDEMPOTENCY_IN_PROGRESS,
            created_at=now,
            expires_at=now + TTL,
        )
        .on_conflict_do_nothing(index_elements=["org_id", "actor_key", "idempotency_key"])
        .returning(IdempotencyRecord.id)
    )
    record_id = ctx.db.execute(insert_stmt).scalar_one_or_none()
    ctx.db.commit()

    if record_id is None:
        existing = ctx.db.execute(
            select(IdempotencyRecord).where(
                IdempotencyRecord.org_id == org_id,
                IdempotencyRecord.actor_key == actor_key,
                IdempotencyRecord.idempotency_key == idem_key,
            )
        ).scalar_one_or_none()
        if existing is None:  # extremely unlikely: row vanished between insert and read
            raise Conflict("Idempotency record disappeared; retry the request")
        if existing.method != method[:10] or existing.path != path[:300] or existing.request_hash != request_hash:
            raise Conflict(
                "Idempotency-Key was already used with a different request",
                details=[{"field": "Idempotency-Key", "message": "Key reuse with a different payload or path"}],
            )
        if existing.status == IDEMPOTENCY_COMPLETED and existing.response_body is not None:
            return existing.response_body, True
        if now - existing.created_at > STALE_IN_PROGRESS:
            # The first worker died. Take over the row rather than blocking the
            # key for the whole TTL.
            existing.created_at = now
            existing.expires_at = now + TTL
            existing.request_hash = request_hash
            ctx.db.commit()
            record_id = existing.id
        else:
            raise Conflict(
                "A request with this Idempotency-Key is still in progress",
                headers={"Retry-After": "1"},
            )

    try:
        result = fn()
        body = jsonable_encoder(result)
        if len(json.dumps(body, default=str)) > MAX_REPLAY_BYTES:
            raise Conflict("Response is too large to store for idempotent replay")
        record = ctx.db.get(IdempotencyRecord, record_id)
        if record is not None:
            record.status = IDEMPOTENCY_COMPLETED
            record.response_status = replay_status
            record.response_body = body
            ctx.db.commit()
        return body, False
    except Exception:
        ctx.db.rollback()
        ctx.db.execute(delete(IdempotencyRecord).where(IdempotencyRecord.id == record_id))
        ctx.db.commit()
        raise


def purge_expired(ctx: RequestContext) -> int:
    result = ctx.db.execute(delete(IdempotencyRecord).where(IdempotencyRecord.expires_at <= utcnow()))
    ctx.db.commit()
    return int(result.rowcount or 0)


def purge_expired_records(db: Session) -> int:
    """Bounded maintenance hook used by the durable worker."""
    result = db.execute(delete(IdempotencyRecord).where(IdempotencyRecord.expires_at <= utcnow()))
    db.commit()
    return int(result.rowcount or 0)


__all__ = ["execute", "fingerprint", "purge_expired", "purge_expired_records", "validate_key"]
