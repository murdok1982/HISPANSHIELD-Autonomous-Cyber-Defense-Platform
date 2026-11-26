"""Database-backed fixed-window rate limiting shared across worker processes.

Buckets are mutated through an independent short-lived session so a rejected
request cannot roll back its own rate-limit increment.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, text
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.db import SessionLocal, utcnow
from app.core.errors import RateLimited
from app.models.core import RateLimitBucket


def _window(now: datetime, seconds: int) -> datetime:
    epoch = int(now.timestamp())
    return datetime.fromtimestamp(epoch - (epoch % seconds), tz=UTC)


def _consume(db: Session, key: str, window_seconds: int) -> tuple[int, int]:
    now = utcnow()
    window_start = _window(now, window_seconds)
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": f"rl:{key}"})
    bucket = db.get(RateLimitBucket, key, with_for_update=True)
    if bucket is None:
        bucket = RateLimitBucket(
            key=key,
            window_start=window_start,
            count=1,
            expires_at=window_start + timedelta(seconds=window_seconds * 2),
        )
        db.add(bucket)
    elif bucket.window_start < window_start:
        bucket.window_start = window_start
        bucket.count = 1
        bucket.expires_at = window_start + timedelta(seconds=window_seconds * 2)
    else:
        bucket.count += 1
    db.commit()
    retry_after = max(1, int((window_start + timedelta(seconds=window_seconds) - now).total_seconds()))
    return bucket.count, retry_after


def enforce(key: str, limit: int, window_seconds: int = 60) -> int:
    """Raise RateLimited when `key` exceeds `limit` calls in the current window."""
    if not settings.rate_limit_enabled:
        return 0
    with SessionLocal() as db:
        count, retry_after = _consume(db, key, window_seconds)
    if count > limit:
        raise RateLimited(retry_after)
    return max(0, limit - count)


def record_attempt(key: str, window_seconds: int = 900) -> int:
    """Increment a counter without enforcing a limit and return the new count.

    Used for authentication telemetry (distinct source addresses behind failed
    logins) where the decision is made by the auth service, not by the limiter.
    """
    with SessionLocal() as db:
        count, _ = _consume(db, key, window_seconds)
    return count


def purge_expired(before: datetime | None = None) -> int:
    cutoff = before or utcnow() - timedelta(hours=2)
    with SessionLocal() as db:
        result = db.execute(delete(RateLimitBucket).where(RateLimitBucket.expires_at < cutoff))
        db.commit()
        return int(result.rowcount or 0)
