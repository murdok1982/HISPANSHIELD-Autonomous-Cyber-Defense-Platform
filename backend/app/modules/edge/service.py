"""Edge gateway lifecycle, authenticated telemetry ingestion and signed config."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select, text
from sqlalchemy.orm import Session

from app.core.audit import append_audit
from app.core.crypto import constant_time_equals, decrypt_secret, encrypt_secret
from app.core.db import utcnow
from app.core.deps import RequestContext
from app.core.errors import Conflict, NotFound, Unauthorized
from app.models.core import Organization
from app.models.edge import EdgeGateway, EdgeIngestEvent, EdgeSyncCursor
from app.models.events import SecurityEvent
from app.modules.edge.normalizer import dedupe_key_for, normalize_edge_event
from app.modules.edge.security import (
    DEFAULT_GATEWAY_CONFIG,
    ENROLLMENT_TTL_SECONDS,
    EnrollmentTokenError,
    attach_secret,
    enrollment_blob,
    gateway_secret_ciphertext,
    generate_gateway_secret,
    issue_enrollment_token,
    read_enrollment,
    sanitize_config,
    sign_config_bundle,
    token_sha256,
    verify_enrollment_token,
    verify_signature,
)

BUNDLE_TTL_SECONDS = 15 * 60


def serialize_gateway(gateway: EdgeGateway) -> dict[str, Any]:
    return {
        "id": gateway.id,
        "org_id": gateway.org_id,
        "name": gateway.name,
        "fingerprint": gateway.fingerprint,
        "status": gateway.status,
        "version": gateway.version,
        "last_seen_at": gateway.last_seen_at,
        "enrolled_at": gateway.enrolled_at,
        "revoked_at": gateway.revoked_at,
        "certificate_serial": gateway.certificate_serial,
        "config": sanitize_config(gateway.config),
        "buffer_stats": gateway.buffer_stats or {},
        "created_at": gateway.created_at,
        "updated_at": gateway.updated_at,
    }


def get_gateway(db: Session, org_id: UUID, gateway_id: UUID) -> EdgeGateway:
    gateway = db.get(EdgeGateway, gateway_id)
    if gateway is None or gateway.org_id != org_id:
        raise NotFound("Gateway")
    return gateway


def create_enrollment_token(db: Session, ctx: RequestContext) -> dict[str, Any]:
    token, hashed, expires_at = issue_enrollment_token(ctx.org.id)
    claims = verify_enrollment_token(token)
    gateway = EdgeGateway(
        org_id=ctx.org.id,
        name=f"enrollment-{claims['jti'][:8]}",
        fingerprint=f"pending-{uuid4().hex}",
        status="pending",
        version=None,
        config=enrollment_blob(hashed, claims["jti"], expires_at),
        buffer_stats={},
        created_by=ctx.actor_id,
    )
    db.add(gateway)
    db.flush()
    ctx.audit(
        action="edge.enrollment_token.create",
        resource_type="edge_gateway",
        resource_id=str(gateway.id),
        payload={"expires_at": expires_at.isoformat(), "ttl_seconds": ENROLLMENT_TTL_SECONDS},
    )
    db.commit()
    return {
        "gateway_id": gateway.id,
        "token": token,
        "expires_at": expires_at,
        "expires_in_seconds": ENROLLMENT_TTL_SECONDS,
    }


def _find_enrollment_gateway(db: Session, org_id: UUID, claims: dict[str, Any], token: str) -> EdgeGateway:
    rows = list(
        db.execute(select(EdgeGateway).where(EdgeGateway.org_id == org_id, EdgeGateway.status == "pending")).scalars()
    )
    hashed = token_sha256(token)
    for gateway in rows:
        enrollment = read_enrollment(gateway.config)
        if not enrollment:
            continue
        stored_hash = enrollment.get("token_hash")
        stored_jti = enrollment.get("jti")
        if not isinstance(stored_hash, str) or not isinstance(stored_jti, str):
            continue
        if stored_jti != claims["jti"]:
            continue
        if constant_time_equals(stored_hash, hashed):
            return gateway
    # Do not reveal whether the token was already used or never existed.
    raise Unauthorized("Enrollment token is invalid, expired or already used")


def register_gateway(db: Session, payload: Any) -> dict[str, Any]:
    try:
        claims = verify_enrollment_token(payload.enrollment_token)
    except EnrollmentTokenError as exc:
        raise Unauthorized(str(exc)) from exc

    organization = db.get(Organization, claims["org_id"])
    if organization is None or organization.deleted_at is not None or organization.status != "active":
        raise Unauthorized("Enrollment token organization is not active")

    gateway = _find_enrollment_gateway(db, organization.id, claims, payload.enrollment_token)
    enrollment = read_enrollment(gateway.config) or {}
    stored_expiry = enrollment.get("expires_at")
    if isinstance(stored_expiry, str):
        try:
            expires_at = datetime.fromisoformat(stored_expiry)
        except ValueError as exc:
            raise Unauthorized("Enrollment token metadata is invalid") from exc
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)
        if expires_at <= utcnow():
            raise Unauthorized("Enrollment token has expired")

    duplicate = db.execute(
        select(EdgeGateway).where(
            EdgeGateway.org_id == organization.id,
            EdgeGateway.fingerprint == payload.fingerprint,
            EdgeGateway.id != gateway.id,
        )
    ).scalar_one_or_none()
    if duplicate is not None:
        raise Conflict("A gateway with this fingerprint is already registered in this organization")

    secret = generate_gateway_secret()
    public_config = {key: value for key, value in (gateway.config or {}).items() if not str(key).startswith("_")}
    merged_config: dict[str, Any] = {**DEFAULT_GATEWAY_CONFIG, **public_config}
    gateway.name = payload.name
    gateway.fingerprint = payload.fingerprint
    gateway.version = payload.version
    gateway.certificate_serial = payload.certificate_serial
    gateway.status = "active"
    gateway.enrolled_at = utcnow()
    gateway.last_seen_at = utcnow()
    gateway.config = attach_secret(merged_config, encrypt_secret(secret))
    db.flush()

    bundle = build_config_bundle(gateway, secret)
    append_audit(
        db,
        org_id=gateway.org_id,
        action="edge.gateway.register",
        resource_type="edge_gateway",
        resource_id=str(gateway.id),
        actor_type="system",
        actor_id="edge-enrollment",
        payload={
            "fingerprint": gateway.fingerprint,
            "name": gateway.name,
            "certificate_serial": gateway.certificate_serial,
        },
    )
    db.commit()
    return {
        "gateway_id": gateway.id,
        "org_id": gateway.org_id,
        "fingerprint": gateway.fingerprint,
        "status": gateway.status,
        "enrolled_at": gateway.enrolled_at,
        "shared_key": secret,
        "config_bundle": bundle,
    }


def build_config_bundle(gateway: EdgeGateway, secret: str) -> dict[str, Any]:
    issued_at = utcnow()
    bundle = {
        "gateway_id": str(gateway.id),
        "org_id": str(gateway.org_id),
        "name": gateway.name,
        "fingerprint": gateway.fingerprint,
        "version": gateway.version,
        "config": sanitize_config(gateway.config),
        "issued_at": issued_at.isoformat(),
        "expires_at": (issued_at + timedelta(seconds=BUNDLE_TTL_SECONDS)).isoformat(),
    }
    return {
        "bundle": bundle,
        "signature": sign_config_bundle(secret, bundle),
        "algorithm": "HMAC-SHA256",
    }


def authenticate_gateway(
    db: Session,
    gateway_id: UUID,
    *,
    fingerprint: str | None,
    timestamp: str | None,
    signature: str | None,
    method: str,
    path: str,
    body: bytes,
) -> tuple[EdgeGateway, str]:
    """Authenticate a gateway request by fingerprint + HMAC over the raw request."""
    gateway = db.get(EdgeGateway, gateway_id)
    if gateway is None or gateway.revoked_at is not None or gateway.status == "revoked":
        raise NotFound("Gateway")
    if not fingerprint or not constant_time_equals(gateway.fingerprint, fingerprint):
        raise Unauthorized("Gateway fingerprint mismatch")
    ciphertext = gateway_secret_ciphertext(gateway.config)
    if not ciphertext:
        raise Unauthorized("Gateway has no active signing key")
    try:
        secret = decrypt_secret(ciphertext)
    except ValueError as exc:
        raise Unauthorized("Gateway signing key is unavailable") from exc
    if not verify_signature(secret, timestamp, signature, method, path, body):
        raise Unauthorized("Gateway signature is invalid or expired")
    return gateway, secret


def rotate_gateway_key(db: Session, ctx: RequestContext, gateway: EdgeGateway) -> dict[str, Any]:
    if gateway.revoked_at is not None or gateway.status == "revoked":
        raise Conflict("A revoked gateway cannot rotate its key")
    secret = generate_gateway_secret()
    gateway.config = attach_secret(sanitize_config(gateway.config), encrypt_secret(secret))
    ctx.audit(
        action="edge.gateway.rotate_key",
        resource_type="edge_gateway",
        resource_id=str(gateway.id),
        payload={"fingerprint": gateway.fingerprint},
    )
    db.commit()
    return {
        "gateway_id": gateway.id,
        "shared_key": secret,
        "key_id": secret[:8],
        "rotated_at": utcnow(),
    }


def ingest_events(db: Session, gateway: EdgeGateway, envelope: Any, *, path: str) -> dict[str, Any]:
    """Accept a signed, ordered batch with replay protection and idempotent dedupe."""
    lock_key = f"edge:seq:{gateway.id}"
    db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:key))"), {"key": lock_key})
    cursor = db.execute(
        select(EdgeSyncCursor).where(EdgeSyncCursor.gateway_id == gateway.id).with_for_update()
    ).scalar_one_or_none()

    if cursor is not None and envelope.sequence <= cursor.last_sequence:
        db.add(
            EdgeIngestEvent(
                gateway_id=gateway.id,
                org_id=gateway.org_id,
                kind=envelope.kind,
                sequence=envelope.sequence,
                payload={"event_count": len(envelope.events), "reason": "replay_sequence"},
                signature_valid=True,
                accepted=False,
                rejection_reason="replay_sequence",
                processed_count=0,
            )
        )
        append_audit(
            db,
            org_id=gateway.org_id,
            action="edge.events.ingest",
            resource_type="edge_gateway",
            resource_id=str(gateway.id),
            actor_type="system",
            actor_id=f"gateway:{gateway.id}",
            outcome="failure",
            payload={
                "sequence": envelope.sequence,
                "cursor": cursor.last_sequence,
                "reason": "replay_sequence",
                "path": path,
            },
        )
        db.commit()
        raise Conflict("Sequence already ingested; replay rejected")

    normalized: list[dict[str, Any]] = []
    seen: set[str] = set()
    for event in envelope.events:
        kwargs = normalize_edge_event(gateway.id, envelope.kind, event)
        dedupe_key = dedupe_key_for(gateway.id, kwargs["event_uid"])
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        kwargs.update(
            {
                "org_id": gateway.org_id,
                "dedupe_key": dedupe_key,
                "source_connector": f"edge:{gateway.id}",
            }
        )
        normalized.append(kwargs)

    existing_keys: set[str] = set()
    if normalized:
        existing_keys = {
            key
            for key in db.execute(
                select(SecurityEvent.dedupe_key).where(
                    SecurityEvent.org_id == gateway.org_id,
                    SecurityEvent.dedupe_key.in_([item["dedupe_key"] for item in normalized]),
                )
            ).scalars()
            if key
        }

    created = 0
    for item in normalized:
        if item["dedupe_key"] in existing_keys:
            continue
        db.add(SecurityEvent(**item))
        created += 1
    db.flush()

    duplicates = len(normalized) - created
    db.add(
        EdgeIngestEvent(
            gateway_id=gateway.id,
            org_id=gateway.org_id,
            kind=envelope.kind,
            sequence=envelope.sequence,
            payload={
                "event_count": len(envelope.events),
                "normalized_count": len(normalized),
                "accepted_count": created,
                "duplicate_count": duplicates,
                "event_uids": [item["event_uid"] for item in normalized[:100]],
                "batch_id": envelope.batch_id,
            },
            signature_valid=True,
            accepted=True,
            rejection_reason=None,
            processed_count=created,
        )
    )
    if cursor is None:
        cursor = EdgeSyncCursor(
            gateway_id=gateway.id,
            org_id=gateway.org_id,
            last_sequence=envelope.sequence,
        )
        db.add(cursor)
    else:
        cursor.last_sequence = envelope.sequence
        cursor.updated_at = utcnow()

    gateway.last_seen_at = utcnow()
    append_audit(
        db,
        org_id=gateway.org_id,
        action="edge.events.ingest",
        resource_type="edge_gateway",
        resource_id=str(gateway.id),
        actor_type="system",
        actor_id=f"gateway:{gateway.id}",
        payload={
            "sequence": envelope.sequence,
            "kind": envelope.kind,
            "event_count": len(envelope.events),
            "accepted": created,
            "duplicates": duplicates,
            "path": path,
        },
    )
    db.commit()
    return {
        "accepted": True,
        "sequence": envelope.sequence,
        "processed": created,
        "duplicates": duplicates,
        "cursor": envelope.sequence,
    }


__all__ = [
    "authenticate_gateway",
    "build_config_bundle",
    "create_enrollment_token",
    "get_gateway",
    "ingest_events",
    "register_gateway",
    "rotate_gateway_key",
    "serialize_gateway",
]
