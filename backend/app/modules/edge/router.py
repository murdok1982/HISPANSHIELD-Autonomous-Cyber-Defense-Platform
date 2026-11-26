"""Edge gateway API: one-time enrollment, HMAC-authenticated telemetry and config."""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from pydantic import ValidationError
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.audit import append_audit
from app.core.crypto import decrypt_secret
from app.core.db import get_db, utcnow
from app.core.deps import RequestContext, require_permission
from app.core.errors import Conflict, NotFound, ValidationFailure
from app.core.rate_limit import enforce
from app.core.schemas import Page, paginate
from app.models.edge import EdgeGateway, EdgeIngestEvent, EdgeSyncCursor
from app.modules.edge import service
from app.modules.edge.schemas import (
    EnrollmentTokenOut,
    GatewayConfigPatch,
    GatewayEventEnvelope,
    GatewayEventIngestResult,
    GatewayIngestEventOut,
    GatewayOut,
    GatewayRegisterRequest,
    GatewayRegisterResponse,
    GatewayRotateKeyResult,
    HeartbeatRequest,
    HeartbeatResponse,
)
from app.modules.edge.security import gateway_secret_ciphertext, sanitize_config

router = APIRouter(prefix="/edge", tags=["Edge Gateways"])


def _validation_error(exc: ValidationError, field: str = "body") -> ValidationFailure:
    details = [
        {"field": ".".join(str(part) for part in error.get("loc", ())) or field, "message": error.get("msg", "Invalid")}
        for error in exc.errors()[:20]
    ]
    return ValidationFailure(details)


# --------------------------------------------------------------------------- #
# Enrollment (authenticated) and registration (public)
# --------------------------------------------------------------------------- #
@router.post(
    "/gateways/enroll-token",
    response_model=EnrollmentTokenOut,
    status_code=201,
    summary="Create a one-time gateway enrollment token",
)
def create_enrollment_token(
    ctx: RequestContext = Depends(require_permission("edge:write")),
) -> EnrollmentTokenOut:
    result = service.create_enrollment_token(ctx.db, ctx)
    return EnrollmentTokenOut(**result)


@router.post(
    "/gateways/register",
    response_model=GatewayRegisterResponse,
    status_code=201,
    summary="Register a gateway with a one-time enrollment token (public)",
)
def register_gateway(
    payload: GatewayRegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> GatewayRegisterResponse:
    """Public enrollment endpoint.

    It is intentionally unauthenticated but bounded: the enrollment token is
    HMAC-signed, single-use and expires after 15 minutes, and the request is
    rate-limited per source address. No other API surface is exposed here.
    """
    client_ip = request.client.host if request.client else "unknown"
    enforce(f"edge:register:{client_ip}", 20, 60)
    result = service.register_gateway(db, payload)
    return GatewayRegisterResponse(**result)


# --------------------------------------------------------------------------- #
# Gateway-authenticated endpoints
# --------------------------------------------------------------------------- #
@router.post("/gateways/{gateway_id}/heartbeat", response_model=HeartbeatResponse, summary="Gateway heartbeat")
async def gateway_heartbeat(
    gateway_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    x_gateway_fingerprint: str | None = Header(default=None, alias="X-Gateway-Fingerprint"),
    x_gateway_timestamp: str | None = Header(default=None, alias="X-Gateway-Timestamp"),
    x_gateway_signature: str | None = Header(default=None, alias="X-Gateway-Signature"),
) -> HeartbeatResponse:
    raw = await request.body()
    if len(raw) > 64_000:
        raise ValidationFailure([{"field": "body", "message": "Heartbeat body exceeds 64 KB"}])
    gateway, _secret = service.authenticate_gateway(
        db,
        gateway_id,
        fingerprint=x_gateway_fingerprint,
        timestamp=x_gateway_timestamp,
        signature=x_gateway_signature,
        method=request.method,
        path=request.url.path,
        body=raw,
    )
    if raw:
        try:
            payload = HeartbeatRequest.model_validate_json(raw)
        except ValidationError as exc:
            raise _validation_error(exc) from exc
    else:
        payload = HeartbeatRequest()

    gateway.last_seen_at = utcnow()
    if payload.version:
        gateway.version = payload.version
    if payload.buffer_stats:
        gateway.buffer_stats = payload.buffer_stats
    cursor = db.execute(
        select(EdgeSyncCursor.last_sequence).where(EdgeSyncCursor.gateway_id == gateway.id)
    ).scalar_one_or_none()
    public_config = sanitize_config(gateway.config)
    next_heartbeat = int(public_config.get("heartbeat_interval_seconds", 60) or 60)
    db.commit()
    return HeartbeatResponse(
        ok=True,
        server_time=utcnow(),
        cursor=int(cursor or 0),
        next_heartbeat_seconds=max(15, min(next_heartbeat, 3600)),
        config_version=str(int(gateway.updated_at.timestamp())),
    )


@router.post(
    "/gateways/{gateway_id}/events",
    response_model=GatewayEventIngestResult,
    summary="Ingest a signed batch of edge telemetry",
)
async def gateway_events(
    gateway_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    x_gateway_fingerprint: str | None = Header(default=None, alias="X-Gateway-Fingerprint"),
    x_gateway_timestamp: str | None = Header(default=None, alias="X-Gateway-Timestamp"),
    x_gateway_signature: str | None = Header(default=None, alias="X-Gateway-Signature"),
) -> GatewayEventIngestResult:
    raw = await request.body()
    gateway, _secret = service.authenticate_gateway(
        db,
        gateway_id,
        fingerprint=x_gateway_fingerprint,
        timestamp=x_gateway_timestamp,
        signature=x_gateway_signature,
        method=request.method,
        path=request.url.path,
        body=raw,
    )
    try:
        envelope = GatewayEventEnvelope.model_validate_json(raw)
    except ValidationError as exc:
        raise _validation_error(exc) from exc
    result = service.ingest_events(db, gateway, envelope, path=request.url.path)
    return GatewayEventIngestResult(**result)


# --------------------------------------------------------------------------- #
# Tenant administration
# --------------------------------------------------------------------------- #
@router.get("/gateways", response_model=Page[GatewayOut], summary="List edge gateways")
def list_gateways(
    ctx: RequestContext = Depends(require_permission("edge:read")),
    status: str | None = Query(default=None, max_length=20),
    q: str | None = Query(default=None, max_length=160),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
) -> Page[GatewayOut]:
    stmt = select(EdgeGateway).where(EdgeGateway.org_id == ctx.org.id)
    stmt = stmt.where(EdgeGateway.status == status) if status else stmt.where(EdgeGateway.status != "pending")
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(func.lower(EdgeGateway.name).like(needle), func.lower(EdgeGateway.fingerprint).like(needle))
        )
    stmt = stmt.order_by(EdgeGateway.last_seen_at.desc().nulls_last(), EdgeGateway.name)
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[GatewayOut](**paginate([service.serialize_gateway(row) for row in rows], total, page, page_size))


@router.get("/gateways/{gateway_id}", response_model=GatewayOut, summary="Read an edge gateway")
def get_gateway(gateway_id: UUID, ctx: RequestContext = Depends(require_permission("edge:read"))) -> GatewayOut:
    return GatewayOut.model_validate(service.serialize_gateway(service.get_gateway(ctx.db, ctx.org.id, gateway_id)))


@router.patch(
    "/gateways/{gateway_id}",
    response_model=GatewayOut,
    summary="Update gateway operational configuration (allow-listed keys)",
)
def update_gateway(
    gateway_id: UUID,
    payload: GatewayConfigPatch,
    ctx: RequestContext = Depends(require_permission("edge:write")),
) -> GatewayOut:
    gateway = service.get_gateway(ctx.db, ctx.org.id, gateway_id)
    if gateway.status == "revoked":
        raise Conflict("A revoked gateway cannot be reconfigured")
    changes = payload.model_dump(exclude_unset=True)
    internal = {key: value for key, value in (gateway.config or {}).items() if str(key).startswith("_")}
    gateway.config = {**sanitize_config(gateway.config), **changes, **internal}
    ctx.audit(
        action="edge.gateway.update_config",
        resource_type="edge_gateway",
        resource_id=str(gateway.id),
        payload={"fields": sorted(changes.keys())},
    )
    ctx.db.commit()
    ctx.db.refresh(gateway)
    return GatewayOut.model_validate(service.serialize_gateway(gateway))


@router.post("/gateways/{gateway_id}/revoke", response_model=GatewayOut, summary="Revoke an edge gateway")
def revoke_gateway(gateway_id: UUID, ctx: RequestContext = Depends(require_permission("edge:write"))) -> GatewayOut:
    gateway = service.get_gateway(ctx.db, ctx.org.id, gateway_id)
    if gateway.status == "revoked":
        raise Conflict("Gateway is already revoked")
    gateway.status = "revoked"
    gateway.revoked_at = utcnow()
    ctx.audit(
        action="edge.gateway.revoke",
        resource_type="edge_gateway",
        resource_id=str(gateway.id),
        payload={"fingerprint": gateway.fingerprint},
    )
    ctx.db.commit()
    ctx.db.refresh(gateway)
    return GatewayOut.model_validate(service.serialize_gateway(gateway))


@router.post(
    "/gateways/{gateway_id}/rotate-key",
    response_model=GatewayRotateKeyResult,
    summary="Rotate the gateway HMAC key (returned once)",
)
def rotate_gateway_key(
    gateway_id: UUID, ctx: RequestContext = Depends(require_permission("edge:write"))
) -> GatewayRotateKeyResult:
    gateway = service.get_gateway(ctx.db, ctx.org.id, gateway_id)
    result = service.rotate_gateway_key(ctx.db, ctx, gateway)
    return GatewayRotateKeyResult(**result)


@router.get(
    "/gateways/{gateway_id}/config-bundle/signed",
    summary="Signed configuration bundle for the gateway itself (HMAC-authenticated)",
)
async def get_config_bundle_signed(
    gateway_id: UUID,
    request: Request,
    db: Session = Depends(get_db),
    x_gateway_fingerprint: str | None = Header(default=None, alias="X-Gateway-Fingerprint"),
    x_gateway_timestamp: str | None = Header(default=None, alias="X-Gateway-Timestamp"),
    x_gateway_signature: str | None = Header(default=None, alias="X-Gateway-Signature"),
) -> dict[str, Any]:
    """Allow a gateway to refresh its own signed configuration.

    Tenant operators keep using the `edge:read` endpoint. The gateway proves its
    identity with the same HMAC scheme used for heartbeat and telemetry, so no
    long-lived user session is shipped to an edge device.
    """
    raw = await request.body()
    if len(raw) > 8_000:
        raise ValidationFailure([{"field": "body", "message": "Bundle request body is too large"}])
    gateway, secret = service.authenticate_gateway(
        db,
        gateway_id,
        fingerprint=x_gateway_fingerprint,
        timestamp=x_gateway_timestamp,
        signature=x_gateway_signature,
        method=request.method,
        path=request.url.path,
        body=raw,
    )
    if gateway.status == "revoked":
        raise Conflict("A revoked gateway has no active configuration bundle")
    bundle = service.build_config_bundle(gateway, secret)
    append_audit(
        db,
        org_id=gateway.org_id,
        action="edge.gateway.config_bundle.read",
        resource_type="edge_gateway",
        resource_id=str(gateway.id),
        actor_type="system",
        actor_id=f"gateway:{gateway.id}",
        payload={"fingerprint": gateway.fingerprint, "channel": "gateway-hmac"},
    )
    db.commit()
    return bundle


@router.get("/gateways/{gateway_id}/config-bundle", summary="Signed gateway configuration bundle")
def get_config_bundle(
    gateway_id: UUID, ctx: RequestContext = Depends(require_permission("edge:read"))
) -> dict[str, Any]:
    gateway = service.get_gateway(ctx.db, ctx.org.id, gateway_id)
    if gateway.status == "revoked":
        raise Conflict("A revoked gateway has no active configuration bundle")
    ciphertext = gateway_secret_ciphertext(gateway.config)
    if not ciphertext:
        raise NotFound("Gateway signing key")
    try:
        secret = decrypt_secret(ciphertext)
    except ValueError as exc:
        raise Conflict("Gateway signing key is unavailable") from exc
    bundle = service.build_config_bundle(gateway, secret)
    ctx.audit(
        action="edge.gateway.config_bundle.read",
        resource_type="edge_gateway",
        resource_id=str(gateway.id),
        payload={"fingerprint": gateway.fingerprint},
    )
    ctx.db.commit()
    return bundle


@router.get(
    "/gateways/{gateway_id}/events",
    response_model=Page[GatewayIngestEventOut],
    summary="List telemetry batches received from a gateway",
)
def list_gateway_events(
    gateway_id: UUID,
    ctx: RequestContext = Depends(require_permission("edge:read")),
    accepted: bool | None = Query(default=None),
    kind: str | None = Query(default=None, max_length=40),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
) -> Page[GatewayIngestEventOut]:
    gateway = service.get_gateway(ctx.db, ctx.org.id, gateway_id)
    stmt = select(EdgeIngestEvent).where(EdgeIngestEvent.gateway_id == gateway.id)
    if accepted is not None:
        stmt = stmt.where(EdgeIngestEvent.accepted.is_(accepted))
    if kind:
        stmt = stmt.where(EdgeIngestEvent.kind == kind)
    stmt = stmt.order_by(EdgeIngestEvent.received_at.desc())
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[GatewayIngestEventOut](
        **paginate([GatewayIngestEventOut.model_validate(row) for row in rows], total, page, page_size)
    )


__all__ = ["router"]
