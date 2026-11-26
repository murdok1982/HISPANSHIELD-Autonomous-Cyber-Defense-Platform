"""Connector registry, health, read-only invocation and synchronisation API."""

from __future__ import annotations

import re
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, or_, select
from sqlalchemy.exc import IntegrityError

from app.core.crypto import encrypt_secret
from app.core.deps import RequestContext, require_permission
from app.core.errors import Conflict, PolicyDenied, ServiceUnavailable, ValidationFailure
from app.core.rate_limit import enforce
from app.core.schemas import Page, paginate
from app.models.connectors import Connector
from app.models.events import IngestSource
from app.models.ti import TIFeed
from app.modules.connectors.schemas import (
    ConnectorCatalogOut,
    ConnectorCreate,
    ConnectorHealthOut,
    ConnectorHealthResultOut,
    ConnectorHealthSummaryOut,
    ConnectorInvokeRequest,
    ConnectorInvokeResultOut,
    ConnectorOut,
    ConnectorPatch,
    ConnectorRunOut,
    ConnectorSyncRequest,
    ConnectorSyncResultOut,
)
from app.modules.connectors.service import (
    build_catalog,
    build_health_summary,
    capability_manifest,
    get_connector,
    initial_status,
    list_runs,
    run_health,
    run_invoke,
    serialize_connector,
    validate_configuration,
)
from app.modules.connectors.sync import run_sync
from app.services.connectors.base import READ, ConnectorAdapter, get_adapter_class
from app.services.connectors.secrets import redact_config

router = APIRouter(prefix="/connectors", tags=["Connectors & Integrations"])

CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9_]{1,59}$")

SORT_COLUMNS = {
    "name": Connector.name,
    "connector_type": Connector.connector_type,
    "status": Connector.status,
    "created_at": Connector.created_at,
    "updated_at": Connector.updated_at,
    "last_health_at": Connector.last_health_at,
}


def _adapter_class(connector_type: str) -> type[ConnectorAdapter]:
    adapter_class = get_adapter_class(connector_type)
    if adapter_class is None:
        raise ValidationFailure(
            [{"field": "connector_type", "message": "No adapter is installed for this connector type"}]
        )
    return adapter_class


def _ensure_unique_name(db, org_id: UUID, name: str, exclude: UUID | None = None) -> None:  # type: ignore[no-untyped-def]
    stmt = select(Connector.id).where(Connector.org_id == org_id, func.lower(Connector.name) == name.lower())
    if exclude is not None:
        stmt = stmt.where(Connector.id != exclude)
    if db.execute(stmt.limit(1)).scalar_one_or_none() is not None:
        raise Conflict("A connector with this name already exists")


@router.get("/catalog", response_model=ConnectorCatalogOut, summary="Adapter catalogue and configuration gaps")
def get_catalog(ctx: RequestContext = Depends(require_permission("connector:read"))) -> ConnectorCatalogOut:
    return build_catalog(ctx.db, ctx.org.id)


@router.get("/health/summary", response_model=ConnectorHealthSummaryOut, summary="Connector fleet health")
def connector_health_summary(
    ctx: RequestContext = Depends(require_permission("connector:read")),
) -> ConnectorHealthSummaryOut:
    return build_health_summary(ctx.db, ctx.org.id)


@router.get("", response_model=Page[ConnectorOut], summary="List configured connectors")
def list_connectors(
    ctx: RequestContext = Depends(require_permission("connector:read")),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    q: str | None = Query(default=None, max_length=200),
    connector_type: str | None = Query(default=None, max_length=60, pattern=r"^[a-z][a-z0-9_]*$"),
    status: str | None = Query(default=None, max_length=20, pattern=r"^[a-z]+$"),
    enabled: bool | None = Query(default=None),
    sort: str = Query(default="name", max_length=40),
    order: str = Query(default="asc", pattern="^(asc|desc)$"),
) -> Page[ConnectorOut]:
    stmt = select(Connector).where(Connector.org_id == ctx.org.id)
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(Connector.name).like(needle),
                func.lower(Connector.connector_type).like(needle),
                func.lower(func.coalesce(Connector.base_url, "")).like(needle),
            )
        )
    if connector_type:
        stmt = stmt.where(Connector.connector_type == connector_type)
    if enabled is not None:
        stmt = stmt.where(Connector.enabled.is_(enabled))
    if status:
        if status == "disabled":
            stmt = stmt.where(Connector.enabled.is_(False))
        else:
            stmt = stmt.where(Connector.status == status, Connector.enabled.is_(True))
    column = SORT_COLUMNS.get(sort, Connector.name)
    stmt = stmt.order_by(column.asc() if order == "asc" else column.desc())
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[ConnectorOut](**paginate([serialize_connector(row) for row in rows], total, page, page_size))


@router.post("", response_model=ConnectorOut, status_code=201, summary="Register a connector")
def create_connector(
    payload: ConnectorCreate, ctx: RequestContext = Depends(require_permission("connector:write"))
) -> ConnectorOut:
    adapter_class = _adapter_class(payload.connector_type)
    validate_configuration(
        adapter_class,
        base_url=payload.base_url,
        auth_type=payload.auth_type,
        config=payload.config,
        verify_tls=payload.verify_tls,
    )
    _ensure_unique_name(ctx.db, ctx.org.id, payload.name)
    secret_encrypted = encrypt_secret(payload.secret) if payload.secret else None
    connector = Connector(
        org_id=ctx.org.id,
        name=payload.name,
        connector_type=payload.connector_type,
        version=payload.version,
        base_url=payload.base_url,
        auth_type=payload.auth_type,
        secret_encrypted=secret_encrypted,
        config=payload.config,
        capabilities=capability_manifest(adapter_class),
        status=initial_status(
            adapter_class,
            auth_type=payload.auth_type,
            has_secret=secret_encrypted is not None,
            config=payload.config,
            enabled=payload.enabled,
        ),
        enabled=payload.enabled,
        verify_tls=payload.verify_tls,
        rate_limit_per_minute=payload.rate_limit_per_minute,
        created_by=ctx.actor_id,
    )
    ctx.db.add(connector)
    try:
        ctx.db.flush()
    except IntegrityError as exc:
        ctx.db.rollback()
        raise Conflict("A connector with this name already exists") from exc
    ctx.audit(
        action="connector.create",
        resource_type="connector",
        resource_id=str(connector.id),
        payload={
            "name": connector.name,
            "connector_type": connector.connector_type,
            "auth_type": connector.auth_type,
            "base_url": connector.base_url,
            "auth_material_present": connector.secret_encrypted is not None,
            "config": redact_config(connector.config),
        },
    )
    ctx.db.commit()
    ctx.db.refresh(connector)
    return serialize_connector(connector)


@router.get("/{connector_id}", response_model=ConnectorOut, summary="Read a connector (secret redacted)")
def get_connector_detail(
    connector_id: UUID, ctx: RequestContext = Depends(require_permission("connector:read"))
) -> ConnectorOut:
    return serialize_connector(get_connector(ctx.db, ctx.org.id, connector_id))


@router.get(
    "/{connector_id}/health",
    response_model=ConnectorHealthOut,
    summary="Read the last persisted connector health state",
)
def get_connector_health(
    connector_id: UUID, ctx: RequestContext = Depends(require_permission("connector:read"))
) -> ConnectorHealthOut:
    connector = get_connector(ctx.db, ctx.org.id, connector_id)
    return serialize_connector(connector).health


@router.patch("/{connector_id}", response_model=ConnectorOut, summary="Update a connector or rotate its secret")
def update_connector(
    connector_id: UUID,
    payload: ConnectorPatch,
    ctx: RequestContext = Depends(require_permission("connector:write")),
) -> ConnectorOut:
    connector = get_connector(ctx.db, ctx.org.id, connector_id)
    adapter_class = _adapter_class(connector.connector_type)
    changes = payload.model_dump(exclude_unset=True)
    for field in ("name", "version", "auth_type", "config", "verify_tls", "rate_limit_per_minute", "enabled"):
        if field in changes and changes[field] is None:
            raise ValidationFailure([{"field": field, "message": f"{field} cannot be null"}])
    name = changes.get("name", connector.name)
    base_url = changes.get("base_url", connector.base_url)
    auth_type = changes.get("auth_type", connector.auth_type)
    config = changes.get("config", connector.config or {})
    verify_tls = changes.get("verify_tls", connector.verify_tls)
    validate_configuration(adapter_class, base_url=base_url, auth_type=auth_type, config=config, verify_tls=verify_tls)
    if "name" in changes and name != connector.name:
        _ensure_unique_name(ctx.db, ctx.org.id, name, exclude=connector.id)

    rotated = False
    if "secret" in changes:
        raw_secret = changes["secret"]
        connector.secret_encrypted = encrypt_secret(raw_secret) if raw_secret else None
        rotated = True
    for field in ("name", "version", "base_url", "auth_type", "config", "verify_tls", "rate_limit_per_minute"):
        if field in changes:
            setattr(connector, field, changes[field])
    if "enabled" in changes and changes["enabled"] is not None:
        enabled = bool(changes["enabled"])
        if not enabled:
            connector.status = "disabled"
        elif connector.status == "disabled":
            connector.status = "unknown"
        connector.enabled = enabled
    connector.capabilities = capability_manifest(adapter_class)
    if connector.enabled and connector.status == "unconfigured" and connector.secret_encrypted:
        connector.status = "unknown"
    try:
        ctx.db.flush()
    except IntegrityError as exc:
        ctx.db.rollback()
        raise Conflict("A connector with this name already exists") from exc
    ctx.audit(
        action="connector.update",
        resource_type="connector",
        resource_id=str(connector.id),
        payload={"fields": sorted(field for field in changes if field != "secret")},
    )
    if rotated:
        ctx.audit(
            action="connector.rotate_secret",
            resource_type="connector",
            resource_id=str(connector.id),
            payload={"auth_material_present": connector.secret_encrypted is not None},
        )
    ctx.db.commit()
    ctx.db.refresh(connector)
    return serialize_connector(connector)


@router.delete(
    "/{connector_id}",
    status_code=204,
    response_class=Response,
    summary="Delete an unreferenced connector",
)
def delete_connector(
    connector_id: UUID, ctx: RequestContext = Depends(require_permission("connector:write"))
) -> Response:
    connector = get_connector(ctx.db, ctx.org.id, connector_id)
    ingest_reference = ctx.db.execute(
        select(IngestSource.id).where(IngestSource.connector_id == connector.id).limit(1)
    ).scalar_one_or_none()
    feed_reference = ctx.db.execute(
        select(TIFeed.id).where(TIFeed.connector_id == connector.id).limit(1)
    ).scalar_one_or_none()
    if ingest_reference is not None or feed_reference is not None:
        raise Conflict(
            "Connector is referenced by ingest sources or threat-intelligence feeds; disable it instead",
            code="connector_in_use",
        )
    ctx.audit(
        action="connector.delete",
        resource_type="connector",
        resource_id=str(connector.id),
        payload={"name": connector.name, "connector_type": connector.connector_type},
    )
    ctx.db.delete(connector)
    ctx.db.commit()
    return Response(status_code=204)


@router.post("/{connector_id}/health", response_model=ConnectorHealthResultOut, summary="Probe connector health")
def probe_connector_health(
    connector_id: UUID, ctx: RequestContext = Depends(require_permission("connector:execute"))
) -> ConnectorHealthResultOut:
    connector = get_connector(ctx.db, ctx.org.id, connector_id)
    enforce(f"connector:{connector.id}:health", connector.rate_limit_per_minute, 60)
    result = run_health(ctx.db, connector, request_id=ctx.request_id)
    ctx.audit(
        action="connector.health",
        resource_type="connector",
        resource_id=str(connector.id),
        outcome="success" if result.ok else "failure",
        payload={"status": result.status, "latency_ms": result.latency_ms, "error": result.error},
    )
    ctx.db.commit()
    return result


@router.post(
    "/{connector_id}/invoke/{capability}",
    response_model=ConnectorInvokeResultOut,
    summary="Invoke a read-only connector capability",
)
def invoke_connector_capability(
    connector_id: UUID,
    capability: str,
    payload: ConnectorInvokeRequest,
    ctx: RequestContext = Depends(require_permission("connector:execute")),
) -> ConnectorInvokeResultOut:
    if not CAPABILITY_RE.match(capability):
        raise ValidationFailure([{"field": "capability", "message": "Invalid capability name"}])
    connector = get_connector(ctx.db, ctx.org.id, connector_id)
    adapter_class = _adapter_class(connector.connector_type)
    spec = next((item for item in adapter_class.capabilities if item.name == capability), None)
    if spec is None:
        raise ValidationFailure([{"field": "capability", "message": "The connector does not declare this capability"}])
    if spec.direction != READ:
        raise PolicyDenied(
            "Write, administrative and destructive capabilities must be executed through the action broker",
            details=[
                {
                    "capability": capability,
                    "direction": spec.direction,
                    "broker_action": "POST /api/v1/defence/actions",
                }
            ],
        )
    enforce(f"connector:{connector.id}:invoke", connector.rate_limit_per_minute, 60)
    try:
        result = run_invoke(ctx.db, connector, capability=capability, params=payload.params, request_id=ctx.request_id)
    except ServiceUnavailable:
        ctx.audit(
            action="connector.invoke",
            resource_type="connector",
            resource_id=str(connector.id),
            outcome="failure",
            payload={"capability": capability},
        )
        ctx.db.commit()
        raise
    ctx.audit(
        action="connector.invoke",
        resource_type="connector",
        resource_id=str(connector.id),
        outcome="success" if result.ok else "failure",
        payload={"capability": capability, "latency_ms": result.latency_ms, "ok": result.ok},
    )
    ctx.db.commit()
    return result


@router.post(
    "/{connector_id}/sync", response_model=ConnectorSyncResultOut, summary="Synchronise reads into the event fabric"
)
def sync_connector(
    connector_id: UUID,
    payload: ConnectorSyncRequest,
    ctx: RequestContext = Depends(require_permission("connector:execute")),
) -> ConnectorSyncResultOut:
    connector = get_connector(ctx.db, ctx.org.id, connector_id)
    enforce(f"connector:{connector.id}:sync", connector.rate_limit_per_minute, 60)
    try:
        result = run_sync(ctx.db, connector, limit=payload.limit, request_id=ctx.request_id)
    except ServiceUnavailable:
        ctx.audit(
            action="connector.sync",
            resource_type="connector",
            resource_id=str(connector.id),
            outcome="failure",
            payload={"limit": payload.limit},
        )
        ctx.db.commit()
        raise
    ctx.audit(
        action="connector.sync",
        resource_type="connector",
        resource_id=str(connector.id),
        payload={
            "events_created": result.events_created,
            "events_duplicate": result.events_duplicate,
            "indicators_created": result.indicators_created,
            "indicators_updated": result.indicators_updated,
            "capabilities": result.capabilities,
        },
    )
    ctx.db.commit()
    return result


@router.get(
    "/{connector_id}/runs",
    response_model=Page[ConnectorRunOut],
    summary="Connector run audit trail",
)
def list_connector_runs(
    connector_id: UUID,
    ctx: RequestContext = Depends(require_permission("connector:read")),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    operation: str | None = Query(default=None, max_length=120),
    status: str | None = Query(default=None, pattern="^(success|failed|error)$"),
) -> Page[ConnectorRunOut]:
    connector = get_connector(ctx.db, ctx.org.id, connector_id)
    rows, total = list_runs(ctx.db, connector, page=page, page_size=page_size, operation=operation, status=status)
    return Page[ConnectorRunOut](
        **paginate([ConnectorRunOut.model_validate(row) for row in rows], total, page, page_size)
    )


__all__ = ["router"]
