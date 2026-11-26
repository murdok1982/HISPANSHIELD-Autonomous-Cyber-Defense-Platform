"""Attack surface findings, inventory analysis and authorized discovery jobs."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import case, func, or_, select

from app.core.db import utcnow
from app.core.deps import RequestContext, require_permission
from app.core.errors import AppError, Conflict, Forbidden, NotFound, PolicyDenied
from app.core.schemas import Page, paginate
from app.models.assets import Asset, AttackSurfaceFinding, DiscoveryAuthorization, DiscoveryJob
from app.modules.attack_surface import discovery, service
from app.modules.attack_surface.schemas import (
    AnalyzeResult,
    DiscoveryAuthorizationCreate,
    DiscoveryAuthorizationOut,
    DiscoveryJobCreate,
    DiscoveryJobOut,
    DiscoveryJobPatch,
    DiscoveryRunRequest,
    DiscoveryRunResult,
    FindingCreate,
    FindingOut,
    FindingPatch,
    FindingSummaryOut,
)

router = APIRouter(prefix="/attack-surface", tags=["Attack Surface"])

SEVERITY_RANK = case(
    (AttackSurfaceFinding.severity == "critical", 5),
    (AttackSurfaceFinding.severity == "high", 4),
    (AttackSurfaceFinding.severity == "medium", 3),
    (AttackSurfaceFinding.severity == "low", 2),
    else_=1,
)

FINDING_SORTS = {
    "last_seen": AttackSurfaceFinding.last_seen,
    "first_seen": AttackSurfaceFinding.first_seen,
    "severity": SEVERITY_RANK,
    "status": AttackSurfaceFinding.status,
    "kind": AttackSurfaceFinding.kind,
    "title": AttackSurfaceFinding.title,
}

JOB_SORTS = {
    "created_at": DiscoveryJob.created_at,
    "name": DiscoveryJob.name,
    "started_at": DiscoveryJob.started_at,
    "status": DiscoveryJob.status,
}


def _get_finding(db, org_id: UUID, finding_id: UUID) -> AttackSurfaceFinding:
    finding = db.get(AttackSurfaceFinding, finding_id)
    if finding is None or finding.org_id != org_id:
        raise NotFound("Finding")
    return finding


def _get_job(db, org_id: UUID, job_id: UUID) -> DiscoveryJob:
    job = db.get(DiscoveryJob, job_id)
    if job is None or job.org_id != org_id:
        raise NotFound("Discovery job")
    return job


def _actor_uuid(ctx: RequestContext) -> UUID | None:
    """Actor as a users.id when the caller is a human session, else ``None``."""
    return ctx.user.id if ctx.user is not None else None


@router.get("/findings", response_model=Page[FindingOut], summary="List attack-surface findings")
def list_findings(
    ctx: RequestContext = Depends(require_permission("attack_surface:read")),
    severity: str | None = Query(default=None, pattern="^(critical|high|medium|low|info)$"),
    status: str | None = Query(default=None, pattern="^(open|triaged|accepted|resolved|false_positive)$"),
    kind: str | None = Query(default=None, max_length=60),
    asset_id: UUID | None = Query(default=None),
    q: str | None = Query(default=None, max_length=200),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    sort: str = Query(default="last_seen", pattern="^(" + "|".join(FINDING_SORTS) + ")$"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
) -> Page[FindingOut]:
    stmt = select(AttackSurfaceFinding).where(AttackSurfaceFinding.org_id == ctx.org.id)
    if severity:
        stmt = stmt.where(AttackSurfaceFinding.severity == severity)
    if status:
        stmt = stmt.where(AttackSurfaceFinding.status == status)
    if kind:
        stmt = stmt.where(AttackSurfaceFinding.kind == kind)
    if asset_id:
        stmt = stmt.where(AttackSurfaceFinding.asset_id == asset_id)
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(
            or_(
                func.lower(AttackSurfaceFinding.title).like(needle),
                func.lower(AttackSurfaceFinding.kind).like(needle),
                func.lower(AttackSurfaceFinding.evidence).like(needle),
            )
        )
    column = FINDING_SORTS[sort]
    stmt = stmt.order_by(column.asc() if order == "asc" else column.desc(), AttackSurfaceFinding.id.asc())
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[FindingOut](**paginate([FindingOut.model_validate(row) for row in rows], int(total), page, page_size))


@router.post("/findings", response_model=FindingOut, status_code=201, summary="Create a finding")
def create_finding(
    payload: FindingCreate, ctx: RequestContext = Depends(require_permission("attack_surface:write"))
) -> AttackSurfaceFinding:
    if payload.asset_id is not None:
        asset = ctx.db.get(Asset, payload.asset_id)
        if asset is None or asset.org_id != ctx.org.id:
            raise NotFound("Asset")
    finding = AttackSurfaceFinding(
        org_id=ctx.org.id,
        asset_id=payload.asset_id,
        kind=payload.kind,
        title=payload.title,
        severity=payload.severity,
        status=payload.status,
        evidence=payload.evidence,
        source=payload.source,
        metadata_json=payload.metadata,
    )
    ctx.db.add(finding)
    ctx.db.flush()
    ctx.audit(
        action="attack_surface.finding.create",
        resource_type="attack_surface_finding",
        resource_id=str(finding.id),
        payload={"kind": finding.kind, "severity": finding.severity, "asset_id": str(finding.asset_id or "")},
    )
    ctx.db.commit()
    ctx.db.refresh(finding)
    return finding


@router.get("/findings/{finding_id}", response_model=FindingOut, summary="Read a finding")
def read_finding(
    finding_id: UUID, ctx: RequestContext = Depends(require_permission("attack_surface:read"))
) -> AttackSurfaceFinding:
    return _get_finding(ctx.db, ctx.org.id, finding_id)


@router.patch("/findings/{finding_id}", response_model=FindingOut, summary="Update finding status")
def update_finding(
    finding_id: UUID,
    payload: FindingPatch,
    ctx: RequestContext = Depends(require_permission("attack_surface:write")),
) -> AttackSurfaceFinding:
    finding = _get_finding(ctx.db, ctx.org.id, finding_id)
    changes = payload.model_dump(exclude_unset=True)
    if "status" in changes and changes["status"] is not None:
        finding.status = changes["status"]
    if "severity" in changes and changes["severity"] is not None:
        finding.severity = changes["severity"]
    if "evidence" in changes:
        finding.evidence = changes["evidence"]
    if "metadata" in changes and changes["metadata"] is not None:
        finding.metadata_json = changes["metadata"]
    finding.last_seen = utcnow()
    ctx.audit(
        action="attack_surface.finding.update",
        resource_type="attack_surface_finding",
        resource_id=str(finding.id),
        payload={"fields": sorted(changes.keys()), "status": finding.status},
    )
    ctx.db.commit()
    ctx.db.refresh(finding)
    return finding


@router.post("/analyze", response_model=AnalyzeResult, summary="Analyse inventory and create deduplicated findings")
def analyze(
    ctx: RequestContext = Depends(require_permission("attack_surface:write")),
) -> AnalyzeResult:
    result = service.analyze(ctx.db, ctx.org.id)
    ctx.audit(
        action="attack_surface.analyze",
        resource_type="attack_surface",
        payload={
            "scanned_assets": result.scanned_assets,
            "created": result.created,
            "updated": result.updated,
            "by_kind": result.by_kind,
        },
    )
    ctx.db.commit()
    return result


@router.get("/summary", response_model=FindingSummaryOut, summary="Attack-surface summary")
def summary(ctx: RequestContext = Depends(require_permission("attack_surface:read"))) -> FindingSummaryOut:
    return service.finding_summary(ctx.db, ctx.org.id)


# ---------------------------------------------------------------------------
# Dual-control discovery authorizations
# ---------------------------------------------------------------------------


@router.get(
    "/authorizations",
    response_model=Page[DiscoveryAuthorizationOut],
    summary="List discovery authorizations",
)
def list_authorizations(
    ctx: RequestContext = Depends(require_permission("attack_surface:read")),
    status: str | None = Query(default=None, pattern="^(pending|approved|expired|revoked)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
) -> Page[DiscoveryAuthorizationOut]:
    now = utcnow()
    stmt = select(DiscoveryAuthorization).where(DiscoveryAuthorization.org_id == ctx.org.id)
    if status == "revoked":
        stmt = stmt.where(DiscoveryAuthorization.revoked_at.isnot(None))
    elif status == "pending":
        stmt = stmt.where(
            DiscoveryAuthorization.revoked_at.is_(None),
            DiscoveryAuthorization.approved_at.is_(None),
        )
    elif status == "approved":
        stmt = stmt.where(
            DiscoveryAuthorization.revoked_at.is_(None),
            DiscoveryAuthorization.approved_at.isnot(None),
            DiscoveryAuthorization.expires_at > now,
        )
    elif status == "expired":
        stmt = stmt.where(
            DiscoveryAuthorization.revoked_at.is_(None),
            DiscoveryAuthorization.approved_at.isnot(None),
            DiscoveryAuthorization.expires_at <= now,
        )
    stmt = stmt.order_by(DiscoveryAuthorization.created_at.desc(), DiscoveryAuthorization.id.asc())
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    items = [DiscoveryAuthorizationOut(**service.serialize_authorization(row)) for row in rows]
    return Page[DiscoveryAuthorizationOut](**paginate(items, int(total), page, page_size))


@router.post(
    "/authorizations",
    response_model=DiscoveryAuthorizationOut,
    status_code=201,
    summary="Request a discovery authorization (pending approval)",
)
def create_authorization(
    payload: DiscoveryAuthorizationCreate,
    ctx: RequestContext = Depends(require_permission("attack_surface:write")),
) -> DiscoveryAuthorizationOut:
    discovery.validate_scope_cidrs(payload.cidrs, required=True)
    ports = discovery.normalize_ports(payload.ports)
    authorization = DiscoveryAuthorization(
        org_id=ctx.org.id,
        name=payload.name,
        cidrs=payload.cidrs,
        ports=ports,
        max_hosts=payload.max_hosts,
        expires_at=payload.expires_at,
        created_by=_actor_uuid(ctx),
    )
    ctx.db.add(authorization)
    ctx.db.flush()
    ctx.audit(
        action="attack_surface.authorization.create",
        resource_type="discovery_authorization",
        resource_id=str(authorization.id),
        payload={
            "name": authorization.name,
            "cidrs": authorization.cidrs,
            "ports": authorization.ports,
            "expires_at": authorization.expires_at.isoformat(),
        },
    )
    ctx.db.commit()
    ctx.db.refresh(authorization)
    return DiscoveryAuthorizationOut(**service.serialize_authorization(authorization))


@router.post(
    "/authorizations/{authorization_id}/approve",
    response_model=DiscoveryAuthorizationOut,
    summary="Approve a discovery authorization (creator cannot self-approve)",
)
def approve_authorization(
    authorization_id: UUID,
    ctx: RequestContext = Depends(require_permission("attack_surface:write")),
) -> DiscoveryAuthorizationOut:
    authorization = discovery.load_authorization(ctx.db, ctx.org.id, authorization_id)
    actor = _actor_uuid(ctx)
    if actor is None:
        raise Forbidden("A human user session is required to approve a discovery authorization")
    if authorization.created_by is not None and authorization.created_by == actor:
        raise Forbidden("The creator of a discovery authorization cannot approve it")
    if authorization.revoked_at is not None:
        raise Conflict("A revoked discovery authorization cannot be approved")
    if authorization.approved_at is not None:
        raise Conflict("This discovery authorization is already approved")
    if discovery.authorization_status(authorization) == discovery.AUTHORIZATION_EXPIRED:
        raise PolicyDenied(
            "An expired discovery authorization cannot be approved",
            details=[{"field": "expires_at", "message": "Authorization expired"}],
        )
    authorization.approved_by = actor
    authorization.approved_at = utcnow()
    ctx.audit(
        action="attack_surface.authorization.approve",
        resource_type="discovery_authorization",
        resource_id=str(authorization.id),
        payload={"approved_by": str(actor), "expires_at": authorization.expires_at.isoformat()},
    )
    ctx.db.commit()
    ctx.db.refresh(authorization)
    return DiscoveryAuthorizationOut(**service.serialize_authorization(authorization))


@router.post(
    "/authorizations/{authorization_id}/revoke",
    response_model=DiscoveryAuthorizationOut,
    summary="Revoke a discovery authorization",
)
def revoke_authorization(
    authorization_id: UUID,
    ctx: RequestContext = Depends(require_permission("attack_surface:write")),
) -> DiscoveryAuthorizationOut:
    authorization = discovery.load_authorization(ctx.db, ctx.org.id, authorization_id)
    if authorization.revoked_at is not None:
        raise Conflict("This discovery authorization is already revoked")
    actor = _actor_uuid(ctx)
    authorization.revoked_at = utcnow()
    authorization.revoked_by = actor
    ctx.audit(
        action="attack_surface.authorization.revoke",
        resource_type="discovery_authorization",
        resource_id=str(authorization.id),
        payload={"revoked_by": str(actor) if actor else None},
    )
    ctx.db.commit()
    ctx.db.refresh(authorization)
    return DiscoveryAuthorizationOut(**service.serialize_authorization(authorization))


# ---------------------------------------------------------------------------
# Discovery jobs
# ---------------------------------------------------------------------------


@router.get("/discovery-jobs", response_model=Page[DiscoveryJobOut], summary="List discovery jobs")
def list_jobs(
    ctx: RequestContext = Depends(require_permission("attack_surface:read")),
    status: str | None = Query(default=None, pattern="^(pending|running|completed|failed)$"),
    mode: str | None = Query(default=None, pattern="^(passive|active)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
    sort: str = Query(default="created_at", pattern="^(" + "|".join(JOB_SORTS) + ")$"),
    order: str = Query(default="desc", pattern="^(asc|desc)$"),
) -> Page[DiscoveryJobOut]:
    stmt = select(DiscoveryJob).where(DiscoveryJob.org_id == ctx.org.id)
    if status:
        stmt = stmt.where(DiscoveryJob.status == status)
    if mode:
        stmt = stmt.where(DiscoveryJob.mode == mode)
    column = JOB_SORTS[sort]
    stmt = stmt.order_by(column.asc() if order == "asc" else column.desc(), DiscoveryJob.id.asc())
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[DiscoveryJobOut](
        **paginate([DiscoveryJobOut.model_validate(row) for row in rows], int(total), page, page_size)
    )


@router.post("/discovery-jobs", response_model=DiscoveryJobOut, status_code=201, summary="Create a discovery job")
def create_job(
    payload: DiscoveryJobCreate, ctx: RequestContext = Depends(require_permission("attack_surface:write"))
) -> DiscoveryJob:
    discovery.validate_scope_cidrs(payload.scope_cidrs, required=payload.mode == "active")
    authorization = service.resolve_job_authorization(
        ctx.db,
        ctx.org.id,
        payload.authorization_id,
        payload.scope_cidrs,
        required_scope=payload.mode == "active",
    )
    job = DiscoveryJob(
        org_id=ctx.org.id,
        name=payload.name,
        mode=payload.mode,
        scope_cidrs=payload.scope_cidrs,
        authorization_id=authorization.id,
        status="pending",
        authorized_by=payload.authorized_by,
        authorization_reference=payload.authorization_reference,
        authorized_at=utcnow() if payload.authorization_reference else None,
        summary={},
        created_by=ctx.actor_id,
    )
    ctx.db.add(job)
    ctx.db.flush()
    ctx.audit(
        action="attack_surface.discovery.create",
        resource_type="discovery_job",
        resource_id=str(job.id),
        payload={
            "name": job.name,
            "mode": job.mode,
            "scope_cidrs": job.scope_cidrs,
            "authorization_id": str(authorization.id),
        },
    )
    ctx.db.commit()
    ctx.db.refresh(job)
    return job


@router.get("/discovery-jobs/{job_id}", response_model=DiscoveryJobOut, summary="Read a discovery job")
def read_job(job_id: UUID, ctx: RequestContext = Depends(require_permission("attack_surface:read"))) -> DiscoveryJob:
    return _get_job(ctx.db, ctx.org.id, job_id)


@router.patch("/discovery-jobs/{job_id}", response_model=DiscoveryJobOut, summary="Update a discovery job")
def update_job(
    job_id: UUID,
    payload: DiscoveryJobPatch,
    ctx: RequestContext = Depends(require_permission("attack_surface:write")),
) -> DiscoveryJob:
    job = _get_job(ctx.db, ctx.org.id, job_id)
    changes = payload.model_dump(exclude_unset=True)
    next_mode = changes.get("mode") or job.mode
    next_scope = (
        changes["scope_cidrs"] if "scope_cidrs" in changes and changes["scope_cidrs"] is not None else job.scope_cidrs
    )
    next_authorization = changes.get("authorization_id") or job.authorization_id
    discovery.validate_scope_cidrs(next_scope, required=next_mode == "active")
    authorization = service.resolve_job_authorization(
        ctx.db,
        ctx.org.id,
        next_authorization,
        next_scope,
        required_scope=next_mode == "active",
    )
    for field in ("name", "mode", "scope_cidrs", "authorized_by", "authorization_reference"):
        if field in changes and changes[field] is not None:
            setattr(job, field, changes[field])
    job.authorization_id = authorization.id
    if changes.get("authorization_reference") and job.authorized_at is None:
        job.authorized_at = utcnow()
    job.updated_at = utcnow()
    ctx.audit(
        action="attack_surface.discovery.update",
        resource_type="discovery_job",
        resource_id=str(job.id),
        payload={"fields": sorted(changes.keys())},
    )
    ctx.db.commit()
    ctx.db.refresh(job)
    return job


@router.delete("/discovery-jobs/{job_id}", status_code=204, response_class=Response, summary="Delete a discovery job")
def delete_job(job_id: UUID, ctx: RequestContext = Depends(require_permission("attack_surface:write"))) -> Response:
    job = _get_job(ctx.db, ctx.org.id, job_id)
    if job.status == "running":
        raise Conflict("A running discovery job cannot be deleted")
    ctx.audit(
        action="attack_surface.discovery.delete",
        resource_type="discovery_job",
        resource_id=str(job.id),
        payload={"name": job.name},
    )
    ctx.db.delete(job)
    ctx.db.commit()
    return Response(status_code=204)


@router.post(
    "/discovery-jobs/{job_id}/run",
    response_model=DiscoveryRunResult,
    summary="Execute a bounded authorized discovery run",
)
async def run_job(
    job_id: UUID,
    payload: DiscoveryRunRequest | None = None,
    ctx: RequestContext = Depends(require_permission("attack_surface:write")),
) -> DiscoveryRunResult:
    job = _get_job(ctx.db, ctx.org.id, job_id)
    if job.status == "running":
        raise Conflict("This discovery job is already running")
    request = payload or DiscoveryRunRequest()
    selected_ports = discovery.normalize_ports(request.ports)
    discovery.validate_scope_cidrs(job.scope_cidrs, required=job.mode == "active")
    authorization = service.resolve_job_authorization(
        ctx.db,
        ctx.org.id,
        job.authorization_id,
        job.scope_cidrs,
        required_scope=job.mode == "active",
    )
    if job.mode == "active":
        selected_ports = discovery.ensure_ports_authorized(selected_ports, authorization)

    job.status = "running"
    job.started_at = utcnow()
    job.finished_at = None
    if job.authorization_reference:
        job.authorized_at = job.authorized_at or utcnow()
    try:
        summary = await service.execute_job(ctx.db, ctx.org.id, job, selected_ports)
    except AppError as exc:
        ctx.db.rollback()
        failed = _get_job(ctx.db, ctx.org.id, job_id)
        failed.status = "failed"
        failed.finished_at = utcnow()
        failed.summary = {"error": exc.message, "code": exc.code}
        ctx.audit(
            action="attack_surface.discovery.run",
            resource_type="discovery_job",
            resource_id=str(job_id),
            outcome="failure",
            payload={"mode": failed.mode, "error": exc.message},
        )
        ctx.db.commit()
        raise

    summary["runs"] = int((job.summary or {}).get("runs", 0)) + 1
    job.status = "completed"
    job.finished_at = utcnow()
    job.summary = summary
    ctx.audit(
        action="attack_surface.discovery.run",
        resource_type="discovery_job",
        resource_id=str(job.id),
        payload={
            "mode": job.mode,
            "scope_cidrs": job.scope_cidrs,
            "summary": summary,
            "authorization_id": str(job.authorization_id) if job.authorization_id else None,
            "authorization_reference": job.authorization_reference,
        },
    )
    ctx.db.commit()
    ctx.db.refresh(job)
    return DiscoveryRunResult(job=DiscoveryJobOut.model_validate(job), summary=summary)


__all__ = ["router"]
