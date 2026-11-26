"""Organization administration endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.audit import verify_audit_chain
from app.core.crypto import hash_password
from app.core.db import utcnow
from app.core.deps import RequestContext, get_context, require_permission
from app.core.errors import Conflict, Forbidden, NotFound, ValidationFailure
from app.core.schemas import Page, PasswordPolicyError, paginate, validate_password_strength
from app.models.connectors import Connector
from app.models.core import Approval, AuditRecord, KillSwitch, Membership, Organization, Policy, User
from app.modules.auth.service import user_organizations
from app.modules.organizations.schemas import (
    ApprovalDecision,
    ApprovalOut,
    AuditOut,
    KillSwitchCreate,
    KillSwitchOut,
    MemberCreate,
    MemberOut,
    MemberPatch,
    OrganizationCreate,
    OrganizationOut,
    OrganizationPatch,
    PolicyCreate,
    PolicyOut,
    PolicyPatch,
)

router = APIRouter(prefix="/organizations", tags=["Organizations & Governance"])


def _org_out(org: Organization) -> OrganizationOut:
    return OrganizationOut.model_validate(org)


def _member_out(membership: Membership, user: User) -> MemberOut:
    return MemberOut(
        id=membership.id,
        user_id=user.id,
        email=user.email,
        full_name=user.full_name,
        role=membership.role,
        status=membership.status,
        mfa_enabled=user.mfa_enabled,
        last_login_at=user.last_login_at,
        created_at=membership.created_at,
    )


def _get_org_or_404(db: Session, org_id: UUID) -> Organization:
    org = db.get(Organization, org_id)
    if org is None or org.deleted_at is not None:
        raise NotFound("Organization")
    return org


@router.get("", response_model=list[OrganizationOut], summary="List organizations visible to the caller")
def list_organizations(ctx: RequestContext = Depends(require_permission("org:read"))) -> list[OrganizationOut]:
    if ctx.user and ctx.user.is_platform_admin:
        orgs = list(
            ctx.db.execute(
                select(Organization).where(Organization.deleted_at.is_(None)).order_by(Organization.name)
            ).scalars()
        )
    else:
        orgs = [org for org, _role in user_organizations(ctx.db, ctx.user)]
    return [_org_out(org) for org in orgs]


@router.post("", response_model=OrganizationOut, status_code=201, summary="Create an organization")
def create_organization(
    payload: OrganizationCreate, ctx: RequestContext = Depends(require_permission("org:write"))
) -> OrganizationOut:
    if not (ctx.user and ctx.user.is_platform_admin):
        raise Forbidden("Only platform administrators can create organizations")
    if ctx.db.execute(select(Organization).where(Organization.slug == payload.slug)).scalar_one_or_none():
        raise Conflict("An organization with this slug already exists")
    org = Organization(**payload.model_dump())
    ctx.db.add(org)
    ctx.db.flush()
    ctx.audit(
        action="organization.create",
        resource_type="organization",
        resource_id=str(org.id),
        payload={"slug": org.slug, "name": org.name},
        org_id=org.id,
    )
    ctx.db.commit()
    return _org_out(org)


@router.get("/current", response_model=OrganizationOut, summary="Active organization profile")
def current_organization(ctx: RequestContext = Depends(get_context)) -> OrganizationOut:
    return _org_out(ctx.org)


@router.patch("/current", response_model=OrganizationOut, summary="Update the active organization")
def update_current_organization(
    payload: OrganizationPatch, ctx: RequestContext = Depends(require_permission("org:write"))
) -> OrganizationOut:
    data = payload.model_dump(exclude_unset=True)
    for field, value in data.items():
        setattr(ctx.org, field, value)
    ctx.audit(
        action="organization.update",
        resource_type="organization",
        resource_id=str(ctx.org.id),
        payload={"fields": sorted(data.keys())},
    )
    ctx.db.commit()
    return _org_out(ctx.org)


@router.get("/current/members", response_model=Page[MemberOut], summary="List organization members")
def list_members(
    ctx: RequestContext = Depends(require_permission("user:read")),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    q: str | None = Query(default=None, max_length=120),
) -> Page[MemberOut]:
    stmt = (
        select(Membership, User)
        .join(User, User.id == Membership.user_id)
        .where(Membership.org_id == ctx.org.id)
        .order_by(User.full_name.asc())
    )
    if q:
        needle = f"%{q.lower()}%"
        stmt = stmt.where(or_(func.lower(User.email).like(needle), func.lower(User.full_name).like(needle)))
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).all()
    items = [_member_out(membership, user) for membership, user in rows]
    return Page[MemberOut](**paginate(items, total, page, page_size))


@router.post("/current/members", response_model=MemberOut, status_code=201, summary="Add a member to the organization")
def add_member(payload: MemberCreate, ctx: RequestContext = Depends(require_permission("user:manage"))) -> MemberOut:
    email = payload.email.strip().lower()
    user = ctx.db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    created = False
    if user is None:
        if not payload.password:
            raise ValidationFailure([{"field": "password", "message": "A password is required for a new account"}])
        try:
            validate_password_strength(payload.password, email=email)
        except PasswordPolicyError as exc:
            raise ValidationFailure([{"field": "password", "message": v} for v in exc.violations]) from exc
        user = User(
            email=email,
            full_name=payload.full_name.strip(),
            password_hash=hash_password(payload.password),
            status="active",
            locale="es",
        )
        ctx.db.add(user)
        ctx.db.flush()
        created = True
    else:
        if ctx.db.execute(
            select(Membership).where(Membership.org_id == ctx.org.id, Membership.user_id == user.id)
        ).scalar_one_or_none():
            raise Conflict("The user is already a member of this organization")

    membership = Membership(org_id=ctx.org.id, user_id=user.id, role=payload.role, status="active")
    ctx.db.add(membership)
    ctx.db.flush()
    ctx.audit(
        action="organization.member.add",
        resource_type="membership",
        resource_id=str(membership.id),
        payload={"email": email, "role": payload.role, "new_account": created},
    )
    ctx.db.commit()
    return _member_out(membership, user)


@router.patch("/current/members/{membership_id}", response_model=MemberOut, summary="Update a member role or status")
def update_member(
    membership_id: UUID,
    payload: MemberPatch,
    ctx: RequestContext = Depends(require_permission("user:manage")),
) -> MemberOut:
    membership = ctx.db.get(Membership, membership_id)
    if membership is None or membership.org_id != ctx.org.id:
        raise NotFound("Membership")
    user = ctx.db.get(User, membership.user_id)
    if user is None:
        raise NotFound("User")
    if ctx.user and user.id == ctx.user.id and payload.status == "suspended":
        raise Conflict("You cannot suspend your own membership")

    demoting = (payload.role is not None and payload.role != "org_admin") or (
        payload.status is not None and payload.status != "active"
    )
    if membership.role == "org_admin" and demoting:
        remaining = ctx.db.execute(
            select(func.count())
            .select_from(Membership)
            .where(
                Membership.org_id == ctx.org.id,
                Membership.role == "org_admin",
                Membership.status == "active",
                Membership.id != membership.id,
            )
        ).scalar_one()
        if remaining == 0:
            raise Conflict("The organization must retain at least one active administrator")

    changes = payload.model_dump(exclude_unset=True)
    for field, value in changes.items():
        setattr(membership, field, value)
    if payload.status == "suspended" and payload.status != "active":
        # Suspension is org-scoped; the account keeps access to other organizations.
        pass
    ctx.audit(
        action="organization.member.update",
        resource_type="membership",
        resource_id=str(membership.id),
        payload={"changes": changes, "email": user.email},
    )
    ctx.db.commit()
    return _member_out(membership, user)


@router.delete(
    "/current/members/{membership_id}",
    status_code=204,
    response_class=Response,
    summary="Remove a member from the organization",
)
def remove_member(membership_id: UUID, ctx: RequestContext = Depends(require_permission("user:manage"))) -> Response:
    membership = ctx.db.get(Membership, membership_id)
    if membership is None or membership.org_id != ctx.org.id:
        raise NotFound("Membership")
    if ctx.user and membership.user_id == ctx.user.id:
        raise Conflict("You cannot remove your own membership")
    if membership.role == "org_admin":
        remaining = ctx.db.execute(
            select(func.count())
            .select_from(Membership)
            .where(
                Membership.org_id == ctx.org.id,
                Membership.role == "org_admin",
                Membership.status == "active",
                Membership.id != membership.id,
            )
        ).scalar_one()
        if remaining == 0:
            raise Conflict("The organization must retain at least one active administrator")
    ctx.audit(
        action="organization.member.remove",
        resource_type="membership",
        resource_id=str(membership.id),
        payload={"user_id": str(membership.user_id)},
    )
    ctx.db.delete(membership)
    ctx.db.commit()
    return Response(status_code=204)


@router.get("/current/policies", response_model=list[PolicyOut], summary="List applicable policies")
def list_policies(ctx: RequestContext = Depends(require_permission("policy:read"))) -> list[Policy]:
    return list(
        ctx.db.execute(
            select(Policy)
            .where(or_(Policy.org_id == ctx.org.id, Policy.org_id.is_(None)))
            .order_by(Policy.kind.asc(), Policy.name.asc())
        ).scalars()
    )


@router.post("/current/policies", response_model=PolicyOut, status_code=201, summary="Create a policy")
def create_policy(payload: PolicyCreate, ctx: RequestContext = Depends(require_permission("policy:write"))) -> Policy:
    if ctx.db.execute(
        select(Policy).where(Policy.org_id == ctx.org.id, Policy.name == payload.name, Policy.version == 1)
    ).scalar_one_or_none():
        raise Conflict("A policy with this name already exists")
    policy = Policy(
        org_id=ctx.org.id,
        name=payload.name,
        kind=payload.kind,
        definition=payload.definition,
        description=payload.description,
        enabled=payload.enabled,
        created_by=ctx.actor_id,
    )
    ctx.db.add(policy)
    ctx.db.flush()
    ctx.audit(
        action="policy.create",
        resource_type="policy",
        resource_id=str(policy.id),
        payload={"name": policy.name, "kind": policy.kind, "version": policy.version},
    )
    ctx.db.commit()
    ctx.db.refresh(policy)
    return policy


@router.patch(
    "/current/policies/{policy_id}", response_model=PolicyOut, summary="Update a policy (creates a new version)"
)
def update_policy(
    policy_id: UUID, payload: PolicyPatch, ctx: RequestContext = Depends(require_permission("policy:write"))
) -> Policy:
    policy = ctx.db.get(Policy, policy_id)
    if policy is None or policy.org_id != ctx.org.id:
        raise NotFound("Policy")
    changes = payload.model_dump(exclude_unset=True)
    if "definition" in changes and changes["definition"] is not None:
        policy.definition = changes["definition"]
    if "description" in changes:
        policy.description = changes["description"]
    if "enabled" in changes and changes["enabled"] is not None:
        policy.enabled = changes["enabled"]
    policy.version += 1
    ctx.audit(
        action="policy.update",
        resource_type="policy",
        resource_id=str(policy.id),
        payload={"version": policy.version, "fields": sorted(changes.keys())},
    )
    ctx.db.commit()
    ctx.db.refresh(policy)
    return policy


@router.get("/current/kill-switches", response_model=list[KillSwitchOut], summary="List kill switches")
def list_kill_switches(ctx: RequestContext = Depends(require_permission("defence:read"))) -> list[KillSwitch]:
    return list(
        ctx.db.execute(
            select(KillSwitch)
            .where(or_(KillSwitch.org_id == ctx.org.id, KillSwitch.org_id.is_(None)))
            .order_by(KillSwitch.engaged_at.desc())
        ).scalars()
    )


@router.post("/current/kill-switches", response_model=KillSwitchOut, status_code=201, summary="Engage a kill switch")
def engage_kill_switch(
    payload: KillSwitchCreate, ctx: RequestContext = Depends(require_permission("killswitch:operate"))
) -> KillSwitch:
    org_id = ctx.org.id
    if payload.scope == "global":
        if not (ctx.user and ctx.user.is_platform_admin):
            raise Forbidden("Only platform administrators can engage the global kill switch")
        org_id = None
    if payload.scope in {"connector", "autonomy"} and not payload.target_id:
        raise ValidationFailure([{"field": "target_id", "message": "target_id is required for this scope"}])
    if payload.scope == "connector" and payload.target_id:
        connector = ctx.db.get(Connector, UUID(payload.target_id))
        if connector is None or connector.org_id != ctx.org.id:
            raise NotFound("Connector")

    for existing in ctx.db.execute(
        select(KillSwitch).where(KillSwitch.engaged.is_(True), KillSwitch.scope == payload.scope)
    ).scalars():
        if existing.target_id == payload.target_id and existing.org_id == org_id:
            raise Conflict("This kill switch is already engaged")

    switch = KillSwitch(
        org_id=org_id,
        scope=payload.scope,
        target_id=payload.target_id,
        engaged=True,
        reason=payload.reason,
        engaged_by=ctx.actor_email or ctx.actor_id,
    )
    ctx.db.add(switch)
    ctx.db.flush()
    ctx.audit(
        action="killswitch.engage",
        resource_type="kill_switch",
        resource_id=str(switch.id),
        payload={"scope": payload.scope, "target_id": payload.target_id, "reason": payload.reason},
        org_id=org_id or ctx.org.id,
    )
    ctx.db.commit()
    return switch


@router.post(
    "/current/kill-switches/{switch_id}/release", response_model=KillSwitchOut, summary="Release a kill switch"
)
def release_kill_switch(
    switch_id: UUID, ctx: RequestContext = Depends(require_permission("killswitch:operate"))
) -> KillSwitch:
    switch = ctx.db.get(KillSwitch, switch_id)
    if switch is None or (switch.org_id is not None and switch.org_id != ctx.org.id):
        raise NotFound("Kill switch")
    if switch.scope == "global" and not (ctx.user and ctx.user.is_platform_admin):
        raise Forbidden("Only platform administrators can release the global kill switch")
    switch.engaged = False
    switch.released_by = ctx.actor_email or ctx.actor_id
    switch.released_at = utcnow()
    ctx.audit(
        action="killswitch.release",
        resource_type="kill_switch",
        resource_id=str(switch.id),
        payload={"scope": switch.scope, "target_id": switch.target_id},
        org_id=ctx.org.id,
    )
    ctx.db.commit()
    return switch


@router.get("/current/approvals", response_model=Page[ApprovalOut], summary="List approval requests")
def list_approvals(
    ctx: RequestContext = Depends(require_permission("approval:read")),
    status: str | None = Query(default=None, pattern="^(pending|approved|rejected|expired)$"),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=200),
) -> Page[ApprovalOut]:
    stmt = select(Approval).where(Approval.org_id == ctx.org.id).order_by(Approval.created_at.desc())
    if status:
        stmt = stmt.where(Approval.status == status)
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[ApprovalOut](**paginate([ApprovalOut.model_validate(row) for row in rows], total, page, page_size))


@router.post(
    "/current/approvals/{approval_id}/decision", response_model=ApprovalOut, summary="Approve or reject a request"
)
def decide_approval(
    approval_id: UUID,
    payload: ApprovalDecision,
    ctx: RequestContext = Depends(require_permission("approval:decide")),
) -> Approval:
    approval = ctx.db.get(Approval, approval_id)
    if approval is None or approval.org_id != ctx.org.id:
        raise NotFound("Approval")
    if approval.status != "pending":
        raise Conflict("The approval is no longer pending")
    if approval.expires_at and approval.expires_at < utcnow():
        approval.status = "expired"
        ctx.db.commit()
        raise Conflict("The approval request has expired")
    if ctx.user and approval.requested_by_user_id == ctx.user.id:
        raise Forbidden("Separation of duties: the requester cannot approve their own action")
    approval.status = payload.decision
    approval.decided_by = ctx.user.id if ctx.user else None
    approval.decided_at = utcnow()
    approval.reason = payload.reason
    ctx.audit(
        action="approval.decide",
        resource_type="approval",
        resource_id=str(approval.id),
        payload={"decision": payload.decision, "request_type": approval.request_type},
    )
    ctx.db.commit()
    return approval


@router.get("/current/audit", response_model=Page[AuditOut], summary="Read the append-only audit trail")
def list_audit(
    ctx: RequestContext = Depends(require_permission("audit:read")),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    action: str | None = Query(default=None, max_length=120),
    resource_type: str | None = Query(default=None, max_length=80),
    outcome: str | None = Query(default=None, pattern="^(success|failure|pending)$"),
    actor: str | None = Query(default=None, max_length=255),
) -> Page[AuditOut]:
    stmt = select(AuditRecord).where(AuditRecord.org_id == ctx.org.id).order_by(AuditRecord.created_at.desc())
    if action:
        stmt = stmt.where(AuditRecord.action == action)
    if resource_type:
        stmt = stmt.where(AuditRecord.resource_type == resource_type)
    if outcome:
        stmt = stmt.where(AuditRecord.outcome == outcome)
    if actor:
        stmt = stmt.where(AuditRecord.actor_email == actor)
    total = ctx.db.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = list(ctx.db.execute(stmt.offset((page - 1) * page_size).limit(page_size)).scalars())
    return Page[AuditOut](**paginate([AuditOut.model_validate(row) for row in rows], total, page, page_size))


@router.get("/current/audit/verify", summary="Verify the audit hash chain")
def verify_audit(ctx: RequestContext = Depends(require_permission("audit:verify"))) -> dict:
    org_result = verify_audit_chain(ctx.db, ctx.org.id)
    global_result = verify_audit_chain(ctx.db, None)
    return {"organization": org_result, "global_tail": global_result, "verified_at": utcnow()}


@router.get("/{org_id}", response_model=OrganizationOut, summary="Read an organization")
def get_organization(org_id: UUID, ctx: RequestContext = Depends(require_permission("org:read"))) -> OrganizationOut:
    if org_id != ctx.org.id and not (ctx.user and ctx.user.is_platform_admin):
        raise NotFound("Organization")
    return _org_out(_get_org_or_404(ctx.db, org_id))
