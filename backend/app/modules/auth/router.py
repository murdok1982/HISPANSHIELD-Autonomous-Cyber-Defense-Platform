"""Authentication API endpoints."""

from __future__ import annotations

from typing import Literal, TypedDict
from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import append_audit
from app.core.config import settings
from app.core.crypto import constant_time_equals, hash_password, token_hash, verify_password
from app.core.db import get_db, utcnow
from app.core.deps import RequestContext, get_context, require_permission
from app.core.errors import AppError, Forbidden, NotFound, Unauthorized, ValidationFailure
from app.core.rate_limit import enforce
from app.core.rbac import ALL_PERMISSIONS, ROLE_PERMISSIONS, effective_permissions
from app.core.schemas import COMMON_PASSWORDS, PasswordPolicyError, validate_password_strength
from app.models.core import ApiToken, BreakGlassGrant, Invitation, Membership, Notification, Organization, User
from app.models.core import Session as AuthSession
from app.modules.auth import service
from app.modules.auth.schemas import (
    ApiTokenCreate,
    ApiTokenCreated,
    ApiTokenInfo,
    BreakGlassRequest,
    BreakGlassResponse,
    ChangePasswordRequest,
    InvitationAccepted,
    InvitationAcceptRequest,
    LoginRequest,
    MfaActivateRequest,
    MfaDisableRequest,
    MfaEnrollment,
    MfaEnrollRequest,
    MfaRequiredResponse,
    MfaVerifyRequest,
    PasswordPolicyOut,
    PermissionsCatalogue,
    RecoveryCodesRequest,
    RecoveryLoginRequest,
    SessionInfo,
    SessionSummary,
    SwitchOrgRequest,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


class _CookieOptions(TypedDict):
    """Explicit type for the shared ``set_cookie`` keyword arguments."""

    max_age: int
    path: str
    samesite: Literal["lax", "strict", "none"]
    domain: str | None


def _set_session_cookies(response: Response, raw_token: str, session: AuthSession) -> None:
    max_age = settings.session_ttl_minutes * 60
    common: _CookieOptions = {
        "max_age": max_age,
        "path": "/",
        "samesite": "strict",
        "domain": settings.cookie_domain or None,
    }
    response.set_cookie(
        settings.cookie_name,
        raw_token,
        httponly=True,
        secure=settings.cookie_secure,
        **common,
    )
    response.set_cookie(
        settings.csrf_cookie_name,
        session.csrf_token,
        httponly=False,
        secure=settings.cookie_secure,
        **common,
    )


def _clear_session_cookies(response: Response) -> None:
    response.delete_cookie(settings.cookie_name, path="/", domain=settings.cookie_domain or None)
    response.delete_cookie(settings.csrf_cookie_name, path="/", domain=settings.cookie_domain or None)


def _client_ip(request: Request) -> str:
    return (request.client.host if request.client else "unknown")[:64]


@router.get("/password-policy", response_model=PasswordPolicyOut, summary="Public password and session policy")
def password_policy() -> PasswordPolicyOut:
    """Expose the same rules the server enforces, so clients can pre-validate.

    No account data is returned; this endpoint is intentionally unauthenticated
    (the login form needs it before a session exists).
    """
    return PasswordPolicyOut(
        min_length=12,
        max_length=128,
        required_classes=3,
        classes=["lowercase", "uppercase", "digits", "symbols"],
        denylist_entries=len(COMMON_PASSWORDS),
        mfa_recovery_codes=10,
        session_idle_minutes=settings.session_idle_minutes,
        session_ttl_minutes=settings.session_ttl_minutes,
    )


@router.post(
    "/invitations/accept", response_model=InvitationAccepted, summary="Accept a one-time organization invitation"
)
def accept_invitation(
    payload: InvitationAcceptRequest,
    request: Request,
    db: Session = Depends(get_db),
) -> InvitationAccepted:
    enforce(f"invite:ip:{_client_ip(request)}", 10, 3600)
    normalized = str(payload.token).strip()
    invitation = db.execute(
        select(Invitation).where(Invitation.token_hash == token_hash(normalized)).with_for_update()
    ).scalar_one_or_none()
    if invitation is None:
        raise NotFound("Invitation")
    if invitation.status == "consumed":
        raise AppError("invite_consumed", "Invitation has already been used", 410)
    if invitation.status == "revoked":
        raise AppError("invite_revoked", "Invitation was revoked", 410)
    if invitation.status != "pending" or invitation.expires_at <= utcnow():
        invitation.status = "expired"
        db.commit()
        raise AppError("invite_expired", "Invitation has expired", 410)

    org = db.get(Organization, invitation.org_id)
    if org is None or org.deleted_at is not None:
        raise NotFound("Organization")
    user = db.execute(select(User).where(User.email == invitation.email)).scalar_one_or_none()
    already_member = False
    if user is None:
        try:
            validate_password_strength(payload.password, email=invitation.email)
        except PasswordPolicyError as exc:
            raise ValidationFailure([{"field": "password", "message": "; ".join(exc.violations)}]) from exc
        user = User(
            email=invitation.email,
            full_name=(payload.full_name or invitation.email.split("@", 1)[0])[:200],
            password_hash=hash_password(payload.password),
            status="active",
        )
        db.add(user)
        db.flush()
    else:
        if not verify_password(payload.password, user.password_hash):
            raise Unauthorized("Invalid credentials for the invited account")
        if user.status != "active":
            raise Forbidden("The invited account is not active")

    membership = db.execute(
        select(Membership).where(Membership.org_id == org.id, Membership.user_id == user.id)
    ).scalar_one_or_none()
    if membership is not None and membership.status == "active":
        already_member = True
    elif membership is not None:
        membership.status = "active"
        membership.role = invitation.role
    else:
        db.add(
            Membership(
                org_id=org.id,
                user_id=user.id,
                role=invitation.role,
                status="active",
                invited_by=invitation.invited_by,
            )
        )

    invitation.status = "consumed"
    invitation.consumed_at = utcnow()
    if invitation.invited_by:
        db.add(
            Notification(
                org_id=org.id,
                user_id=invitation.invited_by,
                kind="invitation",
                title=f"Invitation accepted by {user.email}"[:240],
                body=f"Role {invitation.role} in {org.name}",
                resource_type="user",
                resource_id=str(user.id),
            )
        )
    append_audit(
        db,
        org_id=org.id,
        action="organization.invitation.accept",
        resource_type="membership",
        resource_id=str(user.id),
        actor_type="user",
        actor_id=str(user.id),
        actor_email=user.email,
        payload={"role": invitation.role, "already_member": already_member},
        request_id=getattr(request.state, "request_id", None),
        ip_address=_client_ip(request),
        user_agent=(request.headers.get("user-agent") or "")[:400],
    )
    db.commit()
    return InvitationAccepted(
        user_id=user.id,
        email=user.email,
        organization_id=org.id,
        organization_slug=org.slug,
        role=invitation.role,
        already_member=already_member,
    )


@router.post(
    "/login",
    response_model=None,
    summary="Authenticate with email and password (MFA-aware)",
    responses={
        200: {"description": "Session established or MFA challenge issued"},
        401: {"description": "Invalid credentials"},
    },
)
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    ip = request.client.host if request.client else "unknown"
    enforce(f"login:ip:{ip}", settings.login_rate_limit_per_minute, 60)
    email_key = token_hash(payload.email.strip().lower())[:32]
    enforce(f"login:email:{email_key}", settings.login_rate_limit_per_minute, 60)

    result = service.authenticate_password(db, email=payload.email, password=payload.password, ip=ip)
    if isinstance(result, str):
        append_audit(
            db,
            org_id=None,
            action="auth.mfa.challenge",
            resource_type="auth",
            outcome="pending",
            actor_email=payload.email.strip().lower(),
            ip_address=ip,
        )
        db.commit()
        return MfaRequiredResponse(challenge_token=result, expires_in=service.CHALLENGE_TTL_SECONDS)

    user, _default_org, _role = result
    org, role = service.select_org_for_login(db, user, payload.org_slug)
    raw_token, session = service.finalize_password_login(
        db, user=user, org=org, role=role, ip=ip, user_agent=request.headers.get("user-agent")
    )
    info = service.serialize_session(db, user, org, session, role)
    db.commit()
    _set_session_cookies(response, raw_token, session)
    return info


@router.post("/mfa/verify", response_model=SessionInfo, summary="Complete login with a TOTP code")
def mfa_verify(
    payload: MfaVerifyRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> dict:
    ip = request.client.host if request.client else "unknown"
    enforce(f"mfa:ip:{ip}", settings.login_rate_limit_per_minute, 60)
    # A challenge is single-attempt-bounded too: a leaked token cannot be used
    # to brute-force six-digit codes from a rotating IP pool.
    enforce(f"mfa:challenge:{token_hash(payload.challenge_token)[:32]}", 5, 300)
    user, org, role, raw_token, session = service.complete_mfa_login(
        db,
        challenge_token=payload.challenge_token,
        code=payload.code,
        ip=ip,
        user_agent=request.headers.get("user-agent"),
    )
    info = service.serialize_session(db, user, org, session, role)
    db.commit()
    _set_session_cookies(response, raw_token, session)
    return info


@router.post("/mfa/recovery", response_model=SessionInfo, summary="Complete login with a recovery code")
def mfa_recovery(
    payload: RecoveryLoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db),
) -> dict:
    ip = request.client.host if request.client else "unknown"
    enforce(f"mfa:recovery:ip:{ip}", settings.login_rate_limit_per_minute, 60)
    enforce(f"mfa:recovery:{token_hash(payload.challenge_token)[:32]}", 5, 300)
    user, org, role, raw_token, session = service.complete_recovery_login(
        db,
        challenge_token=payload.challenge_token,
        recovery_code=payload.recovery_code,
        ip=ip,
        user_agent=request.headers.get("user-agent"),
    )
    info = service.serialize_session(db, user, org, session, role)
    db.commit()
    _set_session_cookies(response, raw_token, session)
    return info


@router.post("/logout", summary="Revoke the current session")
def logout(request: Request, response: Response, db: Session = Depends(get_db)) -> dict:
    raw = request.cookies.get(settings.cookie_name)
    if raw:
        session = db.execute(select(AuthSession).where(AuthSession.token_hash == token_hash(raw))).scalar_one_or_none()
        if session and session.revoked_at is None:
            header_csrf = request.headers.get("X-CSRF-Token")
            if header_csrf and constant_time_equals(header_csrf, session.csrf_token):
                service.revoke_session(db, session, "logout")
                append_audit(
                    db,
                    org_id=session.org_id,
                    action="auth.logout",
                    resource_type="auth",
                    resource_id=str(session.user_id),
                    actor_id=str(session.user_id),
                    payload={"session_id": str(session.id)},
                    ip_address=request.client.host if request.client else None,
                )
                db.commit()
    _clear_session_cookies(response)
    return {"message": "Signed out"}


@router.get("/me", response_model=SessionInfo, summary="Current user, organization and permissions")
def me(ctx: RequestContext = Depends(get_context)) -> dict:
    assert ctx.user is not None
    if ctx.session is not None:
        return service.serialize_session(ctx.db, ctx.user, ctx.org, ctx.session, ctx.role)
    # API-token callers have no browser session and therefore no CSRF token.
    orgs = service.user_organizations(ctx.db, ctx.user)
    return {
        "user": {
            "id": ctx.user.id,
            "email": ctx.user.email,
            "full_name": ctx.user.full_name,
            "status": ctx.user.status,
            "is_platform_admin": ctx.user.is_platform_admin,
            "mfa_enabled": ctx.user.mfa_enabled,
            "locale": ctx.user.locale,
            "timezone": ctx.user.timezone,
            "last_login_at": ctx.user.last_login_at,
            "created_at": ctx.user.created_at,
        },
        "organization": {
            "id": ctx.org.id,
            "slug": ctx.org.slug,
            "name": ctx.org.name,
            "kind": ctx.org.kind,
            "is_demo": ctx.org.is_demo,
            "role": "api_token",
        },
        "role": "api_token",
        "permissions": ctx.permissions,
        "organizations": [
            {"id": org.id, "slug": org.slug, "name": org.name, "kind": org.kind, "is_demo": org.is_demo, "role": role}
            for org, role in orgs
        ],
        "csrf_token": "",
        "autonomy_level": ctx.org.autonomy_level,
        "expires_at": ctx.api_token.expires_at if ctx.api_token and ctx.api_token.expires_at else utcnow(),
    }


@router.post("/switch-org", response_model=SessionInfo, summary="Switch the active organization")
def switch_org(payload: SwitchOrgRequest, ctx: RequestContext = Depends(get_context)) -> dict:
    assert ctx.user is not None and ctx.session is not None
    membership = ctx.db.execute(
        select(Membership).where(
            Membership.user_id == ctx.user.id,
            Membership.org_id == payload.org_id,
            Membership.status == "active",
        )
    ).scalar_one_or_none()
    org = ctx.db.get(Organization, payload.org_id)
    if org is None or org.deleted_at is not None or org.status != "active":
        raise NotFound("Organization")
    if membership is None:
        if not ctx.user.is_platform_admin:
            raise NotFound("Organization")
        grant = service.active_break_glass(ctx.db, ctx.user.id, org.id)
        if grant is None:
            raise Forbidden(
                "break_glass_required: request an approved break-glass grant before selecting this organization"
            )
    role = "platform_admin" if ctx.user.is_platform_admin else membership.role  # type: ignore[union-attr]
    ctx.session.org_id = org.id
    ctx.audit(
        action="auth.org.switch",
        resource_type="organization",
        resource_id=str(org.id),
        payload={"from": str(ctx.org.id), "to": str(org.id)},
    )
    info = service.serialize_session(ctx.db, ctx.user, org, ctx.session, role)
    ctx.db.commit()
    return info


@router.post(
    "/break-glass",
    response_model=BreakGlassResponse,
    summary="Create a time-boxed, justified platform-admin grant for another organization",
)
def break_glass(payload: BreakGlassRequest, ctx: RequestContext = Depends(get_context)) -> BreakGlassResponse:
    assert ctx.user is not None
    if not ctx.user.is_platform_admin:
        raise Forbidden("Break-glass access is reserved for platform administrators")
    org = ctx.db.get(Organization, payload.org_id)
    if org is None or org.deleted_at is not None or org.status != "active":
        raise NotFound("Organization")
    grant = service.create_break_glass(
        ctx.db,
        user=ctx.user,
        org=org,
        reason=payload.reason,
        ticket=payload.ticket,
        request_id=ctx.request_id,
    )
    ctx.db.commit()
    return BreakGlassResponse(
        grant_id=grant.id,
        org_id=org.id,
        expires_at=grant.expires_at,
        reason=grant.reason,
        ticket=grant.ticket,
        status=grant.status,
        approved_by=grant.approved_by,
        approved_at=grant.approved_at,
    )


@router.post(
    "/break-glass/{grant_id}/approve",
    response_model=BreakGlassResponse,
    summary="Approve a break-glass grant requested by another platform administrator",
)
def approve_break_glass(grant_id: UUID, ctx: RequestContext = Depends(get_context)) -> BreakGlassResponse:
    assert ctx.user is not None
    grant = ctx.db.get(BreakGlassGrant, grant_id)
    if grant is None:
        raise NotFound("Break-glass grant")
    service.approve_break_glass(ctx.db, grant, approver=ctx.user)
    ctx.db.commit()
    return BreakGlassResponse(
        grant_id=grant.id,
        org_id=grant.org_id,
        expires_at=grant.expires_at,
        reason=grant.reason,
        ticket=grant.ticket,
        status=grant.status,
        approved_by=grant.approved_by,
        approved_at=grant.approved_at,
    )


@router.post("/break-glass/{grant_id}/revoke", summary="Revoke a break-glass grant immediately")
def revoke_break_glass(grant_id: UUID, ctx: RequestContext = Depends(get_context)) -> dict:
    assert ctx.user is not None
    if not ctx.user.is_platform_admin:
        raise Forbidden("Only platform administrators can revoke break-glass grants")
    grant = ctx.db.get(BreakGlassGrant, grant_id)
    if grant is None:
        raise NotFound("Break-glass grant")
    if grant.user_id != ctx.user.id and not ctx.user.is_platform_admin:
        raise Forbidden("Not allowed")
    service.revoke_break_glass(ctx.db, grant, actor=ctx.user)
    ctx.db.commit()
    return {"message": "Break-glass grant revoked", "grant_id": str(grant.id)}


@router.post("/change-password", summary="Change the current account password")
def change_password(payload: ChangePasswordRequest, ctx: RequestContext = Depends(get_context)) -> dict:
    assert ctx.user is not None
    try:
        validate_password_strength(payload.new_password, email=ctx.user.email)
    except PasswordPolicyError as exc:
        raise ValidationFailure([{"field": "new_password", "message": v} for v in exc.violations]) from exc
    service.change_password(ctx.db, ctx.user, payload.current_password, payload.new_password)
    revoked = service.revoke_user_sessions(
        ctx.db, ctx.user.id, except_session_id=ctx.session.id if ctx.session else None, reason="password_change"
    )
    ctx.audit(
        action="auth.password.change",
        resource_type="user",
        resource_id=str(ctx.user.id),
        payload={"revoked_sessions": revoked},
    )
    ctx.db.commit()
    return {"message": "Password updated", "revoked_sessions": revoked}


@router.post("/mfa/enroll", response_model=MfaEnrollment, summary="Start TOTP enrollment")
def mfa_enroll(payload: MfaEnrollRequest, ctx: RequestContext = Depends(get_context)) -> MfaEnrollment:
    assert ctx.user is not None
    if ctx.user.mfa_enabled:
        raise Forbidden("MFA is already enabled; disable it before re-enrolling")
    secret, uri = service.start_mfa_enrollment(ctx.db, ctx.user, password=payload.password)
    ctx.audit(action="auth.mfa.enroll", resource_type="user", resource_id=str(ctx.user.id))
    ctx.db.commit()
    return MfaEnrollment(secret=secret, otpauth_uri=uri, issuer="HISPANSHIELD")


@router.post("/mfa/activate", summary="Confirm and activate TOTP")
def mfa_activate(payload: MfaActivateRequest, ctx: RequestContext = Depends(get_context)) -> dict:
    assert ctx.user is not None
    service.activate_mfa(ctx.db, ctx.user, payload.code, password=payload.password)
    recovery_codes = service.generate_recovery_codes(ctx.db, ctx.user)
    revoked = service.revoke_user_sessions(
        ctx.db, ctx.user.id, except_session_id=ctx.session.id if ctx.session else None, reason="mfa_activated"
    )
    ctx.audit(
        action="auth.mfa.enable",
        resource_type="user",
        resource_id=str(ctx.user.id),
        payload={"revoked_other_sessions": revoked, "recovery_codes": len(recovery_codes)},
    )
    ctx.db.commit()
    return {
        "message": "MFA enabled",
        "revoked_other_sessions": revoked,
        "recovery_codes": recovery_codes,
        "recovery_codes_notice": "Store these codes offline. They are shown only once and each can be used once.",
    }


@router.post("/mfa/recovery-codes", summary="Regenerate one-time MFA recovery codes")
def mfa_regenerate_recovery_codes(payload: RecoveryCodesRequest, ctx: RequestContext = Depends(get_context)) -> dict:
    assert ctx.user is not None
    if not ctx.user.mfa_enabled:
        raise Forbidden("MFA is not enabled for this account")
    if not verify_password(payload.password, ctx.user.password_hash):
        raise Unauthorized("Password is incorrect")
    codes = service.generate_recovery_codes(ctx.db, ctx.user)
    ctx.audit(
        action="auth.mfa.recovery_codes.regenerate",
        resource_type="user",
        resource_id=str(ctx.user.id),
        payload={"count": len(codes)},
    )
    ctx.db.commit()
    return {
        "recovery_codes": codes,
        "recovery_codes_notice": "Existing codes are now invalid. Store the new set offline.",
    }


@router.post("/mfa/disable", summary="Disable TOTP with password and code confirmation")
def mfa_disable(payload: MfaDisableRequest, ctx: RequestContext = Depends(get_context)) -> dict:
    assert ctx.user is not None
    service.disable_mfa(ctx.db, ctx.user, payload.password, payload.code)
    ctx.audit(action="auth.mfa.disable", resource_type="user", resource_id=str(ctx.user.id))
    ctx.db.commit()
    return {"message": "MFA disabled"}


@router.get("/api-tokens", response_model=list[ApiTokenInfo], summary="List API tokens")
def list_tokens(ctx: RequestContext = Depends(require_permission("apikey:manage"))) -> list[ApiToken]:
    assert ctx.user is not None
    return list(
        ctx.db.execute(
            select(ApiToken)
            .where(ApiToken.org_id == ctx.org.id, ApiToken.created_by == ctx.user.id, ApiToken.revoked_at.is_(None))
            .order_by(ApiToken.created_at.desc())
        ).scalars()
    )


@router.post("/api-tokens", response_model=ApiTokenCreated, status_code=201, summary="Create an API token")
def create_token(
    payload: ApiTokenCreate, ctx: RequestContext = Depends(require_permission("apikey:manage"))
) -> ApiTokenCreated:
    assert ctx.user is not None
    # A platform administrator has every permission plus the "*" wildcard; an
    # API token must carry concrete scopes, so never persist the wildcard.
    scopes = payload.scopes or [scope for scope in ctx.permissions if scope != "*"]
    record, raw = service.create_api_token(
        ctx.db,
        user=ctx.user,
        org=ctx.org,
        name=payload.name,
        scopes=scopes,
        expires_days=payload.expires_days,
        granted_permissions=ctx.permissions,
    )
    ctx.audit(
        action="auth.token.create",
        resource_type="api_token",
        resource_id=str(record.id),
        payload={"name": payload.name, "scopes": scopes, "expires_days": payload.expires_days},
    )
    ctx.db.commit()
    return ApiTokenCreated(
        id=record.id,
        name=record.name,
        token=raw,
        prefix=record.prefix,
        scopes=record.scopes,
        expires_at=record.expires_at,
    )


@router.delete("/api-tokens/{token_id}", summary="Revoke an API token")
def revoke_token(token_id: UUID, ctx: RequestContext = Depends(require_permission("apikey:manage"))) -> dict:
    assert ctx.user is not None
    token = ctx.db.get(ApiToken, token_id)
    if token is None or token.org_id != ctx.org.id or token.created_by != ctx.user.id:
        raise NotFound("API token")
    token.revoked_at = utcnow()
    ctx.audit(action="auth.token.revoke", resource_type="api_token", resource_id=str(token.id))
    ctx.db.commit()
    return {"message": "Token revoked"}


@router.get("/sessions", response_model=list[SessionSummary], summary="List my active sessions")
def list_sessions(ctx: RequestContext = Depends(get_context)) -> list[SessionSummary]:
    assert ctx.user is not None
    current_id = ctx.session.id if ctx.session else None
    return [
        SessionSummary(
            id=session.id,
            created_at=session.created_at,
            last_seen_at=session.last_seen_at,
            expires_at=session.expires_at,
            ip_address=session.ip_address,
            user_agent=session.user_agent,
            mfa_verified=session.mfa_verified,
            is_current=session.id == current_id,
        )
        for session in service.list_active_sessions(ctx.db, ctx.user.id)
    ]


@router.delete("/sessions/{session_id}", status_code=204, summary="Revoke one of my other sessions")
def revoke_other_session(session_id: UUID, ctx: RequestContext = Depends(get_context)) -> Response:
    assert ctx.user is not None
    if ctx.session is not None and ctx.session.id == session_id:
        raise Forbidden("Use /auth/logout to revoke the current session")
    session = ctx.db.get(AuthSession, session_id)
    if session is None or session.user_id != ctx.user.id or session.revoked_at is not None:
        raise NotFound("Session")
    service.revoke_session(ctx.db, session, "revoked_by_user")
    ctx.audit(
        action="auth.session.revoke",
        resource_type="auth_session",
        resource_id=str(session.id),
        payload={"reason": "revoked_by_user"},
    )
    ctx.db.commit()
    return Response(status_code=204)


@router.get("/permissions", response_model=PermissionsCatalogue, summary="Permission and role catalogue")
def permissions_catalogue(ctx: RequestContext = Depends(get_context)) -> PermissionsCatalogue:
    roles: dict[str, list[str]] = {
        role: effective_permissions(role) for role in ROLE_PERMISSIONS if role != "platform_admin"
    }
    return PermissionsCatalogue(permissions=ALL_PERMISSIONS, roles=roles)
