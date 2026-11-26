"""Authentication API endpoints."""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import append_audit
from app.core.config import settings
from app.core.crypto import constant_time_equals, token_hash
from app.core.db import get_db, utcnow
from app.core.deps import RequestContext, get_context, require_permission
from app.core.errors import Forbidden, NotFound, ValidationFailure
from app.core.rate_limit import enforce
from app.core.rbac import ALL_PERMISSIONS, ROLE_PERMISSIONS, effective_permissions
from app.core.schemas import PasswordPolicyError, validate_password_strength
from app.models.core import ApiToken, Membership, Organization
from app.models.core import Session as AuthSession
from app.modules.auth import service
from app.modules.auth.schemas import (
    ApiTokenCreate,
    ApiTokenCreated,
    ApiTokenInfo,
    ChangePasswordRequest,
    LoginRequest,
    MfaActivateRequest,
    MfaDisableRequest,
    MfaEnrollment,
    MfaRequiredResponse,
    MfaVerifyRequest,
    PermissionsCatalogue,
    SessionInfo,
    SwitchOrgRequest,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


def _set_session_cookies(response: Response, raw_token: str, session: AuthSession) -> None:
    max_age = settings.session_ttl_minutes * 60
    common = {
        "max_age": max_age,
        "path": "/",
        "samesite": "lax",
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
        "user": ctx.user,
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
    if membership is None and not ctx.user.is_platform_admin:
        raise NotFound("Organization")
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
def mfa_enroll(ctx: RequestContext = Depends(get_context)) -> MfaEnrollment:
    assert ctx.user is not None
    if ctx.user.mfa_enabled:
        raise Forbidden("MFA is already enabled; disable it before re-enrolling")
    secret, uri = service.start_mfa_enrollment(ctx.db, ctx.user)
    ctx.audit(action="auth.mfa.enroll", resource_type="user", resource_id=str(ctx.user.id))
    ctx.db.commit()
    return MfaEnrollment(secret=secret, otpauth_uri=uri, issuer="HISPANSHIELD")


@router.post("/mfa/activate", summary="Confirm and activate TOTP")
def mfa_activate(payload: MfaActivateRequest, ctx: RequestContext = Depends(get_context)) -> dict:
    assert ctx.user is not None
    service.activate_mfa(ctx.db, ctx.user, payload.code)
    ctx.audit(action="auth.mfa.enable", resource_type="user", resource_id=str(ctx.user.id))
    ctx.db.commit()
    return {"message": "MFA enabled"}


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
    scopes = payload.scopes or ctx.permissions
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


@router.get("/permissions", response_model=PermissionsCatalogue, summary="Permission and role catalogue")
def permissions_catalogue(ctx: RequestContext = Depends(get_context)) -> PermissionsCatalogue:
    roles: dict[str, list[str]] = {
        role: effective_permissions(role) for role in ROLE_PERMISSIONS if role != "platform_admin"
    }
    return PermissionsCatalogue(permissions=ALL_PERMISSIONS, roles=roles)
