"""Request authentication, tenant resolution and authorization dependencies."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from fastapi import Depends, Header, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import append_audit
from app.core.config import settings
from app.core.crypto import constant_time_equals, token_hash
from app.core.db import get_db, utcnow
from app.core.errors import Forbidden, NotFound, Unauthorized
from app.core.rate_limit import enforce
from app.core.rbac import ROLE_PERMISSIONS, effective_permissions, has_permission
from app.models.core import ApiToken, BreakGlassGrant, Membership, Organization, User
from app.models.core import Session as AuthSession

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


@dataclass
class RequestContext:
    org: Organization
    role: str
    permissions: list[str]
    request: Request
    db: Session
    user: User | None = None
    membership: Membership | None = None
    session: AuthSession | None = None
    api_token: ApiToken | None = None
    request_id: str = "-"
    ip_address: str | None = None
    user_agent: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def actor_id(self) -> str | None:
        if self.user:
            return str(self.user.id)
        if self.api_token:
            return f"token:{self.api_token.id}"
        return None

    @property
    def actor_email(self) -> str | None:
        return self.user.email if self.user else None

    @property
    def actor_type(self) -> str:
        return "api_token" if self.api_token else "user"

    def can(self, permission: str) -> bool:
        if self.role == "platform_admin":
            return True
        for granted in self.permissions:
            if granted == "*" or granted == permission:
                return True
            if granted.endswith(":*") and permission.startswith(granted[:-1]):
                return True
        return has_permission(self.role, permission) if self.role in ROLE_PERMISSIONS else False

    def require(self, permission: str) -> None:
        if not self.can(permission):
            raise Forbidden(f"Missing permission: {permission}")

    def audit(
        self,
        *,
        action: str,
        resource_type: str,
        resource_id: str | None = None,
        outcome: str = "success",
        payload: dict[str, Any] | None = None,
        org_id: UUID | None = None,
    ) -> None:
        append_audit(
            self.db,
            org_id=org_id if org_id is not None else self.org.id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            actor_type=self.actor_type,
            actor_id=self.actor_id,
            actor_email=self.actor_email,
            outcome=outcome,
            payload=payload,
            request_id=self.request_id,
            ip_address=self.ip_address,
            user_agent=self.user_agent,
        )


def _client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _resolve_session_user(db: Session, token: str) -> tuple[AuthSession | None, User | None]:
    session = db.execute(select(AuthSession).where(AuthSession.token_hash == token_hash(token))).scalar_one_or_none()
    if session is None:
        return None, None
    now = utcnow()
    expires_at = session.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if session.revoked_at is not None or expires_at <= now:
        return session, None
    if (now - _as_utc(session.last_seen_at)).total_seconds() > settings.session_idle_minutes * 60:
        return session, None
    user = db.get(User, session.user_id)
    if user is None or user.status != "active":
        return session, None
    if user.locked_until and user.locked_until > now:
        return session, None
    return session, user


def _resolve_api_token(db: Session, token: str) -> tuple[ApiToken | None, User | None]:
    record = db.execute(select(ApiToken).where(ApiToken.token_hash == token_hash(token))).scalar_one_or_none()
    if record is None or record.revoked_at is not None:
        return None, None
    now = utcnow()
    if record.expires_at and record.expires_at <= now:
        return None, None
    creator = db.get(User, record.created_by) if record.created_by else None
    if creator is not None and creator.status != "active":
        return None, None
    return record, creator


def _resolve_org(
    db: Session, user: User, bound_org_id: UUID | None, requested_org_id: UUID | None
) -> tuple[Organization, Membership | None, str]:
    if user.is_platform_admin:
        org_id = requested_org_id or bound_org_id
        if org_id is None:
            membership = db.execute(
                select(Membership).where(Membership.user_id == user.id, Membership.status == "active").limit(1)
            ).scalar_one_or_none()
            org_id = membership.org_id if membership else None
        org = db.get(Organization, org_id) if org_id else None
        if org is None or org.deleted_at is not None:
            raise NotFound("Organization")
        membership = db.execute(
            select(Membership).where(
                Membership.user_id == user.id, Membership.org_id == org.id, Membership.status == "active"
            )
        ).scalar_one_or_none()
        if membership is None:
            grant = db.execute(
                select(BreakGlassGrant)
                .where(
                    BreakGlassGrant.user_id == user.id,
                    BreakGlassGrant.org_id == org.id,
                    BreakGlassGrant.status == "approved",
                    BreakGlassGrant.revoked_at.is_(None),
                    BreakGlassGrant.expires_at > utcnow(),
                )
                .limit(1)
            ).scalar_one_or_none()
            if grant is None:
                # Conceal existence exactly as for a regular tenant boundary.
                # The administrator obtains access through /auth/break-glass.
                raise NotFound("Organization")
        return org, membership, "platform_admin"

    membership_query = select(Membership).where(Membership.user_id == user.id, Membership.status == "active")
    if requested_org_id:
        membership_query = membership_query.where(Membership.org_id == requested_org_id)
    elif bound_org_id:
        membership_query = membership_query.where(Membership.org_id == bound_org_id)
    membership = db.execute(membership_query.limit(1)).scalar_one_or_none()
    if membership is None:
        # Never reveal whether a foreign organization exists.
        raise NotFound("Organization")
    org = db.get(Organization, membership.org_id)
    if org is None or org.deleted_at is not None or org.status != "active":
        raise NotFound("Organization")
    return org, membership, membership.role


def get_context(
    request: Request,
    db: Session = Depends(get_db),
    x_organization_id: UUID | None = Header(default=None, alias="X-Organization-Id"),
    authorization: str | None = Header(default=None),
    x_csrf_token: str | None = Header(default=None, alias="X-CSRF-Token"),
) -> RequestContext:
    session: AuthSession | None = None
    api_token: ApiToken | None = None
    user: User | None = None

    if authorization:
        scheme, _, credentials = authorization.partition(" ")
        if scheme.lower() != "bearer" or not credentials:
            raise Unauthorized("Malformed Authorization header")
        api_token, user = _resolve_api_token(db, credentials.strip())
        if api_token is None:
            raise Unauthorized("Invalid or expired API token")
        if api_token.last_used_at is None or (utcnow() - api_token.last_used_at).total_seconds() > 60:
            api_token.last_used_at = utcnow()
    else:
        cookie_token = request.cookies.get(settings.cookie_name)
        if not cookie_token:
            raise Unauthorized()
        session, user = _resolve_session_user(db, cookie_token)
        if session is None or user is None:
            raise Unauthorized("Session expired or revoked")
        if request.method not in SAFE_METHODS and (
            not x_csrf_token or not constant_time_equals(x_csrf_token, session.csrf_token)
        ):
            raise Forbidden("CSRF token missing or invalid")
        if (utcnow() - _as_utc(session.last_seen_at)).total_seconds() > 300:
            session.last_seen_at = utcnow()
            db.commit()

    assert user is not None
    if api_token and api_token.org_id and x_organization_id and api_token.org_id != x_organization_id:
        raise Forbidden("API token is scoped to a different organization")
    org, membership, role = _resolve_org(
        db, user, api_token.org_id if api_token else (session.org_id if session else None), x_organization_id
    )
    if api_token is not None:
        permissions = list(api_token.scopes) if api_token.scopes else ["viewer:read"]
        role = "api_token"
    else:
        assert membership is not None or user.is_platform_admin
        permissions = effective_permissions(role)

    ctx = RequestContext(
        org=org,
        role=role,
        permissions=permissions,
        request=request,
        db=db,
        user=user,
        membership=membership,
        session=session,
        api_token=api_token,
        request_id=getattr(request.state, "request_id", "-"),
        ip_address=_client_ip(request),
        user_agent=request.headers.get("user-agent"),
    )

    # General authenticated API rate limit (login has a stricter dedicated bucket).
    limit_key = f"api:{user.id}" if user else f"api:{ctx.ip_address}"
    enforce(limit_key, settings.rate_limit_per_minute, 60)
    return ctx


def require_permission(permission: str) -> Callable[..., RequestContext]:
    def dependency(ctx: RequestContext = Depends(get_context)) -> RequestContext:
        ctx.require(permission)
        return ctx

    return dependency


def require_any_permission(*permissions: str) -> Callable[..., RequestContext]:
    def dependency(ctx: RequestContext = Depends(get_context)) -> RequestContext:
        if not any(ctx.can(permission) for permission in permissions):
            raise Forbidden(f"Missing one of permissions: {', '.join(permissions)}")
        return ctx

    return dependency


def get_current_user(ctx: RequestContext = Depends(get_context)) -> User:
    if ctx.user is None:
        raise Unauthorized()
    return ctx.user
