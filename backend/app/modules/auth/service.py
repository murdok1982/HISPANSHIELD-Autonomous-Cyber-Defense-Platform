"""Authentication service: sessions, MFA, API tokens and organization selection."""

from __future__ import annotations

import base64
import json
import secrets
import time
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pyotp
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import append_audit
from app.core.config import settings
from app.core.crypto import (
    constant_time_equals,
    decrypt_secret,
    encrypt_secret,
    generate_token,
    hash_password,
    hmac_sha256_hex,
    token_hash,
    verify_password,
)
from app.core.db import utcnow
from app.core.errors import Forbidden, NotFound, Unauthorized, ValidationFailure
from app.core.rbac import ALL_PERMISSIONS, effective_permissions
from app.core.schemas import PasswordPolicyError, validate_password_strength
from app.models.core import ApiToken, BreakGlassGrant, Membership, Organization, User
from app.models.core import Session as AuthSession

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15
CHALLENGE_TTL_SECONDS = 300

_DUMMY_HASH = hash_password("HISPANSHIELD-dummy-password-for-timing-equalisation-9f2a")


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def find_user(db: Session, email: str) -> User | None:
    return db.execute(select(User).where(User.email == email.strip().lower())).scalar_one_or_none()


def user_organizations(db: Session, user: User) -> list[tuple[Organization, str]]:
    rows = db.execute(
        select(Organization, Membership.role)
        .join(Membership, Membership.org_id == Organization.id)
        .where(
            Membership.user_id == user.id,
            Membership.status == "active",
            Organization.deleted_at.is_(None),
            Organization.status == "active",
        )
        .order_by(Organization.name.asc())
    ).all()
    return [(org, role) for org, role in rows]


def create_session(
    db: Session, user: User, org: Organization, *, ip: str | None, user_agent: str | None, mfa_verified: bool
) -> tuple[str, AuthSession]:
    raw_token = generate_token(32)
    session = AuthSession(
        user_id=user.id,
        org_id=org.id,
        token_hash=token_hash(raw_token),
        csrf_token=generate_token(32),
        ip_address=ip,
        user_agent=(user_agent or "")[:400] or None,
        mfa_verified=mfa_verified,
        expires_at=utcnow() + timedelta(minutes=settings.session_ttl_minutes),
        last_seen_at=utcnow(),
    )
    db.add(session)
    db.flush()
    return raw_token, session


def authenticate_password(
    db: Session, *, email: str, password: str, ip: str | None
) -> tuple[User, Organization, str] | str:
    """Return (user, org, role) on success or an MFA challenge token."""
    normalized = email.strip().lower()
    user = find_user(db, normalized)
    now = utcnow()

    if user is None:
        verify_password(password, _DUMMY_HASH)
        append_audit(
            db,
            org_id=None,
            action="auth.login.failure",
            resource_type="auth",
            outcome="failure",
            actor_email=normalized,
            payload={"reason": "invalid_credentials"},
            ip_address=ip,
        )
        db.commit()
        raise Unauthorized("Invalid email or password")

    if user.locked_until and _as_utc(user.locked_until) > now:
        append_audit(
            db,
            org_id=None,
            action="auth.login.failure",
            resource_type="auth",
            resource_id=str(user.id),
            outcome="failure",
            actor_email=user.email,
            payload={"reason": "account_locked"},
            ip_address=ip,
        )
        db.commit()
        raise Unauthorized("Invalid email or password")

    if not verify_password(password, user.password_hash):
        user.failed_login_count += 1
        if user.failed_login_count >= MAX_FAILED_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
            user.failed_login_count = 0
        append_audit(
            db,
            org_id=None,
            action="auth.login.failure",
            resource_type="auth",
            resource_id=str(user.id),
            outcome="failure",
            actor_email=user.email,
            payload={"reason": "invalid_credentials"},
            ip_address=ip,
        )
        db.commit()
        raise Unauthorized("Invalid email or password")

    if user.status != "active":
        append_audit(
            db,
            org_id=None,
            action="auth.login.failure",
            resource_type="auth",
            resource_id=str(user.id),
            outcome="failure",
            actor_email=user.email,
            payload={"reason": "user_disabled"},
            ip_address=ip,
        )
        db.commit()
        raise Unauthorized("Invalid email or password")

    memberships = user_organizations(db, user)
    if not memberships:
        raise Forbidden("The account has no active organization membership")

    org, role = memberships[0]

    if user.mfa_enabled:
        db.commit()
        return issue_mfa_challenge(user)

    user.failed_login_count = 0
    user.last_login_at = now
    return user, org, role


def select_org_for_login(db: Session, user: User, org_slug: str | None) -> tuple[Organization, str]:
    memberships = user_organizations(db, user)
    if not memberships:
        raise Forbidden("The account has no active organization membership")
    if org_slug:
        for org, role in memberships:
            if org.slug == org_slug:
                return org, role
        raise NotFound("Organization")
    return memberships[0]


def issue_mfa_challenge(user: User) -> str:
    payload = {
        "uid": str(user.id),
        "exp": int(time.time()) + CHALLENGE_TTL_SECONDS,
        "nonce": secrets.token_urlsafe(16),
        "purpose": "mfa",
    }
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac_sha256_hex(settings.secret_key, encoded.encode())
    return f"{encoded}.{signature}"


def verify_challenge(token: str) -> UUID:
    try:
        encoded, signature = token.split(".", 1)
        expected = hmac_sha256_hex(settings.secret_key, encoded.encode())
        if not constant_time_equals(signature, expected):
            raise Unauthorized("Invalid or expired MFA challenge")
        padded = encoded + "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()))
        if payload.get("purpose") != "mfa" or int(payload.get("exp", 0)) < int(time.time()):
            raise Unauthorized("Invalid or expired MFA challenge")
        return UUID(payload["uid"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise Unauthorized("Invalid or expired MFA challenge") from exc


def verify_totp(user: User, code: str) -> bool:
    if not user.mfa_secret_encrypted:
        return False
    secret = decrypt_secret(user.mfa_secret_encrypted)
    totp = pyotp.TOTP(secret)
    current_counter = int(time.time()) // 30
    for offset in (0, -1, 1):
        counter = current_counter + offset
        if totp.verify(code, for_time=datetime.fromtimestamp(counter * 30, tz=UTC), valid_window=0):
            # Replay protection: the same time step can never be accepted twice.
            if user.mfa_last_counter is not None and counter <= user.mfa_last_counter:
                return False
            user.mfa_last_counter = counter
            return True
    return False


def complete_mfa_login(
    db: Session, *, challenge_token: str, code: str, ip: str | None, user_agent: str | None
) -> tuple[User, Organization, str, str, AuthSession]:
    user_id = verify_challenge(challenge_token)
    user = db.get(User, user_id)
    if user is None or user.status != "active" or not user.mfa_enabled:
        raise Unauthorized("Invalid MFA challenge")
    if not verify_totp(user, code):
        append_audit(
            db,
            org_id=None,
            action="auth.mfa.failure",
            resource_type="auth",
            resource_id=str(user.id),
            outcome="failure",
            actor_email=user.email,
            ip_address=ip,
        )
        db.commit()
        raise Unauthorized("Invalid verification code")
    org, role = select_org_for_login(db, user, None)
    raw_token, session = create_session(db, user, org, ip=ip, user_agent=user_agent, mfa_verified=True)
    user.failed_login_count = 0
    user.last_login_at = utcnow()
    append_audit(
        db,
        org_id=org.id,
        action="auth.login.success",
        resource_type="auth",
        resource_id=str(user.id),
        actor_id=str(user.id),
        actor_email=user.email,
        payload={"mfa": True, "session_id": str(session.id)},
        ip_address=ip,
        user_agent=user_agent,
    )
    return user, org, role, raw_token, session


def finalize_password_login(
    db: Session,
    *,
    user: User,
    org: Organization,
    role: str,
    ip: str | None,
    user_agent: str | None,
) -> tuple[str, AuthSession]:
    raw_token, session = create_session(db, user, org, ip=ip, user_agent=user_agent, mfa_verified=False)
    user.failed_login_count = 0
    user.last_login_at = utcnow()
    append_audit(
        db,
        org_id=org.id,
        action="auth.login.success",
        resource_type="auth",
        resource_id=str(user.id),
        actor_id=str(user.id),
        actor_email=user.email,
        payload={"mfa": False, "session_id": str(session.id)},
        ip_address=ip,
        user_agent=user_agent,
    )
    return raw_token, session


def revoke_session(db: Session, session: AuthSession, reason: str = "logout") -> None:
    session.revoked_at = utcnow()
    session.revoked_reason = reason


def revoke_user_sessions(
    db: Session, user_id: UUID, *, except_session_id: UUID | None = None, reason: str = "security"
) -> int:
    query = select(AuthSession).where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
    sessions = list(db.execute(query).scalars())
    count = 0
    for session in sessions:
        if except_session_id and session.id == except_session_id:
            continue
        session.revoked_at = utcnow()
        session.revoked_reason = reason
        count += 1
    return count


def change_password(db: Session, user: User, current: str, new: str) -> None:
    if not verify_password(current, user.password_hash):
        raise Unauthorized("Current password is incorrect")
    try:
        validate_password_strength(new, email=user.email)
    except PasswordPolicyError as exc:
        raise ValidationFailure([{"field": "new_password", "message": v} for v in exc.violations]) from exc
    if verify_password(new, user.password_hash):
        raise ValidationFailure([{"field": "new_password", "message": "New password must differ from the current one"}])
    user.password_hash = hash_password(new)
    user.password_changed_at = utcnow()


def start_mfa_enrollment(db: Session, user: User) -> tuple[str, str]:
    secret = pyotp.random_base32()
    user.mfa_secret_encrypted = encrypt_secret(secret)
    user.mfa_enabled = False
    user.mfa_last_counter = None
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="HISPANSHIELD")
    return secret, uri


def activate_mfa(db: Session, user: User, code: str) -> None:
    if not user.mfa_secret_encrypted:
        raise ValidationFailure([{"field": "code", "message": "Start MFA enrollment first"}])
    if not verify_totp(user, code):
        raise Unauthorized("Invalid verification code")
    user.mfa_enabled = True


def disable_mfa(db: Session, user: User, password: str, code: str) -> None:
    if not verify_password(password, user.password_hash):
        raise Unauthorized("Password is incorrect")
    if not user.mfa_enabled or not verify_totp(user, code):
        raise Unauthorized("Invalid verification code")
    user.mfa_enabled = False
    user.mfa_secret_encrypted = None
    user.mfa_last_counter = None


def create_api_token(
    db: Session,
    *,
    user: User,
    org: Organization,
    name: str,
    scopes: list[str],
    expires_days: int | None,
    granted_permissions: list[str],
) -> tuple[ApiToken, str]:
    valid_permissions = {entry["key"] for entry in ALL_PERMISSIONS}
    invalid = [scope for scope in scopes if scope not in valid_permissions]
    if invalid:
        raise ValidationFailure([{"field": "scopes", "message": f"Unknown scope: {scope}"} for scope in invalid])
    if scopes:
        for scope in scopes:
            allowed = (
                scope in granted_permissions
                or "*" in granted_permissions
                or any(grant.endswith(":*") and scope.startswith(grant[:-1]) for grant in granted_permissions)
            )
            if not allowed:
                raise Forbidden(f"Cannot grant scope beyond your own permissions: {scope}")
    raw = "hs_" + generate_token(32)
    record = ApiToken(
        org_id=org.id,
        name=name,
        prefix=raw[:10],
        token_hash=token_hash(raw),
        scopes=scopes,
        created_by=user.id,
        expires_at=utcnow() + timedelta(days=expires_days) if expires_days else None,
    )
    db.add(record)
    db.flush()
    return record, raw


def serialize_session(db: Session, user: User, org: Organization, session: AuthSession, role: str) -> dict:
    orgs = user_organizations(db, user)
    if user.is_platform_admin and org.id not in {item[0].id for item in orgs}:
        # The selected organization is shown, but it is NOT a membership and
        # access remains governed by an active break-glass grant.
        orgs.append((org, "platform_admin"))
        orgs.sort(key=lambda item: item[0].name.lower())
    return {
        "user": {
            "id": user.id,
            "email": user.email,
            "full_name": user.full_name,
            "status": user.status,
            "is_platform_admin": user.is_platform_admin,
            "mfa_enabled": user.mfa_enabled,
            "locale": user.locale,
            "timezone": user.timezone,
            "last_login_at": user.last_login_at,
            "created_at": user.created_at,
        },
        "organization": {
            "id": org.id,
            "slug": org.slug,
            "name": org.name,
            "kind": org.kind,
            "is_demo": org.is_demo,
            "role": "platform_admin" if user.is_platform_admin else role,
        },
        "role": role,
        "permissions": effective_permissions(role),
        "organizations": [
            {
                "id": o.id,
                "slug": o.slug,
                "name": o.name,
                "kind": o.kind,
                "role": ("platform_admin" if user.is_platform_admin else r),
            }
            for o, r in orgs
        ],
        "csrf_token": session.csrf_token,
        "autonomy_level": org.autonomy_level,
        "expires_at": session.expires_at,
    }


def active_break_glass(db: Session, user_id: UUID, org_id: UUID) -> BreakGlassGrant | None:
    now = utcnow()
    return db.execute(
        select(BreakGlassGrant)
        .where(
            BreakGlassGrant.user_id == user_id,
            BreakGlassGrant.org_id == org_id,
            BreakGlassGrant.revoked_at.is_(None),
            BreakGlassGrant.expires_at > now,
        )
        .order_by(BreakGlassGrant.expires_at.desc())
        .limit(1)
    ).scalar_one_or_none()


def create_break_glass(
    db: Session, *, user: User, org: Organization, reason: str, ticket: str, request_id: str | None = None
) -> BreakGlassGrant:
    if not user.is_platform_admin:
        raise Forbidden("Break-glass access is reserved for platform administrators")
    cleaned = reason.strip()
    if len(cleaned) < 10:
        raise ValidationFailure(
            [{"field": "reason", "message": "A justification of at least 10 characters is required"}]
        )
    grant = BreakGlassGrant(
        user_id=user.id,
        org_id=org.id,
        reason=cleaned[:1000],
        ticket=ticket.strip()[:80],
        expires_at=utcnow() + timedelta(minutes=settings.break_glass_ttl_minutes),
    )
    db.add(grant)
    db.flush()
    append_audit(
        db,
        org_id=org.id,
        action="auth.break_glass.grant",
        resource_type="organization",
        resource_id=str(org.id),
        actor_id=str(user.id),
        actor_email=user.email,
        payload={
            "grant_id": str(grant.id),
            "reason": cleaned,
            "ticket": grant.ticket,
            "expires_at": grant.expires_at.isoformat(),
        },
        request_id=request_id,
    )
    return grant


def revoke_break_glass(db: Session, grant: BreakGlassGrant, *, actor: User) -> None:
    if grant.revoked_at is not None:
        return
    grant.revoked_at = utcnow()
    grant.revoked_by = actor.id
    append_audit(
        db,
        org_id=grant.org_id,
        action="auth.break_glass.revoke",
        resource_type="organization",
        resource_id=str(grant.org_id),
        actor_id=str(actor.id),
        actor_email=actor.email,
        payload={"grant_id": str(grant.id), "ticket": grant.ticket},
    )
