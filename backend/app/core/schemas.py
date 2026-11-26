"""Shared Pydantic contracts, pagination and input validation helpers."""

from __future__ import annotations

import base64
import binascii
import json
import re
from datetime import datetime
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

T = TypeVar("T")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SLUG_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{1,78}[a-z0-9])?$")

COMMON_PASSWORDS = {
    "password",
    "password123",
    "123456789012",
    "qwertyuiop12",
    "administrator",
    "hispanshield",
    "changeme123",
    "welcome12345",
    "letmein12345",
}


class StrictModel(BaseModel):
    """Input contract: reject unknown fields instead of silently ignoring them."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class PageMeta(BaseModel):
    total: int
    page: int
    page_size: int
    pages: int
    has_next: bool
    # Keyset pagination is additive: existing offset clients keep working.
    next_cursor: str | None = None
    total_estimate: int | None = None


class Page(BaseModel, Generic[T]):
    items: list[T]
    meta: PageMeta


class PaginationParams(StrictModel):
    page: int = Field(default=1, ge=1, le=100000)
    page_size: int = Field(default=25, ge=1, le=200)
    q: str | None = Field(default=None, max_length=200)
    sort: str | None = Field(default=None, max_length=60)
    order: str = Field(default="desc", pattern="^(asc|desc)$")


class MessageResponse(BaseModel):
    message: str
    detail: dict[str, Any] | None = None


class HealthResponse(BaseModel):
    status: str
    version: str
    database: str | None = None
    timestamp: datetime


def paginate(
    items: list[Any],
    total: int,
    page: int,
    page_size: int,
    *,
    next_cursor: str | None = None,
) -> dict[str, Any]:
    pages = (total + page_size - 1) // page_size if page_size else 0
    return {
        "items": items,
        "meta": {
            "total": total,
            "page": page,
            "page_size": page_size,
            "pages": pages,
            "has_next": page < pages,
            "next_cursor": next_cursor,
            "total_estimate": total,
        },
    }


def encode_cursor(payload: dict[str, Any]) -> str:
    """Opaque, bounded keyset cursor. It is not a security boundary."""
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    if len(raw) > 512:
        raise ValueError("Cursor payload is too large")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def decode_cursor(value: str) -> dict[str, Any]:
    if not value or len(value) > 700:
        raise ValueError("Invalid cursor")
    padded = value + "=" * (-len(value) % 4)
    try:
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
        payload = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, binascii.Error) as exc:
        raise ValueError("Invalid cursor") from exc
    if not isinstance(payload, dict):
        raise ValueError("Invalid cursor")
    return payload


def normalize_email(value: str) -> str:
    normalized = value.strip().lower()
    if not EMAIL_RE.match(normalized):
        raise ValueError("Invalid email address")
    return normalized


class PasswordPolicyError(ValueError):
    def __init__(self, violations: list[str]) -> None:
        super().__init__("; ".join(violations))
        self.violations = violations


def validate_password_strength(password: str, *, email: str | None = None) -> None:
    violations: list[str] = []
    if len(password) < 12:
        violations.append("Password must contain at least 12 characters")
    if len(password) > 128:
        violations.append("Password must not exceed 128 characters")
    classes = sum(
        [
            bool(re.search(r"[a-z]", password)),
            bool(re.search(r"[A-Z]", password)),
            bool(re.search(r"\d", password)),
            bool(re.search(r"[^A-Za-z0-9]", password)),
        ]
    )
    if classes < 3:
        violations.append("Password must combine at least three of: lowercase, uppercase, digits, symbols")
    if password.lower() in COMMON_PASSWORDS:
        violations.append("Password is too common")
    if email:
        local = email.split("@", 1)[0].lower()
        if local and local in password.lower():
            violations.append("Password must not contain the account name")
    if violations:
        raise PasswordPolicyError(violations)


class PasswordField(StrictModel):
    password: str = Field(min_length=1, max_length=128)

    @field_validator("password")
    @classmethod
    def _no_null_bytes(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("Password contains invalid characters")
        return value
