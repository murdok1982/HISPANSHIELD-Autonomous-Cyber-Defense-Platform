"""Typed application errors and RFC-7807-inspired API error envelope."""

from __future__ import annotations

from typing import Any


class AppError(Exception):
    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 400,
        details: list[dict[str, Any]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details or []
        self.headers = headers or {}


class NotFound(AppError):
    def __init__(self, resource: str = "Resource") -> None:
        super().__init__("not_found", f"{resource} not found", 404)


class Forbidden(AppError):
    def __init__(self, message: str = "Insufficient permissions for this operation") -> None:
        super().__init__("forbidden", message, 403)


class Unauthorized(AppError):
    def __init__(self, message: str = "Authentication required") -> None:
        super().__init__("unauthorized", message, 401, headers={"WWW-Authenticate": "Session"})


class Conflict(AppError):
    def __init__(
        self,
        message: str,
        code: str = "conflict",
        details: list[dict[str, Any]] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(code, message, 409, details=details, headers=headers)


class ValidationFailure(AppError):
    def __init__(self, details: list[dict[str, Any]], message: str = "Request validation failed") -> None:
        super().__init__("validation_error", message, 422, details=details)


class RateLimited(AppError):
    def __init__(self, retry_after: int) -> None:
        super().__init__(
            "rate_limited",
            "Too many requests. Retry later.",
            429,
            headers={"Retry-After": str(max(1, retry_after))},
        )


class ServiceUnavailable(AppError):
    def __init__(self, message: str, code: str = "service_unavailable") -> None:
        super().__init__(code, message, 503)


class PolicyDenied(AppError):
    def __init__(self, reason: str, code: str = "policy_denied", details: list[dict[str, Any]] | None = None) -> None:
        super().__init__(code, reason, 403, details=details)
