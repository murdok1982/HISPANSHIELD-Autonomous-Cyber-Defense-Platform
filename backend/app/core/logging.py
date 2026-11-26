"""Structured JSON logging with request correlation IDs."""

from __future__ import annotations

import contextvars
import json
import logging
import sys
import time
from datetime import UTC, datetime
from typing import Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import settings

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
user_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("user_id", default="-")
org_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("org_id", default="-")


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
            "request_id": request_id_var.get(),
            "user_id": user_id_var.get(),
            "org_id": org_id_var.get(),
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict):
            payload.update(extra)
        return json.dumps(payload, default=str, ensure_ascii=False)


def configure_logging(level: str = "INFO") -> None:
    root = logging.getLogger()
    root.handlers.clear()
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    root.setLevel(level.upper())
    logging.getLogger("uvicorn.access").handlers.clear()
    logging.getLogger("uvicorn.access").propagate = False
    logging.getLogger("httpx").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


_SECRET_PATH_SEGMENTS = ("ingest",)


def _safe_log_path(path: str) -> str:
    """Redact credential-bearing path segments before they reach a log sink.

    `/ingest/<token>` keeps compatibility, but the token must never be written to
    application or exception logs; reverse proxies should use the header route.
    """
    parts = path.split("/")
    for index, part in enumerate(parts):
        if part in _SECRET_PATH_SEGMENTS and index + 1 < len(parts) and parts[index + 1]:
            parts[index + 1] = "<redacted>"
    return "/".join(parts)


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assign a request ID and emit one structured access log line per request."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        from uuid import uuid4

        incoming = request.headers.get("X-Request-ID", "")
        request_id = incoming[:64] if incoming and incoming.isprintable() else uuid4().hex
        token = request_id_var.set(request_id)
        request.state.request_id = request_id
        started = time.perf_counter()
        logger = get_logger("hispanshield.access")
        try:
            response: Response = await call_next(request)
        except Exception:
            logger.exception(
                "unhandled_request_error",
                extra={"extra_fields": {"method": request.method, "path": _safe_log_path(request.url.path)}},
            )
            raise
        finally:
            elapsed_ms = int((time.perf_counter() - started) * 1000)
        response.headers["X-Request-ID"] = request_id
        route = request.scope.get("route")
        path_template = getattr(route, "path", _safe_log_path(request.url.path))
        logger.info(
            "http_request",
            extra={
                "extra_fields": {
                    "method": request.method,
                    "path": path_template,
                    "status": response.status_code,
                    "duration_ms": elapsed_ms,
                    "client": request.client.host if request.client else None,
                }
            },
        )
        request_id_var.reset(token)
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        response: Response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault("X-Permitted-Cross-Domain-Policies", "none")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'",
        )
        if settings.is_production:
            response.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        if request.url.path.startswith("/api/"):
            response.headers.setdefault("Cache-Control", "no-store")
        return response


class _BodyTooLarge(Exception):
    """Retained for backwards compatibility with older middleware call sites."""


class BodySizeLimitMiddleware:
    """Bound request bodies even when the client omits or forges Content-Length.

    Requests with a declared length are rejected before the application runs.
    Requests without a length (chunked / HTTP2 streaming) are buffered with a
    hard ceiling and replayed to the application; an oversized body is answered
    with 413 without ever reaching the route handler. The previous header-only
    check let chunked uploads bypass the limit entirely (VULN-018).
    """

    def __init__(self, app, max_bytes: int = 30 * 1024 * 1024) -> None:  # type: ignore[no-untyped-def]
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):  # type: ignore[no-untyped-def]
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in (scope.get("headers") or [])}
        declared = headers.get(b"content-length")
        if declared is not None:
            if not declared.isdigit():
                await _send_error(send, 400, "invalid_content_length", "Malformed Content-Length header")
                return
            if int(declared) > self.max_bytes:
                await _send_payload_too_large(send, self.max_bytes)
                return
            await self.app(scope, receive, send)
            return

        if headers.get(b"transfer-encoding", b"").lower() == b"chunked" or scope.get("http_version") == "2":
            chunks: list[bytes] = []
            total = 0
            while True:
                message = await receive()
                if message.get("type") == "http.disconnect":
                    return
                chunk = message.get("body", b"")
                total += len(chunk)
                if total > self.max_bytes:
                    await _send_payload_too_large(send, self.max_bytes)
                    return
                chunks.append(chunk)
                if not message.get("more_body"):
                    break
            body = b"".join(chunks)
            replayed = False

            async def replay_receive():  # type: ignore[no-untyped-def]
                nonlocal replayed
                if replayed:
                    return {"type": "http.request", "body": b"", "more_body": False}
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}

            await self.app(scope, replay_receive, send)
            return

        await self.app(scope, receive, send)


async def _send_error(send, status_code: int, code: str, message: str) -> None:  # type: ignore[no-untyped-def]
    body = json.dumps({"error": {"code": code, "message": message}}).encode()
    await send(
        {
            "type": "http.response.start",
            "status": status_code,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
                (b"x-content-type-options", b"nosniff"),
                (b"cache-control", b"no-store"),
            ],
        }
    )
    await send({"type": "http.response.body", "body": body})


async def _send_payload_too_large(send, max_bytes: int) -> None:  # type: ignore[no-untyped-def]
    await _send_error(
        send,
        413,
        "payload_too_large",
        f"Request body exceeds the {max_bytes // (1024 * 1024)} MB limit",
    )
