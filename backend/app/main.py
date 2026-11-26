"""FastAPI application factory: middleware, error contracts, API and SPA hosting."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from sqlalchemy import text
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.router import api_router
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.errors import AppError
from app.core.logging import (
    BodySizeLimitMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
    configure_logging,
    get_logger,
)

VERSION = "0.1.3"
logger = get_logger("hispanshield")

REQUESTS = Counter("hs_http_requests_total", "HTTP requests", ["method", "path", "status"])
LATENCY = Histogram(
    "hs_http_request_duration_seconds",
    "HTTP request latency",
    ["method", "path"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10),
)


class OriginCheckMiddleware(BaseHTTPMiddleware):
    """Reject cross-origin state-changing requests (defence-in-depth with CSRF tokens)."""

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            site = request.headers.get("sec-fetch-site", "")
            origin = request.headers.get("origin")
            host = request.headers.get("host", "")
            allowed = set(settings.allowed_origins)
            if site == "cross-site" and origin not in allowed:
                return JSONResponse(
                    {"error": {"code": "cross_origin_denied", "message": "Cross-site request blocked"}},
                    status_code=403,
                )
            if origin and origin not in allowed:
                origin_host = origin.split("://", 1)[-1].strip("/")
                if origin_host != host:
                    return JSONResponse(
                        {"error": {"code": "cross_origin_denied", "message": "Origin is not allowed"}},
                        status_code=403,
                    )
        response = await call_next(request)
        return response


class MetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        started = time.perf_counter()
        response = await call_next(request)
        route = request.scope.get("route")
        path = getattr(route, "path", "unmatched")
        if path not in {"/metrics", "/healthz", "/readyz"}:
            REQUESTS.labels(request.method, path, str(response.status_code)).inc()
            LATENCY.labels(request.method, path).observe(time.perf_counter() - started)
        response.headers["Server"] = "HISPANSHIELD"
        return response


def _error_payload(request: Request, code: str, message: str, details: list | None = None) -> dict:
    payload: dict = {
        "error": {
            "code": code,
            "message": message,
            "request_id": getattr(request.state, "request_id", "-"),
        }
    }
    if details:
        payload["error"]["details"] = details
    return payload


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    configure_logging(settings.log_level)
    settings.validate_runtime()
    logger.info("application_start", extra={"extra_fields": {"env": settings.env, "version": VERSION}})
    yield
    logger.info("application_stop")


def create_app() -> FastAPI:
    app = FastAPI(
        title="HISPANSHIELD API",
        version=VERSION,
        description="Enterprise & Government AI-Driven Cyber Defence Platform",
        docs_url=None if settings.is_production else "/api/docs",
        redoc_url=None if settings.is_production else "/api/redoc",
        openapi_url=None if settings.is_production else "/api/openapi.json",
        lifespan=lifespan,
    )

    app.add_middleware(MetricsMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestContextMiddleware)
    app.add_middleware(OriginCheckMiddleware)
    if settings.allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=settings.allowed_origins,
            allow_credentials=True,
            allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
            allow_headers=["Content-Type", "X-CSRF-Token", "X-Organization-Id", "Authorization", "X-Request-ID"],
            expose_headers=["X-Request-ID", "Retry-After"],
            max_age=600,
        )

    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError) -> JSONResponse:
        response = JSONResponse(
            _error_payload(request, exc.code, exc.message, exc.details),
            status_code=exc.status_code,
            headers=exc.headers,
        )
        response.headers["X-Request-ID"] = getattr(request.state, "request_id", "-")
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        details = []
        for error in exc.errors():
            location = ".".join(str(part) for part in error.get("loc", []) if part not in ("body", "query", "path"))
            details.append({"field": location or "request", "message": error.get("msg", "Invalid value")})
        return JSONResponse(
            _error_payload(request, "validation_error", "Request validation failed", details),
            status_code=422,
        )

    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        detail = exc.detail if isinstance(exc.detail, str) else "Request failed"
        return JSONResponse(
            _error_payload(request, "http_error", detail),
            status_code=exc.status_code,
            headers=exc.headers or None,
        )

    @app.exception_handler(Exception)
    async def unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled_exception", extra={"extra_fields": {"path": request.url.path}})
        return JSONResponse(
            _error_payload(request, "internal_error", "Internal server error"),
            status_code=500,
        )

    app.include_router(api_router, prefix=settings.api_prefix)

    @app.get("/healthz", tags=["Operations"], include_in_schema=False)
    def liveness() -> dict:
        return {"status": "ok", "version": VERSION}

    @app.get("/readyz", tags=["Operations"], include_in_schema=False)
    def readiness() -> JSONResponse:
        try:
            with SessionLocal() as db:
                db.execute(text("SELECT 1"))
                current = db.execute(text("SELECT version_num FROM alembic_version")).scalar()
                queue_depth = db.execute(
                    text("SELECT count(*) FROM playbook_executions WHERE status IN ('pending', 'running', 'waiting')")
                ).scalar_one()
                outbox_pending = db.execute(
                    text("SELECT count(*) FROM outbox_events WHERE status IN ('pending', 'processing')")
                ).scalar_one()
                outbox_dead = db.execute(
                    text("SELECT count(*) FROM outbox_events WHERE status = 'dead_letter'")
                ).scalar_one()
            head = _migration_head()
            up_to_date = bool(head) and current == head
            body = {
                "status": "ready" if up_to_date else "degraded",
                "version": VERSION,
                "database": "ok",
                "migrations": {"current": current, "head": head, "up_to_date": up_to_date},
                "queue_depth": int(queue_depth or 0),
                "outbox": {"pending": int(outbox_pending or 0), "dead_letter": int(outbox_dead or 0)},
            }
            return JSONResponse(body, status_code=200 if up_to_date else 503)
        except Exception as exc:  # pragma: no cover - exercised only during outages
            logger.error("readiness_failed", extra={"extra_fields": {"error": str(exc)}})
            return JSONResponse({"status": "unavailable", "reason": "database"}, status_code=503)

    @app.get("/metrics", tags=["Operations"], include_in_schema=False)
    def metrics(request: Request) -> PlainTextResponse:
        token = settings.metrics_token
        provided = ""
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            provided = auth[7:].strip()
        if (settings.is_production or token) and (not token or provided != token):
            return PlainTextResponse("Forbidden", status_code=403)
        return PlainTextResponse(generate_latest().decode(), media_type=CONTENT_TYPE_LATEST)

    _mount_spa(app)
    return app


def _mount_spa(app: FastAPI) -> None:
    dist = Path(settings.frontend_dist)
    if not dist.is_absolute():
        dist = (Path(__file__).resolve().parents[2] / settings.frontend_dist).resolve()
    index = dist / "index.html"
    if not index.exists():

        @app.get("/", include_in_schema=False)
        def api_root() -> dict:
            return {"name": "HISPANSHIELD", "version": VERSION, "docs": "/api/docs", "frontend": "not built"}

        return

    from fastapi.staticfiles import StaticFiles

    assets = dist / "static"
    if assets.exists():
        app.mount("/static", StaticFiles(directory=assets), name="assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    def spa_fallback(full_path: str):
        if full_path.startswith(("api/", "healthz", "readyz", "metrics")):
            return JSONResponse(_error_payload_static("not_found", "Not found"), status_code=404)
        candidate = (dist / full_path).resolve()
        if full_path and candidate.is_file() and candidate.is_relative_to(dist.resolve()):
            return FileResponse(candidate)
        return FileResponse(index, headers={"Cache-Control": "no-cache"})


def _error_payload_static(code: str, message: str) -> dict:
    return {"error": {"code": code, "message": message}}


def _migration_head() -> str | None:
    """Return the latest Alembic revision without touching the database."""
    try:
        from alembic.config import Config
        from alembic.script import ScriptDirectory

        backend_dir = Path(__file__).resolve().parents[1]
        config = Config(str(backend_dir / "alembic.ini"))
        config.set_main_option("script_location", str(backend_dir / "migrations"))
        return ScriptDirectory.from_config(config).get_current_head()
    except Exception:  # pragma: no cover - missing config in exotic deployments
        return None


app = BodySizeLimitMiddleware(create_app(), max_bytes=30 * 1024 * 1024)
