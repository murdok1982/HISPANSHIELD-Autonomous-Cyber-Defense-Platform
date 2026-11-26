"""Test fixtures: isolated PostgreSQL schema built from Alembic migrations."""

from __future__ import annotations

import os
from contextlib import contextmanager
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parents[1]

os.environ.setdefault("HS_ENV", "test")
os.environ.setdefault("HS_DATABASE_URL", "postgresql+psycopg://hispanshield@localhost:55432/hispanshield_test")
os.environ.setdefault("HS_SECRET_KEY", "test-secret-key-0123456789-abcdefghijklmnopqrstuvwxyz")
os.environ.setdefault("HS_ENCRYPTION_KEY", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
os.environ.setdefault("HS_RATE_LIMIT_ENABLED", "false")
os.environ.setdefault("HS_COOKIE_SECURE", "false")
os.environ.setdefault("HS_ALLOWED_ORIGINS", "http://testserver")
os.environ.setdefault("HS_SEED_DEMO", "false")
os.environ.setdefault("HS_FRONTEND_DIST", "/nonexistent-dist")

import pytest  # noqa: E402
from alembic import command  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from app.core.db import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.services.bootstrap import bootstrap_admin  # noqa: E402

ADMIN_EMAIL = "admin@hispanshield.eu"
ADMIN_PASSWORD = "Str0ng-Test-Passw0rd!2026"


@pytest.fixture(scope="session", autouse=True)
def migrate_database():
    config = Config(str(BASE_DIR / "alembic.ini"))
    config.set_main_option("script_location", str(BASE_DIR / "migrations"))
    config.set_main_option("sqlalchemy.url", os.environ["HS_DATABASE_URL"].replace("%", "%%"))
    command.upgrade(config, "head")
    yield


@pytest.fixture(autouse=True)
def clean_database(migrate_database):
    with engine.begin() as connection:
        tables = (
            connection.execute(
                text("SELECT tablename FROM pg_tables WHERE schemaname='public' AND tablename != 'alembic_version'")
            )
            .scalars()
            .all()
        )
        # The audit trail is append-only (UPDATE/DELETE/TRUNCATE triggers).
        # Test isolation may temporarily disable those guards as schema owner.
        has_audit = "audit_records" in tables
        if has_audit:
            connection.execute(text("ALTER TABLE audit_records DISABLE TRIGGER audit_records_append_only"))
            connection.execute(text("ALTER TABLE audit_records DISABLE TRIGGER audit_records_no_truncate"))
        try:
            if tables:
                joined = ", ".join(f'"{table}"' for table in tables)
                connection.execute(text(f"TRUNCATE {joined} RESTART IDENTITY CASCADE"))
        finally:
            if has_audit:
                connection.execute(text("ALTER TABLE audit_records ENABLE TRIGGER audit_records_append_only"))
                connection.execute(text("ALTER TABLE audit_records ENABLE TRIGGER audit_records_no_truncate"))
    yield


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def seeded(db):
    user, org, _ = bootstrap_admin(
        db,
        email=ADMIN_EMAIL,
        password=ADMIN_PASSWORD,
        org_name="HISPANSHIELD Test Organisation",
        org_slug="test-org",
    )
    return {"user": user, "org": org}


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def login(client: TestClient, email: str = ADMIN_EMAIL, password: str = ADMIN_PASSWORD) -> TestClient:
    response = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    assert "mfa_required" not in response.json()
    csrf = client.cookies.get("hs_csrf")
    assert csrf
    client.headers.update({"X-CSRF-Token": csrf})
    return client


@pytest.fixture
def auth_client(seeded, client):
    return login(client)


@pytest.fixture
def org_id(seeded):
    return str(seeded["org"].id)


@contextmanager
def break_glass(client: TestClient, org_id):
    """Temporarily exercise platform-admin break-glass for test setup.

    The grant is revoked and the active-org header restored on exit, so the
    test's isolation assertions execute without a residual cross-tenant grant.
    """
    response = client.post(
        "/api/v1/auth/break-glass",
        json={
            "org_id": str(org_id),
            "reason": "Automated test fixture for cross-tenant setup",
            "ticket": "TEST-ISOLATION-001",
        },
    )
    assert response.status_code == 200, response.text
    grant_id = response.json()["grant_id"]
    previous = client.headers.get("X-Organization-Id")
    client.headers["X-Organization-Id"] = str(org_id)
    try:
        yield grant_id
    finally:
        if previous:
            client.headers["X-Organization-Id"] = previous
        else:
            client.headers.pop("X-Organization-Id", None)
        revoke = client.post(f"/api/v1/auth/break-glass/{grant_id}/revoke")
        assert revoke.status_code == 200, revoke.text
