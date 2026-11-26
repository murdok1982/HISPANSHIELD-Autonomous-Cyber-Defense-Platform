"""Application configuration loaded from environment variables (12-factor)."""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="HS_", env_file=(".env", "../.env"), extra="ignore")

    env: Literal["development", "test", "staging", "production"] = "development"
    debug: bool = False
    log_level: str = "INFO"
    app_name: str = "HISPANSHIELD"
    api_prefix: str = "/api/v1"

    database_url: str = "postgresql+psycopg://hispanshield@localhost:55432/hispanshield"
    db_echo: bool = False
    db_pool_size: int = 10
    db_max_overflow: int = 20

    secret_key: str = ""
    encryption_key: str = ""
    session_ttl_minutes: int = 720
    session_idle_minutes: int = 30
    break_glass_ttl_minutes: int = 30
    cookie_name: str = "hs_session"
    csrf_cookie_name: str = "hs_csrf"
    cookie_secure: bool = False
    cookie_domain: str | None = None
    allowed_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: str | None = None
    bootstrap_org_name: str = "HISPANSHIELD"
    # Optional shared secret required by POST /setup. Recommended (and set by
    # the Kubernetes template) so the first-run window is not open to the world.
    setup_token: str = ""

    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = 240
    login_rate_limit_per_minute: int = 10

    default_ollama_url: str = "http://127.0.0.1:11434"
    ai_request_timeout_seconds: int = 120
    ai_max_concurrency: int = 4
    ai_max_concurrency_per_org: int = 2
    # Per-organization AI governance. Zero means "blocked"; limits are enforced
    # before any outbound call so a tenant cannot exhaust shared GPU capacity.
    ai_daily_token_budget_per_org: int = 2_000_000
    ai_monthly_token_budget_per_org: int = 20_000_000
    ai_daily_request_budget_per_org: int = 5_000
    # External (non-local) inference is opt-in at platform and tenant level.
    ai_allow_external_providers: bool = False
    # Private destinations explicitly authorized for local inference servers.
    # Tenants cannot self-declare a "local" provider outside this allowlist.
    ai_private_allowed_cidrs: Annotated[list[str], NoDecode] = Field(default_factory=lambda: ["127.0.0.0/8", "::1/128"])

    connector_deny_cidrs: Annotated[list[str], NoDecode] = Field(default_factory=list)
    connector_allow_private_networks: bool = False

    metrics_token: str = ""
    seed_demo: bool = False
    public_url: str = "http://localhost:8080"
    support_email: str = "security@example.eu"

    # Audit integrity v3: HMAC-SHA256 with a key held outside PostgreSQL.
    # ``audit_hmac_previous_keys`` is a comma-separated list of
    # ``key_id:secret`` pairs kept only for verification during rotation.
    audit_hmac_key: str = ""
    audit_hmac_key_id: str = "k1"
    audit_hmac_previous_keys: str = ""
    audit_require_hmac: bool = False

    # Directory containing the built SPA (frontend/dist).
    frontend_dist: str = "frontend/dist"

    @field_validator("allowed_origins", "connector_deny_cidrs", "ai_private_allowed_cidrs", mode="before")
    @classmethod
    def _split_csv(cls, value: object) -> object:
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        return value

    @field_validator("secret_key")
    @classmethod
    def _validate_secret(cls, value: str) -> str:
        # Never generate a process-local key: sessions and challenge tokens would
        # silently become invalid on restart and production could run without a
        # deliberate secret. Fail fast instead.
        if not value or len(value) < 32:
            raise ValueError("HS_SECRET_KEY is required and must contain at least 32 characters")
        return value

    @property
    def is_production(self) -> bool:
        return self.env == "production"

    def validate_runtime(self) -> None:
        """Refuse unsafe production configuration instead of silently degrading."""
        if not self.is_production:
            return
        problems: list[str] = []
        if self.debug:
            problems.append("HS_DEBUG must be false in production")
        if not self.cookie_secure:
            problems.append("HS_COOKIE_SECURE must be true in production")
        if len(self.secret_key) < 32:
            problems.append("HS_SECRET_KEY must be at least 32 characters")
        if not self.encryption_key:
            problems.append("HS_ENCRYPTION_KEY is required in production")
        if not self.allowed_origins or "*" in self.allowed_origins:
            problems.append("HS_ALLOWED_ORIGINS must list explicit origins in production")
        if len(self.metrics_token) < 16:
            problems.append("HS_METRICS_TOKEN must be set in production")
        if self.seed_demo:
            problems.append("HS_SEED_DEMO must be false in production")
        if self.audit_require_hmac and len(self.audit_hmac_key) < 32:
            problems.append("HS_AUDIT_HMAC_KEY must be at least 32 characters when HMAC is required")
        for name, value in (
            ("HS_SECRET_KEY", self.secret_key),
            ("HS_ENCRYPTION_KEY", self.encryption_key),
            ("HS_AUDIT_HMAC_KEY", self.audit_hmac_key),
            ("HS_METRICS_TOKEN", self.metrics_token),
            ("HS_SETUP_TOKEN", self.setup_token),
        ):
            if value and ("CHANGE_ME" in value or "REPLACE_ME" in value):
                problems.append(f"{name} still contains a placeholder")
        if self.is_production and not self.audit_require_hmac:
            problems.append("HS_AUDIT_REQUIRE_HMAC must be true in production (audit chain must be keyed)")
        if problems:
            raise RuntimeError("Unsafe production configuration: " + "; ".join(problems))


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
