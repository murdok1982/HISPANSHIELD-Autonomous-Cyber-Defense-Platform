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
    session_idle_minutes: int = 60
    break_glass_ttl_minutes: int = 30
    cookie_name: str = "hs_session"
    csrf_cookie_name: str = "hs_csrf"
    cookie_secure: bool = False
    cookie_domain: str | None = None
    allowed_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    bootstrap_admin_email: str | None = None
    bootstrap_admin_password: str | None = None
    bootstrap_org_name: str = "HISPANSHIELD"

    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = 240
    login_rate_limit_per_minute: int = 10

    default_ollama_url: str = "http://127.0.0.1:11434"
    ai_request_timeout_seconds: int = 120
    ai_max_concurrency: int = 4

    connector_deny_cidrs: Annotated[list[str], NoDecode] = Field(default_factory=list)
    connector_allow_private_networks: bool = False

    metrics_token: str = ""
    seed_demo: bool = False
    public_url: str = "http://localhost:8080"
    support_email: str = "security@example.eu"

    # Directory containing the built SPA (frontend/dist).
    frontend_dist: str = "frontend/dist"

    @field_validator("allowed_origins", "connector_deny_cidrs", mode="before")
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
        if problems:
            raise RuntimeError("Unsafe production configuration: " + "; ".join(problems))


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
