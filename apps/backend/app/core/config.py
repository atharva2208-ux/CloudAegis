"""Application configuration, loaded from environment variables.

No secret has a usable production default: in ``production`` the app
refuses to start without ``SECRET_KEY`` and ``CREDENTIAL_ENCRYPTION_KEY``.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

INSECURE_DEV_SECRET = "dev-only-insecure-secret-change-me-0123456789abcdef"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    app_name: str = "CloudAegis"
    environment: Literal["development", "test", "production"] = "development"
    log_level: str = "INFO"
    log_json: bool = True

    database_url: str = "postgresql+psycopg2://cloudaegis:cloudaegis@localhost:5432/cloudaegis"
    redis_url: str | None = "redis://localhost:6379/0"

    secret_key: str = INSECURE_DEV_SECRET
    credential_encryption_key: str | None = None

    # Sessions
    session_cookie_name: str = "ca_session"
    csrf_cookie_name: str = "ca_csrf"
    session_absolute_minutes: int = 8 * 60
    session_idle_minutes: int = 30
    cookie_secure: bool = True
    cookie_domain: str | None = None

    # Abuse protection
    login_rate_limit_per_minute: int = 10
    api_rate_limit_per_minute: int = 600
    lockout_threshold: int = 5
    lockout_minutes: int = 15

    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173", "http://localhost:8080"])

    # Scanning
    scan_executor: Literal["inprocess", "rq"] = "inprocess"
    scan_workers: int = 2
    scan_timeout_seconds: int = 3600
    aws_default_region: str = "us-east-1"
    # Principal that audit roles should trust (shown in onboarding templates).
    platform_aws_principal_arn: str | None = None

    # Demo
    demo_mode: bool = True
    seed_admin_email: str = "admin@cloudaegis.local"
    seed_admin_password: str | None = None

    @field_validator("cors_origins", mode="before")
    @classmethod
    def _split_origins(cls, value):  # allow comma-separated env var
        if isinstance(value, str) and not value.startswith("["):
            return [v.strip() for v in value.split(",") if v.strip()]
        return value

    @model_validator(mode="after")
    def _production_guards(self) -> "Settings":
        if self.environment == "production":
            if self.secret_key == INSECURE_DEV_SECRET or len(self.secret_key) < 32:
                raise ValueError("SECRET_KEY must be set to a random value of at least 32 characters in production")
            if not self.credential_encryption_key:
                raise ValueError("CREDENTIAL_ENCRYPTION_KEY must be set in production")
            if not self.cookie_secure:
                raise ValueError("COOKIE_SECURE must be true in production")
        return self

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()
