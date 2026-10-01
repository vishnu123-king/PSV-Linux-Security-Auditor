"""
PSV Linux Security Auditor - Application Configuration

Hardening Requirements #4, #9, #10, #31, #32, #83, #84:
- Strict separation of DEVELOPMENT, TEST, and PRODUCTION environments.
- Production MUST require PostgreSQL, RabbitMQ, strong secrets, and explicit CORS origins.
- Production startup MUST fail fast if configured insecurely (no silent fallback).
"""

from functools import lru_cache
import logging
from typing import List, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = logging.getLogger(__name__)

INSECURE_DEFAULT_SECRET = "psv-linux-security-auditor-insecure-default-secret-key-32chars"
INSECURE_DEFAULT_JWT = "psv-linux-security-auditor-jwt-secret-key-32chars"
INSECURE_DEFAULT_ADMIN_PASS = "AdminSecurePassword123!"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )

    APP_NAME: str = "PSV Linux Security Auditor"
    APP_VERSION: str = "1.0.0"
    APP_ENV: str = "development"  # Options: development, test, production
    DEBUG: bool = True
    PORT: int = 8000
    HOST: str = "0.0.0.0"

    SECRET_KEY: str = INSECURE_DEFAULT_SECRET
    JWT_SECRET: str = INSECURE_DEFAULT_JWT
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 480

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./psv_auditor.db"

    # RabbitMQ / Message Broker
    RABBITMQ_URL: str = "memory://"
    RABBITMQ_QUEUE_NAME: str = "psv.assessments"
    RABBITMQ_EXCHANGE_NAME: str = "psv.events"

    # Assessment & SSH limits
    MAX_CONCURRENT_ASSESSMENTS: int = 4
    SSH_CONNECT_TIMEOUT: int = 15
    SSH_COMMAND_TIMEOUT: int = 30
    SSH_MAX_OUTPUT_BYTES: int = 1048576  # 1MB cap per command
    SSH_STRICT_HOST_KEY_CHECKING: bool = True

    # Security & CORS
    CORS_ORIGINS: Union[str, List[str]] = "http://localhost:5173,http://localhost:3000,http://127.0.0.1:5173,http://127.0.0.1:3000"
    LOG_LEVEL: str = "INFO"

    # Request Body Size Limit (bytes)
    MAX_REQUEST_BODY_SIZE: int = 5242880  # 5MB

    # Default rules directory
    RULES_DIR: str = "./rules"

    # Initial Admin Seed
    INITIAL_ADMIN_EMAIL: str = "admin@psv.local"
    INITIAL_ADMIN_PASSWORD: str = INSECURE_DEFAULT_ADMIN_PASS

    @field_validator("CORS_ORIGINS", mode="after")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            return [i.strip() for i in v.split(",") if i.strip()]
        return v

    def validate_production_settings(self) -> List[str]:
        """
        Validates all production security invariants.
        Returns a list of violation errors. Empty list indicates compliant configuration.
        """
        errors = []

        if self.APP_ENV.lower() == "production":
            # 1. Debug mode prohibited in production
            if self.DEBUG:
                errors.append("Production violation: DEBUG must be set to False.")

            # 2. Database must be PostgreSQL
            if not (self.DATABASE_URL.startswith("postgresql+asyncpg://") or self.DATABASE_URL.startswith("postgresql://")):
                errors.append(
                    f"Production violation: PostgreSQL is required in production (found: '{self.DATABASE_URL.split('://')[0]}'). "
                    "SQLite fallback is strictly prohibited in production."
                )

            # 3. Message broker must be RabbitMQ (AMQP)
            if not (self.RABBITMQ_URL.startswith("amqp://") or self.RABBITMQ_URL.startswith("amqps://")):
                errors.append(
                    f"Production violation: RabbitMQ (amqp:// or amqps://) is required in production. "
                    "In-memory queue fallback ('memory://') is strictly prohibited in production."
                )

            # 4. Default or weak secrets prohibited
            if self.SECRET_KEY in (INSECURE_DEFAULT_SECRET, "") or len(self.SECRET_KEY) < 32:
                errors.append(
                    "Production violation: SECRET_KEY must be configured with at least 32 cryptographically random characters."
                )
            if self.JWT_SECRET in (INSECURE_DEFAULT_JWT, "") or len(self.JWT_SECRET) < 32:
                errors.append(
                    "Production violation: JWT_SECRET must be configured with at least 32 cryptographically random characters."
                )

            # 5. Default admin password prohibited
            if self.INITIAL_ADMIN_PASSWORD == INSECURE_DEFAULT_ADMIN_PASS:
                errors.append(
                    "Production violation: INITIAL_ADMIN_PASSWORD must not use default credentials in production."
                )

            # 6. Wildcard or insecure CORS prohibited
            cors_list = self.CORS_ORIGINS if isinstance(self.CORS_ORIGINS, list) else [self.CORS_ORIGINS]
            if "*" in cors_list:
                errors.append(
                    "Production violation: Wildcard '*' CORS origin is strictly prohibited in production."
                )

        return errors

    def enforce_production_compliance(self) -> None:
        """Fails startup immediately if production requirements are violated."""
        if self.APP_ENV.lower() == "production":
            errors = self.validate_production_settings()
            if errors:
                error_msg = "\n".join([f"  - {e}" for e in errors])
                logger.critical(f"FATAL: Production security configuration check failed:\n{error_msg}")
                raise RuntimeError(
                    f"FATAL: Production configuration violated security policy:\n{error_msg}\n"
                    "Refusing startup to prevent security downgrade."
                )


@lru_cache()
def get_settings() -> Settings:
    return Settings()
