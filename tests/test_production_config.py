"""
Tests for Production Configuration Hardening & Environment Validation (Requirements #4, #83)

Verifies:
- Production configuration flags violations on SQLite, memory broker, debug mode, and default secrets
- Development mode allows local conveniences
"""

import pytest
from backend.app.core.config import Settings


def test_production_fails_on_insecure_defaults():
    prod_settings = Settings(
        APP_ENV="production",
        DEBUG=True,  # Violation
        DATABASE_URL="sqlite+aiosqlite:///./test.db",  # Violation
        RABBITMQ_URL="memory://",  # Violation
        SECRET_KEY="psv-linux-security-auditor-insecure-default-secret-key-32chars",  # Violation
        CORS_ORIGINS="*"  # Violation
    )
    violations = prod_settings.validate_production_settings()
    assert len(violations) >= 5
    assert any("DEBUG" in v for v in violations)
    assert any("PostgreSQL" in v for v in violations)
    assert any("RabbitMQ" in v for v in violations)
    assert any("SECRET_KEY" in v for v in violations)
    assert any("CORS" in v for v in violations)

    with pytest.raises(RuntimeError, match="FATAL: Production configuration violated security policy"):
        prod_settings.enforce_production_compliance()


def test_production_passes_on_hardened_settings():
    hardened_settings = Settings(
        APP_ENV="production",
        DEBUG=False,
        DATABASE_URL="postgresql+asyncpg://psv_user:ComplexProdPass99!@db.internal:5432/psv_prod",
        RABBITMQ_URL="amqps://psv_worker:ComplexRabbitPass99!@mq.internal:5671/psv",
        SECRET_KEY="c8f1e07b42d76a89ef23401589bcde34c8f1e07b42d76a89ef23401589bcde34",
        JWT_SECRET="a1b2c3d4e5f678901234567890123456a1b2c3d4e5f678901234567890123456",
        INITIAL_ADMIN_PASSWORD="ProdAdminSecret2026!#",
        CORS_ORIGINS="https://security.example.internal,https://soc.example.internal"
    )
    violations = hardened_settings.validate_production_settings()
    assert len(violations) == 0
