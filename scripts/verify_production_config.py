#!/usr/bin/env python3
"""
PSV Linux Security Auditor - Production Configuration Verification Script
Adheres to requirement #83.

Inspects environment and configuration files to ensure:
- Production is NOT using SQLite
- Production is NOT using in-memory queue fallback
- Production is NOT running with DEBUG=True
- Production does NOT have wildcard '*' CORS
- Production does NOT use default secret keys or passwords
Exits with code 0 on compliance, non-zero on violation.
"""

import os
import re
import sys
from pathlib import Path

# Add repo root to python path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

INSECURE_DEFAULT_SECRET = "psv-linux-security-auditor-insecure-default-secret-key-32chars"
INSECURE_DEFAULT_JWT = "psv-linux-security-auditor-jwt-secret-key-32chars"
INSECURE_DEFAULT_ADMIN_PASS = "AdminSecurePassword123!"


def load_env_file(filepath: Path) -> dict:
    env_vars = {}
    if not filepath.exists():
        return env_vars
    for line in filepath.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        env_vars[k.strip()] = v.strip().strip('"\'')
    return env_vars


def main() -> int:
    print("=" * 65)
    print("  PSV Linux Security Auditor - Production Configuration Audit")
    print("=" * 65)

    env_file = REPO_ROOT / ".env"
    file_vars = load_env_file(env_file)

    def get_var(key: str, default: str = "") -> str:
        return os.environ.get(key, file_vars.get(key, default))

    app_env = get_var("APP_ENV", "production")
    debug_str = get_var("DEBUG", "false").lower()
    db_url = get_var("DATABASE_URL", "sqlite+aiosqlite:///./psv_auditor.db")
    broker_url = get_var("RABBITMQ_URL", "memory://")
    secret_key = get_var("SECRET_KEY", INSECURE_DEFAULT_SECRET)
    jwt_secret = get_var("JWT_SECRET", INSECURE_DEFAULT_JWT)
    admin_pass = get_var("INITIAL_ADMIN_PASSWORD", INSECURE_DEFAULT_ADMIN_PASS)
    cors_str = get_var("CORS_ORIGINS", "http://localhost:3000")

    print(f"Target Environment: {app_env.upper()}")
    print(f"Database Target:    {db_url.split('://')[0]}://***")
    print(f"Broker Target:      {broker_url.split('://')[0]}://***")
    print(f"Debug Mode:         {debug_str}")
    print(f"CORS Origins:       {cors_str}")
    print("-" * 65)

    violations = []

    # 1. Debug
    if debug_str in ("true", "1", "yes"):
        violations.append("DEBUG must be set to False in production.")

    # 2. Database
    if not (db_url.startswith("postgresql+asyncpg://") or db_url.startswith("postgresql://") or db_url.startswith("postgres://")):
        violations.append(f"PostgreSQL is required in production (found '{db_url.split('://')[0]}'). SQLite fallback is prohibited.")

    # 3. RabbitMQ
    if not (broker_url.startswith("amqp://") or broker_url.startswith("amqps://")):
        violations.append(f"RabbitMQ (amqp:// or amqps://) is required in production (found '{broker_url.split('://')[0]}'). In-memory queue fallback is prohibited.")

    # 4. Secrets
    if secret_key in (INSECURE_DEFAULT_SECRET, "") or len(secret_key) < 32 or "replace-this" in secret_key:
        violations.append("SECRET_KEY must be configured with at least 32 cryptographically random characters.")

    if jwt_secret in (INSECURE_DEFAULT_JWT, "") or len(jwt_secret) < 32 or "replace-this" in jwt_secret:
        violations.append("JWT_SECRET must be configured with at least 32 cryptographically random characters.")

    # 5. Admin Pass
    if admin_pass in (INSECURE_DEFAULT_ADMIN_PASS, ""):
        violations.append("INITIAL_ADMIN_PASSWORD must not use default credentials in production.")

    # 6. CORS
    if "*" in cors_str:
        violations.append("Wildcard '*' CORS origin is strictly prohibited in production.")

    if violations:
        print("[!] PRODUCTION SECURITY POLICY VIOLATIONS DETECTED:")
        for v in violations:
            print(f"  [FAIL] {v}")
        print("-" * 65)
        print("[✖] Production configuration validation FAILED. Do not deploy.")
        return 1

    print("[✔] All production configuration checks PASSED. System ready for deployment.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
