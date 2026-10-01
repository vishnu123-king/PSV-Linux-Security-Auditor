"""
Tests for Centralized Secret Redaction Engine (Requirements #10, #11, #58)

Verifies:
- Private keys (RSA, OpenSSH, EC) are masked
- Bearer tokens are masked
- Passwords, secrets, and API keys are masked
- Database connection strings hide credentials
- Recursive dictionary and list redaction
- Robustness against missing regex groups or non-string types
"""

import pytest
from backend.app.core.logging import redact_data, redact_secrets


def test_redact_private_keys():
    sample_key = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Y3wZk2w9N...sample...key...content...
-----END RSA PRIVATE KEY-----"""
    msg = f"Imported SSH key:\n{sample_key}\nDone."
    redacted = redact_secrets(msg)
    assert "-----BEGIN RSA PRIVATE KEY-----" not in redacted
    assert "[REDACTED_PRIVATE_KEY]" in redacted


def test_redact_bearer_tokens():
    raw_token = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignature"
    msg = f"Request Header: Authorization: {raw_token}"
    redacted = redact_secrets(msg)
    assert "doNotLeakThisSignature" not in redacted
    assert "[REDACTED_JWT_TOKEN]" in redacted


def test_redact_passwords_and_secrets():
    msg = 'Config error: password="SuperSecretPassword123!" and api_key=secret-token-xyz'
    redacted = redact_secrets(msg)
    assert "SuperSecretPassword123!" not in redacted
    assert "secret-token-xyz" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_database_urls():
    db_url = "postgresql+asyncpg://psv_admin:P@ssw0rd123!@db-host.internal:5432/psv_auditor"
    redacted = redact_secrets(f"Connecting to {db_url}")
    assert "P@ssw0rd123!" not in redacted
    assert "psv_admin:[REDACTED]@db-host.internal" in redacted


def test_recursive_dict_redaction():
    data = {
        "host": "prod-web-01",
        "password": "ClearTextPassword",
        "nested": {
            "jwt_secret": "my-secret-key-32chars",
            "safe_val": 42,
            "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n-----END OPENSSH PRIVATE KEY-----",
            "items": ["safe_string", "token: abc123def456"]
        }
    }
    cleaned = redact_data(data)
    assert cleaned["password"] == "[REDACTED]"
    assert cleaned["nested"]["jwt_secret"] == "[REDACTED]"
    assert cleaned["nested"]["safe_val"] == 42
    assert "[REDACTED" in cleaned["nested"]["private_key"]
    assert "abc123def456" not in str(cleaned["nested"]["items"])
