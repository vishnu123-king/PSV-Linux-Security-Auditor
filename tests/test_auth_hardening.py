"""
Tests for Authentication Hardening, Password Policy & Rate Limiting (Requirements #10, #12, #44)

Verifies:
- Strong password complexity requirements
- Brute-force failed login threshold and lockout
- Token revocation on logout
"""

import time
import pytest
from backend.app.core.security import (
    check_login_rate_limit,
    create_access_token,
    decode_token,
    is_token_revoked,
    record_failed_login,
    reset_failed_login,
    revoke_token,
    validate_password_strength,
)


def test_password_strength_validation():
    # Too short
    valid, _ = validate_password_strength("Short1!")
    assert valid is False

    # No uppercase
    valid, _ = validate_password_strength("weakpassword1!")
    assert valid is False

    # No number
    valid, _ = validate_password_strength("NoNumbersHere!")
    assert valid is False

    # No special char
    valid, _ = validate_password_strength("NoSpecialChar123")
    assert valid is False

    # Compliant
    valid, _ = validate_password_strength("P@ssw0rdSecure2026!")
    assert valid is True


def test_brute_force_rate_limiting_and_lockout():
    ident = "test-user-ip-127.0.0.1"
    reset_failed_login(ident)

    # 4 failed attempts should still be allowed
    for _ in range(4):
        record_failed_login(ident)
        allowed, retry_after = check_login_rate_limit(ident)
        assert allowed is True
        assert retry_after is None

    # 5th failed attempt triggers lockout
    record_failed_login(ident)
    allowed, retry_after = check_login_rate_limit(ident)
    assert allowed is False
    assert retry_after is not None
    assert retry_after > 0

    # Reset allows immediate login
    reset_failed_login(ident)
    allowed, _ = check_login_rate_limit(ident)
    assert allowed is True


def test_token_revocation():
    token = create_access_token(
        subject="user-123",
        role="ADMIN",
        org_id="org-1",
        token_id="jti-test-abc"
    )

    # Valid before revocation
    payload = decode_token(token)
    assert payload is not None
    assert payload["sub"] == "user-123"

    # Revoke JTI
    revoke_token("jti-test-abc")
    assert is_token_revoked("jti-test-abc") is True

    # Decoding revoked token returns None
    assert decode_token(token) is None
