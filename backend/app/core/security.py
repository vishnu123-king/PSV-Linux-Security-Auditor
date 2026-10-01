"""
PSV Linux Security Auditor - Cryptographic Security & Authentication Primitives

Hardening Requirements #10, #12, #44:
- Secure bcrypt password hashing.
- Strong password complexity policy validator.
- JWT generation and decoding with expiration.
- In-memory token revocation blacklist.
- Brute-force rate limiting / account lockout tracking.
"""

from datetime import datetime, timedelta, timezone
import re
import time
from typing import Any, Dict, Optional, Set, Tuple, Union
from jose import JWTError, jwt
from passlib.context import CryptContext
from backend.app.core.config import get_settings

import bcrypt

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Revoked JWT IDs or user logout cutoffs
REVOKED_TOKENS: Set[str] = set()

# Login attempt rate limiting: {identifier: [(timestamp), ...]}
LOGIN_ATTEMPTS: Dict[str, list] = {}
LOCKOUT_THRESHOLD = 5
LOCKOUT_WINDOW_SECONDS = 300  # 5 minutes
LOCKOUT_DURATION_SECONDS = 900  # 15 minutes
LOCKOUT_UNTIL: Dict[str, float] = {}


def verify_password(plain_password: str, hashed_password: str) -> bool:
    if not plain_password or not hashed_password:
        return False
    try:
        password_bytes = plain_password.encode("utf-8")[:72]
        hashed_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(password_bytes, hashed_bytes)
    except Exception:
        try:
            return pwd_context.verify(plain_password[:72], hashed_password)
        except Exception:
            return False


def get_password_hash(password: str) -> str:
    try:
        password_bytes = password.encode("utf-8")[:72]
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password_bytes, salt).decode("utf-8")
    except Exception:
        return pwd_context.hash(password[:72])


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """
    Enforces strong password policy (Requirement #12):
    - Minimum 10 characters
    - At least 1 uppercase letter
    - At least 1 lowercase letter
    - At least 1 digit
    - At least 1 special character
    """
    if len(password) < 10:
        return False, "Password must be at least 10 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"[0-9]", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, "Password meets complexity standards."


def check_login_rate_limit(identifier: str) -> Tuple[bool, Optional[int]]:
    """
    Checks if account or IP is temporarily locked out due to excessive failed attempts.
    Returns (is_allowed, retry_after_seconds).
    """
    now = time.time()

    # Check active lockout
    if identifier in LOCKOUT_UNTIL:
        lock_expiry = LOCKOUT_UNTIL[identifier]
        if now < lock_expiry:
            return False, int(lock_expiry - now)
        else:
            del LOCKOUT_UNTIL[identifier]
            LOGIN_ATTEMPTS[identifier] = []

    # Clean old attempts
    attempts = LOGIN_ATTEMPTS.get(identifier, [])
    attempts = [t for t in attempts if now - t < LOCKOUT_WINDOW_SECONDS]
    LOGIN_ATTEMPTS[identifier] = attempts

    if len(attempts) >= LOCKOUT_THRESHOLD:
        LOCKOUT_UNTIL[identifier] = now + LOCKOUT_DURATION_SECONDS
        return False, LOCKOUT_DURATION_SECONDS

    return True, None


def record_failed_login(identifier: str) -> None:
    now = time.time()
    attempts = LOGIN_ATTEMPTS.get(identifier, [])
    attempts.append(now)
    LOGIN_ATTEMPTS[identifier] = attempts


def reset_failed_login(identifier: str) -> None:
    if identifier in LOGIN_ATTEMPTS:
        del LOGIN_ATTEMPTS[identifier]
    if identifier in LOCKOUT_UNTIL:
        del LOCKOUT_UNTIL[identifier]


def clear_login_lockouts() -> None:
    LOGIN_ATTEMPTS.clear()
    LOCKOUT_UNTIL.clear()


def create_access_token(
    subject: Union[str, Any],
    role: str,
    org_id: str,
    token_id: Optional[str] = None,
    expires_delta: Optional[timedelta] = None
) -> str:
    settings = get_settings()
    now_utc = datetime.now(timezone.utc)
    if expires_delta:
        expire = now_utc + expires_delta
    else:
        expire = now_utc + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    import uuid
    jti = token_id or str(uuid.uuid4())

    to_encode: Dict[str, Any] = {
        "exp": expire,
        "sub": str(subject),
        "role": role,
        "org_id": org_id,
        "jti": jti,
        "iat": now_utc
    }
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt


def revoke_token(jti: str) -> None:
    """Adds token JTI to the revocation blacklist."""
    REVOKED_TOKENS.add(jti)


def is_token_revoked(jti: str) -> bool:
    return jti in REVOKED_TOKENS


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        jti = payload.get("jti")
        if jti and is_token_revoked(jti):
            return None
        return payload
    except JWTError:
        return None
