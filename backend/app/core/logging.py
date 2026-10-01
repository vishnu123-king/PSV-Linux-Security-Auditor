"""
PSV Linux Security Auditor - Centralized Secret Redaction and Structured Logging

Hardening Requirements #10, #11, #58:
- Redact passwords, private keys, bearer tokens, API keys, session cookies, database credentials.
- Apply recursive redaction to dictionaries, lists, exception messages, audit metadata, and logs.
- Never crash on malformed input or missing regex capture groups.
"""

import logging
import re
import sys
from typing import Any, Dict, List, Union

# Regex patterns for sensitive credentials
PRIVATE_KEY_PATTERN = re.compile(
    r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----",
    re.DOTALL
)

BEARER_TOKEN_PATTERN = re.compile(
    r"(Bearer\s+)[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_=]*",
    re.IGNORECASE
)

KEY_VALUE_SECRET_PATTERN = re.compile(
    r'(password|token|secret|jwt|private_key|api_key|access_token|client_secret|authorization|passphrase)\s*[:=]\s*["\']?([^"\'\s,;]+)["\']?',
    re.IGNORECASE
)

CONNECTION_STRING_PATTERN = re.compile(
    r"://([^:]+):([^@]+)@",
    re.IGNORECASE
)

COOKIE_SECRET_PATTERN = re.compile(
    r'(session_id|token|auth)=([^;\s]+)',
    re.IGNORECASE
)


def redact_secrets(message: str) -> str:
    """Masks credentials, private keys, and authorization tokens in string output."""
    if not isinstance(message, str):
        message = str(message)

    # 1. Redact full private keys
    redacted = PRIVATE_KEY_PATTERN.sub("[REDACTED_PRIVATE_KEY]", message)

    # 2. Redact Bearer tokens
    redacted = BEARER_TOKEN_PATTERN.sub(r"\1[REDACTED_JWT_TOKEN]", redacted)

    # 3. Redact key-value pairs (e.g. password=..., secret: ...)
    redacted = KEY_VALUE_SECRET_PATTERN.sub(r"\1: [REDACTED]", redacted)

    # 4. Redact database credentials in connection strings
    redacted = CONNECTION_STRING_PATTERN.sub(r"://\1:[REDACTED]@", redacted)

    # 5. Redact cookie tokens
    redacted = COOKIE_SECRET_PATTERN.sub(r"\1=[REDACTED]", redacted)

    return redacted


def redact_data(data: Any) -> Any:
    """
    Recursively redacts sensitive keys and values in nested data structures (dicts, lists, strings).
    Safe for use on audit logs, evidence, and API responses.
    """
    SENSITIVE_KEYS = {
        "password",
        "secret",
        "private_key",
        "client_keys",
        "jwt_secret",
        "secret_key",
        "hashed_password",
        "token",
        "access_token",
        "encrypted_secret",
        "key_passphrase",
        "authorization",
        "cookie",
    }

    if isinstance(data, dict):
        cleaned: Dict[str, Any] = {}
        for k, v in data.items():
            if str(k).lower() in SENSITIVE_KEYS:
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = redact_data(v)
        return cleaned

    if isinstance(data, (list, tuple, set)):
        return [redact_data(item) for item in data]

    if isinstance(data, str):
        return redact_secrets(data)

    return data


class RedactingFormatter(logging.Formatter):
    """Logging formatter that automatically sanitizes all log outputs."""

    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        return redact_secrets(original)


def setup_logging(log_level: str = "INFO") -> None:
    """Sets up root logging with redaction filter and stdout stream handler."""
    root_logger = logging.getLogger()
    root_logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

    # Remove existing handlers to avoid duplicates
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    handler = logging.StreamHandler(sys.stdout)
    formatter = RedactingFormatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)

    # Silence overly verbose external loggers
    logging.getLogger("asyncssh").setLevel(logging.WARNING)
    logging.getLogger("aiosqlite").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.INFO)
