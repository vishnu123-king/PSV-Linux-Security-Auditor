"""
PSV Linux Security Auditor - Network Target Validation and SSRF Protection

Hardening Requirements #25, #26:
- Prevent SSRF attacks against cloud metadata services (169.254.169.254, AWS/GCP/Azure).
- Block unauthorized localhost/loopback probing in production environments.
- Enforce strict hostname and IP validation, rejecting newlines, spaces, shell injection, or URL confusion.
"""

import ipaddress
import re
import socket
from typing import Optional, Tuple
from fastapi import HTTPException, status
from backend.app.core.config import get_settings

# Cloud metadata addresses to strictly block
CLOUD_METADATA_HOSTS = {
    "169.254.169.254",
    "metadata.google.internal",
    "169.254.169.250",
    "169.254.169.251",
    "169.254.169.253",
    "instance-data",
}

HOSTNAME_REGEX = re.compile(
    r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$"
)


class TargetValidationError(ValueError):
    """Raised when a remote host target fails security validation."""
    pass


def validate_network_target(
    hostname: str,
    port: int,
    allow_loopback: bool = False
) -> str:
    """
    Validates and normalizes target hostname or IP address.
    Raises TargetValidationError or HTTPException if unsafe.
    """
    settings = get_settings()
    is_prod = settings.APP_ENV.lower() == "production"

    # 1. Port range check
    if not (1 <= port <= 65535):
        raise TargetValidationError(f"Invalid port: {port}. Port must be between 1 and 65535.")

    cleaned_host = hostname.strip().lower()

    # 2. Reject shell injection or newline injection characters
    if any(char in cleaned_host for char in [";", "&", "|", "`", "$", " ", "\n", "\r", "\t", "<", ">", '"', "'", "\\"]):
        raise TargetValidationError(f"Target address contains illegal characters: '{hostname}'")

    # 3. Block known cloud metadata hostnames
    if cleaned_host in CLOUD_METADATA_HOSTS:
        raise TargetValidationError(f"Access to cloud metadata service '{cleaned_host}' is strictly prohibited.")

    # 4. Check if IP address
    try:
        ip = ipaddress.ip_address(cleaned_host)

        # Check loopback
        if ip.is_loopback:
            if is_prod and not allow_loopback:
                raise TargetValidationError("Loopback addresses (127.0.0.0/8, ::1) are prohibited in production.")

        # Check link-local / cloud metadata IP
        if ip.is_link_local or str(ip) in CLOUD_METADATA_HOSTS:
            raise TargetValidationError(f"Link-local and cloud metadata addresses are prohibited: {ip}")

        # Check multicast or unspecified
        if ip.is_multicast or ip.is_unspecified:
            raise TargetValidationError(f"Multicast and unspecified addresses are prohibited: {ip}")

        return str(ip)
    except ValueError:
        pass  # It's a hostname, not a raw IP address

    # 5. Validate RFC 1123 hostname format
    if len(cleaned_host) > 253 or not HOSTNAME_REGEX.match(cleaned_host):
        raise TargetValidationError(f"Invalid hostname format: '{hostname}'")

    return cleaned_host
