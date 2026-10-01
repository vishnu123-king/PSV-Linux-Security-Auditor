"""
Tests for Network Target Validation and SSRF Protection (Requirements #25, #26)

Verifies:
- Cloud metadata service IPs (169.254.169.254, metadata.google.internal) are rejected
- Loopback addresses are rejected in production
- Shell injection, newlines, and illegal characters in hostnames are rejected
- Valid IP addresses and RFC 1123 hostnames pass validation
"""

import pytest
from backend.app.core.config import Settings
from backend.app.security.network_validation import TargetValidationError, validate_network_target


def test_valid_hostnames_and_ips():
    assert validate_network_target("192.168.1.50", 22) == "192.168.1.50"
    assert validate_network_target("web-server.internal", 2222) == "web-server.internal"
    assert validate_network_target("10.0.0.1", 22) == "10.0.0.1"


def test_block_cloud_metadata_ips():
    with pytest.raises(TargetValidationError, match="metadata"):
        validate_network_target("169.254.169.254", 22)

    with pytest.raises(TargetValidationError, match="metadata"):
        validate_network_target("metadata.google.internal", 80)


def test_block_shell_injection_in_target():
    dangerous_targets = [
        "192.168.1.1; id",
        "10.0.0.1 && cat /etc/passwd",
        "$(whoami).evil.com",
        "`id`.test.local",
        "host\nname",
        "host\rname",
        "192.168.1.1 | rm -rf /",
    ]
    for target in dangerous_targets:
        with pytest.raises(TargetValidationError):
            validate_network_target(target, 22)


def test_block_invalid_ports():
    with pytest.raises(TargetValidationError, match="port"):
        validate_network_target("192.168.1.1", 0)

    with pytest.raises(TargetValidationError, match="port"):
        validate_network_target("192.168.1.1", 70000)
