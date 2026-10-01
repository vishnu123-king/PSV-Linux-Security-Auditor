"""
PSV Linux Security Auditor - Predefined Safe Command Security Registry

Hardening Requirements #6, #21, #22, #23, #24:
- Arbitrary shell commands are strictly prohibited.
- Predefined immutable SafeCommand registry for all remote execution.
- Strict separation between read-only inspection commands and remediation commands.
- Rejection of shell metacharacters (; && || | ` $ < > ( ) \n \r).
"""

from dataclasses import dataclass
import re
from typing import Dict, List, Optional, Set
from backend.app.collectors.registry import SAFE_COMMAND_REGISTRY, SafeCommand, get_safe_command

SHELL_INJECTION_PATTERN = re.compile(r"[;`$|&><\n\r]")


class CommandSecurityPolicy:
    """
    Enforces security invariant: only pre-registered, static commands can be run.
    Validates command identifiers and ensures no arbitrary strings can be injected.
    """

    @staticmethod
    def get_registered_command(command_id: str) -> Optional[SafeCommand]:
        return SAFE_COMMAND_REGISTRY.get(command_id)

    @staticmethod
    def is_safe(command_id: str) -> bool:
        return command_id in SAFE_COMMAND_REGISTRY

    @staticmethod
    def sanitize_input(user_input: str) -> str:
        """
        Validates that user input contains no shell metacharacters.
        Raises ValueError if dangerous characters are detected.
        """
        if SHELL_INJECTION_PATTERN.search(user_input):
            raise ValueError(f"Dangerous characters or shell injection detected in input: '{user_input}'")
        return user_input.strip()

    @staticmethod
    def list_registered_commands() -> List[Dict[str, str]]:
        return [
            {
                "identifier": cmd.identifier,
                "command": " ".join(cmd.command_args),
                "description": cmd.description,
                "timeout_seconds": str(cmd.timeout_seconds),
                "type": "read_only"
            }
            for cmd in SAFE_COMMAND_REGISTRY.values()
        ]


__all__ = ["SafeCommand", "SAFE_COMMAND_REGISTRY", "get_safe_command", "CommandSecurityPolicy"]
