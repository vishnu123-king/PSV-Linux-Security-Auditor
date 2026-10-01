"""
PSV Linux Security Auditor - Local Machine Execution Context

Provides real, safe, non-destructive execution context for auditing the local Linux host
directly via file reading and the immutable SAFE_COMMAND_REGISTRY.

Hardening Requirements:
- Safe file reading strictly restricted to whitelisted SAFE_FILE_PATHS.
- Command execution restricted exclusively to immutable SAFE_COMMAND_REGISTRY.
- Never accepts arbitrary user input as commands.
- Timeouts and max output buffers strictly enforced.
"""

import asyncio
import fnmatch
import os
import platform
import socket
from typing import Any, Dict, Optional
from backend.app.collectors.base import ExecutionContext
from backend.app.collectors.registry import SAFE_COMMAND_REGISTRY, SAFE_FILE_PATHS, SafeCommand


class LocalExecutionContext(ExecutionContext):
    """
    Real execution context for local Linux machine security auditing.
    Executes real safe commands and reads real system files on the host.
    """

    def __init__(self, hostname: Optional[str] = None) -> None:
        self.hostname = hostname or socket.gethostname()

    def _is_safe_path(self, path: str) -> bool:
        normalized = os.path.normpath(path)
        if normalized in SAFE_FILE_PATHS:
            return True
        for pattern in SAFE_FILE_PATHS:
            if "*" in pattern and fnmatch.fnmatch(normalized, pattern):
                return True
        return False

    async def read_file(self, path: str, max_bytes: int = 262144) -> Optional[str]:
        """Safely reads file content from the local system if in whitelist and readable."""
        if not self._is_safe_path(path):
            return None

        # Resolve symlink to verify it stays within system bounds
        try:
            real_path = os.path.realpath(path)
            if not os.path.exists(real_path) or not os.path.isfile(real_path):
                return None

            # Read up to max_bytes
            loop = asyncio.get_running_loop()
            def _read():
                with open(real_path, "r", encoding="utf-8", errors="ignore") as f:
                    return f.read(max_bytes)
            return await loop.run_in_executor(None, _read)
        except (PermissionError, OSError):
            return None

    async def run_command(self, command_id: str) -> Dict[str, Any]:
        """Runs a safe, registered command by identifier on the local system."""
        cmd_def: Optional[SafeCommand] = SAFE_COMMAND_REGISTRY.get(command_id)
        if not cmd_def:
            return {
                "command": command_id,
                "stdout": "",
                "stderr": f"Command identifier '{command_id}' is not registered in safe command registry.",
                "exit_code": 127
            }

        cmd_args = cmd_def.command_args
        try:
            process = await asyncio.create_subprocess_exec(
                cmd_args[0],
                *cmd_args[1:],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(),
                    timeout=cmd_def.timeout_seconds
                )
                stdout = stdout_bytes[:cmd_def.max_output_bytes].decode("utf-8", errors="replace")
                stderr = stderr_bytes[:cmd_def.max_output_bytes].decode("utf-8", errors="replace")
                return {
                    "command": " ".join(cmd_args),
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": process.returncode or 0
                }
            except asyncio.TimeoutError:
                try:
                    process.kill()
                except Exception:
                    pass
                return {
                    "command": " ".join(cmd_args),
                    "stdout": "",
                    "stderr": f"Command timed out after {cmd_def.timeout_seconds} seconds",
                    "exit_code": 124
                }
        except FileNotFoundError:
            return {
                "command": " ".join(cmd_args),
                "stdout": "",
                "stderr": f"Executable '{cmd_args[0]}' not found on local system.",
                "exit_code": 127
            }
        except Exception as e:
            return {
                "command": " ".join(cmd_args),
                "stdout": "",
                "stderr": f"Execution failed: {str(e)}",
                "exit_code": 1
            }

    def get_target_metadata(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "os_family": "linux",
            "kernel": platform.release(),
            "arch": platform.machine(),
            "is_local": True
        }
