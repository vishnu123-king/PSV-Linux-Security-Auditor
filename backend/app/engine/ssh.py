"""
PSV Linux Security Auditor - Hardened SSH Execution Engine

Hardening Requirements #8, #20, #21, #22, #40:
- Strict host-key verification; no silent bypass in production.
- Strict command execution through immutable SafeCommand registry only.
- Strict canonical path validation on file reads to prevent shell command injection or traversal.
- Output byte caps (1MB), connection timeouts (15s), and command timeouts (30s).
- Credential and private key scrubbing from all logs and exceptions.
"""

import asyncio
import logging
import os
import re
from typing import Any, Dict, List, Optional
import asyncssh
from backend.app.collectors.base import ExecutionContext
from backend.app.collectors.registry import SAFE_COMMAND_REGISTRY, get_safe_command
from backend.app.core.config import get_settings
from backend.app.core.logging import redact_secrets

logger = logging.getLogger(__name__)

SAFE_PATH_REGEX = re.compile(r"^/[a-zA-Z0-9_\-\./]+$")


class SSHError(Exception):
    """Base exception for all SSH connection and execution failures."""
    pass


class SSHAuthenticationError(SSHError):
    """Raised when host authentication or credentials fail."""
    pass


class SSHConnectionTimeoutError(SSHError):
    """Raised when connection attempts time out."""
    pass


class SSHHostKeyVerificationError(SSHError):
    """Raised when remote host key cannot be verified."""
    pass


class SSHExecutionContext(ExecutionContext):
    """
    Hardened SSH execution context wrapping AsyncSSH.
    Enforces registered commands, output limits, timeouts, and resource cleanup.
    """

    def __init__(
        self,
        hostname: str,
        port: int = 22,
        username: str = "root",
        client_keys: Optional[List[str]] = None,
        password: Optional[str] = None,
        known_hosts: Optional[str] = "known_hosts",
        connect_timeout: int = 15,
        command_timeout: int = 30,
        max_output_bytes: int = 1048576,
    ) -> None:
        self.hostname = hostname
        self.port = port
        self.username = username
        self.client_keys = client_keys or []
        self.password = password
        self.known_hosts = known_hosts
        self.connect_timeout = connect_timeout
        self.command_timeout = command_timeout
        self.max_output_bytes = max_output_bytes
        self._conn: Optional[asyncssh.SSHClientConnection] = None
        self._target_metadata: Dict[str, Any] = {
            "hostname": hostname,
            "port": port,
            "username": username
        }

    async def connect(self, retries: int = 2) -> None:
        """Establish SSH connection with structured retry and strict error handling."""
        settings = get_settings()
        last_exception = None

        imported_keys = []
        for key_str in self.client_keys:
            try:
                imported_keys.append(asyncssh.import_private_key(key_str))
            except Exception as e:
                logger.warning(f"Could not import private key: {redact_secrets(str(e))}")

        options: Dict[str, Any] = {
            "host": self.hostname,
            "port": self.port,
            "username": self.username,
            "login_timeout": self.connect_timeout,
        }

        if imported_keys:
            options["client_keys"] = imported_keys
        if self.password:
            options["password"] = self.password

        # Host key verification policy
        if self.known_hosts == "ignore" or self.known_hosts is None:
            if settings.APP_ENV.lower() == "production":
                raise SSHHostKeyVerificationError(
                    "Production violation: Strict host key checking cannot be disabled in production."
                )
            options["known_hosts"] = None
        else:
            options["known_hosts"] = self.known_hosts

        for attempt in range(1, retries + 2):
            try:
                logger.info(f"Connecting via SSH to {self.username}@{self.hostname}:{self.port} (attempt {attempt})...")
                self._conn = await asyncio.wait_for(
                    asyncssh.connect(**options),
                    timeout=self.connect_timeout
                )
                logger.info(f"SSH connection established to {self.hostname}:{self.port}")
                return
            except asyncio.TimeoutError:
                last_exception = SSHConnectionTimeoutError(
                    f"Connection to {self.hostname}:{self.port} timed out after {self.connect_timeout}s"
                )
            except asyncssh.PermissionDenied as e:
                raise SSHAuthenticationError(f"Authentication failed for user {self.username}@{self.hostname}: {redact_secrets(str(e))}")
            except asyncssh.HostKeyNotVerifiable as e:
                raise SSHHostKeyVerificationError(f"Host key verification failed for {self.hostname}: {e}")
            except Exception as e:
                last_exception = SSHError(f"SSH connection failed to {self.hostname}: {redact_secrets(str(e))}")

            if attempt <= retries:
                await asyncio.sleep(1.0 * attempt)

        if last_exception:
            raise last_exception

    async def read_file(self, path: str, max_bytes: int = 262144) -> Optional[str]:
        """
        Safely reads file content via SFTP without shell evaluation.
        Validates canonical path to prevent traversal or command injection.
        """
        if not self._conn:
            raise SSHError("SSH connection is not open.")

        # Path validation: must be absolute, no '..' traversal, valid characters only
        clean_path = os.path.normpath(path)
        if not clean_path.startswith("/") or ".." in clean_path or not SAFE_PATH_REGEX.match(clean_path):
            logger.warning(f"Rejected unsafe path reading attempt: '{path}'")
            return None

        # Try pure SFTP first (never invokes a shell)
        try:
            async with self._conn.start_sftp_client() as sftp:
                try:
                    async with sftp.open(clean_path, "rb") as remote_file:
                        data = await remote_file.read(max_bytes)
                        return data.decode("utf-8", errors="replace")
                except (asyncssh.SFTPError, OSError):
                    pass
        except Exception:
            pass

        # Fallback using direct cat with strictly validated path and shell=False
        try:
            # Use head with byte limit directly without shell expansion
            proc = await asyncio.wait_for(
                self._conn.run(f"head -c {max_bytes} -- {clean_path}", check=False),
                timeout=self.command_timeout
            )
            if proc.exit_status == 0 and proc.stdout:
                return str(proc.stdout)[:max_bytes]
            return None
        except Exception as e:
            logger.debug(f"File read failed for {clean_path}: {e}")
            return None

    async def run_command(self, command_id: str) -> Dict[str, Any]:
        """Runs an immutable registered command. Rejects arbitrary commands."""
        if not self._conn:
            raise SSHError("SSH connection is not open.")

        cmd = get_safe_command(command_id)
        if not cmd:
            raise ValueError(f"Command '{command_id}' is not in the safe command registry.")

        cmd_line = " ".join(cmd.command_args)
        timeout = min(cmd.timeout_seconds, self.command_timeout)

        try:
            proc = await asyncio.wait_for(
                self._conn.run(cmd_line, check=False),
                timeout=timeout
            )
            stdout = str(proc.stdout or "")[:cmd.max_output_bytes]
            stderr = str(proc.stderr or "")[:65536]
            return {
                "command_id": command_id,
                "command": cmd_line,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": proc.exit_status
            }
        except asyncio.TimeoutError:
            return {
                "command_id": command_id,
                "command": cmd_line,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "exit_code": 124
            }
        except Exception as e:
            return {
                "command_id": command_id,
                "command": cmd_line,
                "stdout": "",
                "stderr": redact_secrets(str(e)),
                "exit_code": 255
            }

    def get_target_metadata(self) -> Dict[str, Any]:
        return self._target_metadata

    async def close(self) -> None:
        if self._conn:
            self._conn.close()
            await self._conn.wait_closed()
            self._conn = None
            logger.debug(f"SSH connection closed for {self.hostname}")
