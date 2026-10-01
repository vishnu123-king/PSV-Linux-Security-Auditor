import re
import time
from typing import Any, Dict, List
from backend.app.collectors.base import BaseCollector, CollectorResult, ExecutionContext, ObservationData


class IdentityCollector(BaseCollector):
    name = "identity"
    category = "identity"
    description = "Audits user accounts, UID 0 exclusivity, shadow password algorithms, and login.defs policies"

    async def collect(self, ctx: ExecutionContext) -> CollectorResult:
        start_time = time.monotonic()
        observations: List[ObservationData] = []
        raw_evidence: Dict[str, Any] = {}

        try:
            # 1. /etc/passwd parsing
            passwd_content = await ctx.read_file("/etc/passwd")
            if passwd_content:
                raw_evidence["/etc/passwd"] = passwd_content
                uid_zero_users = []
                non_root_interactive_users = []
                system_users_with_shell = []

                for line in passwd_content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) >= 7:
                        username, _, uid, gid, _, home, shell = parts[:7]
                        try:
                            uid_num = int(uid)
                        except ValueError:
                            continue

                        if uid_num == 0:
                            uid_zero_users.append(username)

                        # Check for non-standard shells on system users (< 1000)
                        valid_shells = ["/bin/bash", "/bin/sh", "/bin/zsh", "/bin/dash"]
                        invalid_system_shells = ["/bin/false", "/usr/sbin/nologin", "/sbin/nologin"]

                        if uid_num < 1000 and uid_num != 0:
                            if shell not in invalid_system_shells and any(shell.endswith(s.split("/")[-1]) for s in valid_shells):
                                system_users_with_shell.append(username)

                        if uid_num >= 1000 and shell not in invalid_system_shells:
                            non_root_interactive_users.append(username)

                observations.append(ObservationData(
                    category="identity",
                    control="identity.uid_zero_accounts",
                    value=uid_zero_users,
                    source="/etc/passwd"
                ))
                observations.append(ObservationData(
                    category="identity",
                    control="identity.single_uid_zero",
                    value=len(uid_zero_users) == 1 and uid_zero_users[0] == "root",
                    source="/etc/passwd"
                ))
                observations.append(ObservationData(
                    category="identity",
                    control="identity.system_users_with_interactive_shell",
                    value=system_users_with_shell,
                    source="/etc/passwd"
                ))
                observations.append(ObservationData(
                    category="identity",
                    control="identity.interactive_user_count",
                    value=len(non_root_interactive_users),
                    source="/etc/passwd"
                ))

            # 2. /etc/shadow (password algorithms & empty passwords)
            shadow_content = await ctx.read_file("/etc/shadow")
            if shadow_content:
                raw_evidence["/etc/shadow_status"] = "Read successfully"
                empty_password_accounts = []
                weak_hash_accounts = []

                for line in shadow_content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) >= 2:
                        user = parts[0]
                        pw_hash = parts[1]

                        if pw_hash == "":
                            empty_password_accounts.append(user)
                        elif not (pw_hash.startswith("!") or pw_hash.startswith("*")):
                            # Active password - verify hash prefix ($6$ for SHA512, $y$ for yescrypt, $7$ for scrypt)
                            if not (pw_hash.startswith("$6$") or pw_hash.startswith("$y$") or pw_hash.startswith("$7$")):
                                weak_hash_accounts.append(user)

                observations.append(ObservationData(
                    category="identity",
                    control="identity.empty_password_accounts",
                    value=empty_password_accounts,
                    source="/etc/shadow"
                ))
                observations.append(ObservationData(
                    category="identity",
                    control="identity.weak_hash_accounts",
                    value=weak_hash_accounts,
                    source="/etc/shadow"
                ))
            else:
                # /etc/shadow may require root or specific permissions
                observations.append(ObservationData(
                    category="identity",
                    control="identity.shadow_readable",
                    value=False,
                    source="/etc/shadow"
                ))

            # 3. /etc/login.defs
            login_defs = await ctx.read_file("/etc/login.defs")
            if login_defs:
                raw_evidence["/etc/login.defs"] = login_defs
                pass_max_days = None
                pass_min_days = None
                pass_warn_age = None
                encrypt_method = None

                for line in login_defs.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        key = parts[0].upper()
                        val = parts[1]
                        if key == "PASS_MAX_DAYS":
                            pass_max_days = int(val) if val.isdigit() else 99999
                        elif key == "PASS_MIN_DAYS":
                            pass_min_days = int(val) if val.isdigit() else 0
                        elif key == "PASS_WARN_AGE":
                            pass_warn_age = int(val) if val.isdigit() else 7
                        elif key == "ENCRYPT_METHOD":
                            encrypt_method = val.upper()

                observations.append(ObservationData(
                    category="identity",
                    control="identity.pass_max_days",
                    value=pass_max_days if pass_max_days is not None else 99999,
                    source="/etc/login.defs"
                ))
                observations.append(ObservationData(
                    category="identity",
                    control="identity.pass_min_days",
                    value=pass_min_days if pass_min_days is not None else 0,
                    source="/etc/login.defs"
                ))
                observations.append(ObservationData(
                    category="identity",
                    control="identity.pass_warn_age",
                    value=pass_warn_age if pass_warn_age is not None else 7,
                    source="/etc/login.defs"
                ))
                if encrypt_method:
                    observations.append(ObservationData(
                        category="identity",
                        control="identity.encrypt_method",
                        value=encrypt_method,
                        source="/etc/login.defs"
                    ))

            duration_ms = (time.monotonic() - start_time) * 1000.0
            return CollectorResult(
                collector_name=self.name,
                success=True,
                observations=observations,
                raw_evidence=raw_evidence,
                duration_ms=duration_ms
            )
        except Exception as e:
            return CollectorResult(
                collector_name=self.name,
                success=False,
                error_message=f"Identity collector failed: {str(e)}",
                duration_ms=(time.monotonic() - start_time) * 1000.0
            )
