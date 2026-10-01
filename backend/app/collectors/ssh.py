import re
import time
from typing import Any, Dict, List
from backend.app.collectors.base import BaseCollector, CollectorResult, ExecutionContext, ObservationData


class SSHCollector(BaseCollector):
    name = "ssh"
    category = "ssh"
    description = "Parses OpenSSH daemon configuration (sshd_config) and verifies hardening parameters"

    async def collect(self, ctx: ExecutionContext) -> CollectorResult:
        start_time = time.monotonic()
        observations: List[ObservationData] = []
        raw_evidence: Dict[str, Any] = {}

        try:
            sshd_config = await ctx.read_file("/etc/ssh/sshd_config")
            if not sshd_config:
                return CollectorResult(
                    collector_name=self.name,
                    success=False,
                    error_message="/etc/ssh/sshd_config could not be read or does not exist",
                    duration_ms=(time.monotonic() - start_time) * 1000.0
                )

            raw_evidence["/etc/ssh/sshd_config"] = sshd_config

            # Parse sshd_config key-value pairs (case-insensitive keys, ignore commented lines)
            parsed_directives: Dict[str, str] = {}
            for line in sshd_config.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) >= 2:
                    key = parts[0].strip().lower()
                    val = parts[1].strip()
                    # Only record first occurrence as sshd obeys first match
                    if key not in parsed_directives:
                        parsed_directives[key] = val

            # Helper to map yes/no to boolean
            def to_bool(val: Optional[str], default: bool) -> bool:
                if val is None:
                    return default
                return val.lower() == "yes"

            # 1. PermitRootLogin
            permit_root = parsed_directives.get("permitrootlogin", "prohibit-password").lower()
            observations.append(ObservationData(
                category="ssh",
                control="ssh.permit_root_login",
                value=permit_root,
                source="/etc/ssh/sshd_config"
            ))

            # 2. PasswordAuthentication
            pw_auth = to_bool(parsed_directives.get("passwordauthentication"), default=True)
            observations.append(ObservationData(
                category="ssh",
                control="ssh.password_authentication",
                value=pw_auth,
                source="/etc/ssh/sshd_config"
            ))

            # 3. PermitEmptyPasswords
            empty_pw = to_bool(parsed_directives.get("permitemptypasswords"), default=False)
            observations.append(ObservationData(
                category="ssh",
                control="ssh.permit_empty_passwords",
                value=empty_pw,
                source="/etc/ssh/sshd_config"
            ))

            # 4. X11Forwarding
            x11_fwd = to_bool(parsed_directives.get("x11forwarding"), default=False)
            observations.append(ObservationData(
                category="ssh",
                control="ssh.x11_forwarding",
                value=x11_fwd,
                source="/etc/ssh/sshd_config"
            ))

            # 5. MaxAuthTries
            max_tries_val = parsed_directives.get("maxauthtries", "6")
            max_tries = int(max_tries_val) if max_tries_val.isdigit() else 6
            observations.append(ObservationData(
                category="ssh",
                control="ssh.max_auth_tries",
                value=max_tries,
                source="/etc/ssh/sshd_config"
            ))

            # 6. ClientAliveInterval
            interval_val = parsed_directives.get("clientaliveinterval", "0")
            client_interval = int(interval_val) if interval_val.isdigit() else 0
            observations.append(ObservationData(
                category="ssh",
                control="ssh.client_alive_interval",
                value=client_interval,
                source="/etc/ssh/sshd_config"
            ))

            # 7. ClientAliveCountMax
            alive_count_val = parsed_directives.get("clientalivecountmax", "3")
            alive_count = int(alive_count_val) if alive_count_val.isdigit() else 3
            observations.append(ObservationData(
                category="ssh",
                control="ssh.client_alive_count_max",
                value=alive_count,
                source="/etc/ssh/sshd_config"
            ))

            # 8. HostbasedAuthentication
            hostbased = to_bool(parsed_directives.get("hostbasedauthentication"), default=False)
            observations.append(ObservationData(
                category="ssh",
                control="ssh.hostbased_authentication",
                value=hostbased,
                source="/etc/ssh/sshd_config"
            ))

            # 9. IgnoreRhosts
            ignore_rhosts = to_bool(parsed_directives.get("ignorerhosts"), default=True)
            observations.append(ObservationData(
                category="ssh",
                control="ssh.ignore_rhosts",
                value=ignore_rhosts,
                source="/etc/ssh/sshd_config"
            ))

            # 10. LoginGraceTime
            grace_val = parsed_directives.get("logingracetime", "120")
            grace_time = int(grace_val) if grace_val.isdigit() else 120
            observations.append(ObservationData(
                category="ssh",
                control="ssh.login_grace_time",
                value=grace_time,
                source="/etc/ssh/sshd_config"
            ))

            # 11. AllowTcpForwarding
            tcp_fwd = parsed_directives.get("allowtcpforwarding", "yes").lower()
            observations.append(ObservationData(
                category="ssh",
                control="ssh.allow_tcp_forwarding",
                value=tcp_fwd,
                source="/etc/ssh/sshd_config"
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
                error_message=f"SSH collector failed: {str(e)}",
                duration_ms=(time.monotonic() - start_time) * 1000.0
            )
