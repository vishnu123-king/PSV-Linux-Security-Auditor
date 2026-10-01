import re
import time
from typing import Any, Dict, List
from backend.app.collectors.base import BaseCollector, CollectorResult, ExecutionContext, ObservationData


class SudoCollector(BaseCollector):
    name = "sudo"
    category = "sudo"
    description = "Parses sudoers configuration files, checks for NOPASSWD escalation and Defaults options"

    async def collect(self, ctx: ExecutionContext) -> CollectorResult:
        start_time = time.monotonic()
        observations: List[ObservationData] = []
        raw_evidence: Dict[str, Any] = {}

        try:
            sudoers_content = await ctx.read_file("/etc/sudoers")
            if not sudoers_content:
                return CollectorResult(
                    collector_name=self.name,
                    success=False,
                    error_message="Could not read /etc/sudoers",
                    duration_ms=(time.monotonic() - start_time) * 1000.0
                )

            raw_evidence["/etc/sudoers"] = sudoers_content

            has_use_pty = False
            has_env_reset = False
            has_secure_path = False
            has_logfile = False
            nopasswd_rules = []
            has_wildcard_nopasswd = False

            for line in sudoers_content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if line.startswith("Defaults"):
                    if "use_pty" in line:
                        has_use_pty = True
                    if "env_reset" in line:
                        has_env_reset = True
                    if "secure_path" in line:
                        has_secure_path = True
                    if "logfile=" in line:
                        has_logfile = True

                # Check for NOPASSWD directives
                if "NOPASSWD:" in line:
                    nopasswd_rules.append(line)
                    if "ALL" in line and "(ALL" in line:
                        has_wildcard_nopasswd = True

            observations.append(ObservationData(
                category="sudo",
                control="sudo.use_pty",
                value=has_use_pty,
                source="/etc/sudoers"
            ))
            observations.append(ObservationData(
                category="sudo",
                control="sudo.env_reset",
                value=has_env_reset,
                source="/etc/sudoers"
            ))
            observations.append(ObservationData(
                category="sudo",
                control="sudo.secure_path",
                value=has_secure_path,
                source="/etc/sudoers"
            ))
            observations.append(ObservationData(
                category="sudo",
                control="sudo.logfile_configured",
                value=has_logfile,
                source="/etc/sudoers"
            ))
            observations.append(ObservationData(
                category="sudo",
                control="sudo.has_wildcard_nopasswd",
                value=has_wildcard_nopasswd,
                source="/etc/sudoers"
            ))
            observations.append(ObservationData(
                category="sudo",
                control="sudo.nopasswd_rule_count",
                value=len(nopasswd_rules),
                source="/etc/sudoers"
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
                error_message=f"Sudo collector failed: {str(e)}",
                duration_ms=(time.monotonic() - start_time) * 1000.0
            )
