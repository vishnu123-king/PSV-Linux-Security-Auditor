import re
import time
from typing import Any, Dict, List
from backend.app.collectors.base import BaseCollector, CollectorResult, ExecutionContext, ObservationData


class LoggingCollector(BaseCollector):
    name = "logging"
    category = "logging"
    description = "Inspects Linux auditd framework, systemd-journald retention, and rsyslog logging"

    async def collect(self, ctx: ExecutionContext) -> CollectorResult:
        start_time = time.monotonic()
        observations: List[ObservationData] = []
        raw_evidence: Dict[str, Any] = {}

        try:
            # 1. auditctl status
            audit_res = await ctx.run_command("logging.auditctl_status")
            auditd_enabled = False

            if audit_res.get("stdout"):
                raw_evidence["auditctl_status"] = audit_res["stdout"]
                if "enabled 1" in audit_res["stdout"] or "enabled 2" in audit_res["stdout"]:
                    auditd_enabled = True

            observations.append(ObservationData(
                category="logging",
                control="logging.auditd_enabled",
                value=auditd_enabled,
                source="auditctl -s"
            ))

            # 2. audit rules count
            rules_res = await ctx.run_command("logging.auditctl_rules")
            rules_count = 0
            if rules_res.get("stdout"):
                raw_evidence["auditctl_rules"] = rules_res["stdout"]
                rules_lines = [l for l in rules_res["stdout"].splitlines() if l.strip() and not "No rules" in l]
                rules_count = len(rules_lines)

            observations.append(ObservationData(
                category="logging",
                control="logging.auditd_rules_configured",
                value=rules_count > 0,
                source="auditctl -l"
            ))
            observations.append(ObservationData(
                category="logging",
                control="logging.auditd_rules_count",
                value=rules_count,
                source="auditctl -l"
            ))

            # 3. /etc/audit/auditd.conf
            auditd_conf = await ctx.read_file("/etc/audit/auditd.conf")
            max_log_action = "ROTATE"
            space_left_action = "SYSLOG"

            if auditd_conf:
                raw_evidence["/etc/audit/auditd.conf"] = auditd_conf
                for line in auditd_conf.splitlines():
                    if "=" in line and not line.strip().startswith("#"):
                        k, v = line.split("=", 1)
                        k = k.strip().lower()
                        v = v.strip().upper()
                        if k == "max_log_file_action":
                            max_log_action = v
                        elif k == "space_left_action":
                            space_left_action = v

            observations.append(ObservationData(
                category="logging",
                control="logging.auditd_max_log_file_action",
                value=max_log_action,
                source="/etc/audit/auditd.conf"
            ))

            # 4. /etc/systemd/journald.conf
            journald_conf = await ctx.read_file("/etc/systemd/journald.conf")
            journal_persistent = False
            journal_compress = True

            if journald_conf:
                raw_evidence["/etc/systemd/journald.conf"] = journald_conf
                for line in journald_conf.splitlines():
                    if "=" in line and not line.strip().startswith("#"):
                        k, v = line.split("=", 1)
                        k = k.strip().lower()
                        v = v.strip().lower()
                        if k == "storage" and v == "persistent":
                            journal_persistent = True
                        if k == "compress" and v == "yes":
                            journal_compress = True

            observations.append(ObservationData(
                category="logging",
                control="logging.journald_storage_persistent",
                value=journal_persistent,
                source="/etc/systemd/journald.conf"
            ))

            # 5. Remote syslog check in /etc/rsyslog.conf
            rsyslog_conf = await ctx.read_file("/etc/rsyslog.conf") or ""
            has_remote_logging = False
            if rsyslog_conf:
                raw_evidence["/etc/rsyslog.conf"] = rsyslog_conf
                if re.search(r'^\s*[^#]*@', rsyslog_conf, re.MULTILINE):
                    has_remote_logging = True

            observations.append(ObservationData(
                category="logging",
                control="logging.remote_syslog_configured",
                value=has_remote_logging,
                source="/etc/rsyslog.conf"
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
                error_message=f"Logging collector failed: {str(e)}",
                duration_ms=(time.monotonic() - start_time) * 1000.0
            )
