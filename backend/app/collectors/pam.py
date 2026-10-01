import re
import time
from typing import Any, Dict, List
from backend.app.collectors.base import BaseCollector, CollectorResult, ExecutionContext, ObservationData


class PAMCollector(BaseCollector):
    name = "pam"
    category = "pam"
    description = "Inspects Pluggable Authentication Modules (PAM) configuration and password quality policies"

    async def collect(self, ctx: ExecutionContext) -> CollectorResult:
        start_time = time.monotonic()
        observations: List[ObservationData] = []
        raw_evidence: Dict[str, Any] = {}

        try:
            # 1. /etc/security/pwquality.conf
            pwquality_content = await ctx.read_file("/etc/security/pwquality.conf")
            pw_minlen = 8
            pw_retry = 3
            pw_dcredit = 0
            pw_ucredit = 0
            pw_lcredit = 0
            pw_ocredit = 0

            if pwquality_content:
                raw_evidence["/etc/security/pwquality.conf"] = pwquality_content
                for line in pwquality_content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip().lower()
                        v = v.strip()
                        if k == "minlen" and v.lstrip("-").isdigit():
                            pw_minlen = int(v)
                        elif k == "retry" and v.lstrip("-").isdigit():
                            pw_retry = int(v)
                        elif k == "dcredit" and v.lstrip("-").isdigit():
                            pw_dcredit = int(v)
                        elif k == "ucredit" and v.lstrip("-").isdigit():
                            pw_ucredit = int(v)
                        elif k == "lcredit" and v.lstrip("-").isdigit():
                            pw_lcredit = int(v)
                        elif k == "ocredit" and v.lstrip("-").isdigit():
                            pw_ocredit = int(v)

            observations.append(ObservationData(
                category="pam",
                control="pam.password_minlen",
                value=pw_minlen,
                source="/etc/security/pwquality.conf"
            ))
            observations.append(ObservationData(
                category="pam",
                control="pam.password_complexity_enforced",
                value=(pw_dcredit < 0 and pw_ucredit < 0 and pw_lcredit < 0),
                source="/etc/security/pwquality.conf"
            ))

            # 2. Check faillock or tally2 in common-auth or system-auth
            common_auth = await ctx.read_file("/etc/pam.d/common-auth") or await ctx.read_file("/etc/pam.d/system-auth") or ""
            faillock_enabled = False
            lockout_deny = 5

            if common_auth:
                raw_evidence["pam_auth"] = common_auth
                if "pam_faillock.so" in common_auth or "pam_tally2.so" in common_auth:
                    faillock_enabled = True
                    match = re.search(r'deny=(\d+)', common_auth)
                    if match:
                        lockout_deny = int(match.group(1))

            observations.append(ObservationData(
                category="pam",
                control="pam.account_lockout_enabled",
                value=faillock_enabled,
                source="pam common-auth"
            ))
            observations.append(ObservationData(
                category="pam",
                control="pam.lockout_deny_attempts",
                value=lockout_deny,
                source="pam common-auth"
            ))

            # 3. Check password reuse restriction (pam_pwhistory) in common-password
            common_pw = await ctx.read_file("/etc/pam.d/common-password") or ""
            pwhistory_remember = 0
            if common_pw:
                raw_evidence["pam_password"] = common_pw
                match = re.search(r'remember=(\d+)', common_pw)
                if match:
                    pwhistory_remember = int(match.group(1))

            observations.append(ObservationData(
                category="pam",
                control="pam.password_history_remember",
                value=pwhistory_remember,
                source="pam common-password"
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
                error_message=f"PAM collector failed: {str(e)}",
                duration_ms=(time.monotonic() - start_time) * 1000.0
            )
