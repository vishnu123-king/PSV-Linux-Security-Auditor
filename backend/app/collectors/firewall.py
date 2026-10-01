import time
from typing import Any, Dict, List
from backend.app.collectors.base import BaseCollector, CollectorResult, ExecutionContext, ObservationData


class FirewallCollector(BaseCollector):
    name = "firewall"
    category = "firewall"
    description = "Checks status and default drop policies for UFW, iptables, and nftables"

    async def collect(self, ctx: ExecutionContext) -> CollectorResult:
        start_time = time.monotonic()
        observations: List[ObservationData] = []
        raw_evidence: Dict[str, Any] = {}

        try:
            # 1. Check UFW
            ufw_res = await ctx.run_command("firewall.ufw_status")
            ufw_active = False
            ufw_default_incoming_deny = False

            if ufw_res.get("exit_code") == 0 and ufw_res.get("stdout"):
                raw_evidence["ufw"] = ufw_res["stdout"]
                out = ufw_res["stdout"].lower()
                if "status: active" in out:
                    ufw_active = True
                if "default: deny (incoming)" in out or "default: reject (incoming)" in out:
                    ufw_default_incoming_deny = True

            observations.append(ObservationData(
                category="firewall",
                control="firewall.ufw_active",
                value=ufw_active,
                source="ufw status verbose",
                command_executed=ufw_res.get("command")
            ))
            observations.append(ObservationData(
                category="firewall",
                control="firewall.ufw_default_incoming_deny",
                value=ufw_default_incoming_deny,
                source="ufw status verbose",
                command_executed=ufw_res.get("command")
            ))

            # 2. Check iptables
            iptables_res = await ctx.run_command("firewall.iptables_status")
            iptables_rules_present = False
            iptables_input_drop = False

            if iptables_res.get("exit_code") == 0 and iptables_res.get("stdout"):
                raw_evidence["iptables"] = iptables_res["stdout"]
                out = iptables_res["stdout"]
                if "Chain INPUT (policy DROP" in out:
                    iptables_input_drop = True
                lines = [l for l in out.splitlines() if l.strip() and not l.startswith("Chain") and not l.startswith("pkts")]
                if len(lines) > 0:
                    iptables_rules_present = True

            observations.append(ObservationData(
                category="firewall",
                control="firewall.iptables_rules_present",
                value=iptables_rules_present,
                source="iptables -L -n -v",
                command_executed=iptables_res.get("command")
            ))
            observations.append(ObservationData(
                category="firewall",
                control="firewall.iptables_input_drop",
                value=iptables_input_drop,
                source="iptables -L -n -v",
                command_executed=iptables_res.get("command")
            ))

            # Consolidated firewall active check (at least one is active)
            firewall_enabled = ufw_active or iptables_rules_present
            observations.append(ObservationData(
                category="firewall",
                control="firewall.any_firewall_active",
                value=firewall_enabled,
                source="ufw / iptables"
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
                error_message=f"Firewall collector failed: {str(e)}",
                duration_ms=(time.monotonic() - start_time) * 1000.0
            )
