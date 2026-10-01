import re
import time
from typing import Any, Dict, List
from backend.app.collectors.base import BaseCollector, CollectorResult, ExecutionContext, ObservationData


class NetworkingCollector(BaseCollector):
    name = "networking"
    category = "network"
    description = "Discovers listening TCP/UDP sockets and network stack hardening parameters"

    async def collect(self, ctx: ExecutionContext) -> CollectorResult:
        start_time = time.monotonic()
        observations: List[ObservationData] = []
        raw_evidence: Dict[str, Any] = {}

        try:
            # 1. ss listening ports
            ss_res = await ctx.run_command("network.ss_listening_ports")
            insecure_ports_detected = []
            listening_sockets = []

            insecure_port_map = {
                21: "FTP",
                23: "Telnet",
                69: "TFTP",
                512: "rexec",
                513: "rlogin",
                514: "rsh",
            }

            if ss_res.get("stdout"):
                raw_evidence["ss_tulpn"] = ss_res["stdout"]
                for line in ss_res["stdout"].splitlines():
                    if "LISTEN" in line or "UNCONN" in line:
                        listening_sockets.append(line.strip())
                        # Check port match
                        for port, svc in insecure_port_map.items():
                            if f":{port} " in line or f":{port}\t" in line or line.endswith(f":{port}"):
                                insecure_ports_detected.append(f"{svc} (port {port})")

            observations.append(ObservationData(
                category="network",
                control="network.insecure_ports_open",
                value=len(insecure_ports_detected) > 0,
                source="ss -tulpn"
            ))
            observations.append(ObservationData(
                category="network",
                control="network.insecure_services_found",
                value=insecure_ports_detected,
                source="ss -tulpn"
            ))
            observations.append(ObservationData(
                category="network",
                control="network.listening_socket_count",
                value=len(listening_sockets),
                source="ss -tulpn"
            ))

            # 2. Kernel network sysctls via sysctl.conf
            sysctl_content = await ctx.read_file("/etc/sysctl.conf") or ""
            raw_evidence["/etc/sysctl.conf"] = sysctl_content

            def get_sysctl_value(key: str, default: int = 0) -> int:
                matches = re.findall(rf'^\s*{re.escape(key)}\s*=\s*(\d+)', sysctl_content, re.MULTILINE)
                if matches:
                    return int(matches[-1])
                return default

            # IP Forwarding
            ip_fwd = get_sysctl_value("net.ipv4.ip_forward", 0)
            observations.append(ObservationData(
                category="network",
                control="network.ip_forwarding",
                value=ip_fwd == 1,
                source="/etc/sysctl.conf"
            ))

            # ICMP Redirects sending
            send_redirects = get_sysctl_value("net.ipv4.conf.all.send_redirects", 1)
            observations.append(ObservationData(
                category="network",
                control="network.send_redirects",
                value=send_redirects == 1,
                source="/etc/sysctl.conf"
            ))

            # ICMP Redirects accepting
            accept_redirects = get_sysctl_value("net.ipv4.conf.all.accept_redirects", 1)
            observations.append(ObservationData(
                category="network",
                control="network.accept_redirects",
                value=accept_redirects == 1,
                source="/etc/sysctl.conf"
            ))

            # Source routing
            accept_src = get_sysctl_value("net.ipv4.conf.all.accept_source_route", 0)
            observations.append(ObservationData(
                category="network",
                control="network.accept_source_route",
                value=accept_src == 1,
                source="/etc/sysctl.conf"
            ))

            # SYN cookies
            syn_cookies = get_sysctl_value("net.ipv4.tcp_syncookies", 1)
            observations.append(ObservationData(
                category="network",
                control="network.tcp_syncookies",
                value=syn_cookies == 1,
                source="/etc/sysctl.conf"
            ))

            # Reverse path filtering
            rp_filter = get_sysctl_value("net.ipv4.conf.all.rp_filter", 1)
            observations.append(ObservationData(
                category="network",
                control="network.rp_filter_enabled",
                value=rp_filter == 1,
                source="/etc/sysctl.conf"
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
                error_message=f"Networking collector failed: {str(e)}",
                duration_ms=(time.monotonic() - start_time) * 1000.0
            )
