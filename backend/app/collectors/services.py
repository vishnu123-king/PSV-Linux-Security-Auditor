import time
from typing import Any, Dict, List
from backend.app.collectors.base import BaseCollector, CollectorResult, ExecutionContext, ObservationData


class ServicesCollector(BaseCollector):
    name = "services"
    category = "services"
    description = "Discovers running system services and verifies removal of legacy and insecure daemons"

    async def collect(self, ctx: ExecutionContext) -> CollectorResult:
        start_time = time.monotonic()
        observations: List[ObservationData] = []
        raw_evidence: Dict[str, Any] = {}

        try:
            # 1. systemctl list running units
            units_res = await ctx.run_command("services.systemctl_list_units")
            running_services = []

            insecure_services = [
                "telnet.service",
                "rsh.service",
                "rlogin.service",
                "tftp.service",
                "vsftpd.service",
                "inetd.service",
                "xinetd.service",
                "autofs.service",
                "avahi-daemon.service",
                "cups.service",
                "rpcbind.service",
                "nfs-server.service",
                "slapd.service",
                "bind9.service",
                "named.service"
            ]

            found_insecure_services = []

            if units_res.get("stdout"):
                raw_evidence["systemctl_services"] = units_res["stdout"]
                for line in units_res["stdout"].splitlines():
                    tokens = line.split()
                    if tokens:
                        svc_name = tokens[0]
                        running_services.append(svc_name)
                        for insec in insecure_services:
                            if svc_name == insec:
                                found_insecure_services.append(insec)

            observations.append(ObservationData(
                category="services",
                control="services.insecure_services_running",
                value=len(found_insecure_services) > 0,
                source="systemctl list-units"
            ))
            observations.append(ObservationData(
                category="services",
                control="services.insecure_services_list",
                value=found_insecure_services,
                source="systemctl list-units"
            ))
            observations.append(ObservationData(
                category="services",
                control="services.total_running_services",
                value=len(running_services),
                source="systemctl list-units"
            ))

            # 2. Time synchronization check
            chrony_res = await ctx.run_command("services.systemctl_status_chrony")
            timesyncd_res = await ctx.run_command("services.systemctl_status_systemd_timesyncd")

            chrony_active = chrony_res.get("stdout", "").strip() == "active"
            timesyncd_active = timesyncd_res.get("stdout", "").strip() == "active"
            time_sync_configured = chrony_active or timesyncd_active

            observations.append(ObservationData(
                category="services",
                control="services.time_synchronization_active",
                value=time_sync_configured,
                source="systemctl is-active chrony / systemd-timesyncd"
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
                error_message=f"Services collector failed: {str(e)}",
                duration_ms=(time.monotonic() - start_time) * 1000.0
            )
