import re
import time
from typing import Dict
from backend.app.collectors.base import BaseCollector, CollectorResult, ExecutionContext, ObservationData


class SystemCollector(BaseCollector):
    name = "system"
    category = "system"
    description = "Inspects OS release, distribution, kernel version, hostname, and virtualization"

    async def collect(self, ctx: ExecutionContext) -> CollectorResult:
        start_time = time.monotonic()
        observations = []
        raw_evidence: Dict[str, str] = {}

        try:
            # 1. /etc/os-release
            os_release = await ctx.read_file("/etc/os-release")
            if os_release:
                raw_evidence["/etc/os-release"] = os_release
                id_match = re.search(r'^ID=["\']?([^"\'\n]+)', os_release, re.MULTILINE)
                version_id_match = re.search(r'^VERSION_ID=["\']?([^"\'\n]+)', os_release, re.MULTILINE)
                pretty_name_match = re.search(r'^PRETTY_NAME=["\']?([^"\'\n]+)', os_release, re.MULTILINE)

                distro_id = id_match.group(1).lower() if id_match else "unknown"
                version_id = version_id_match.group(1) if version_id_match else "unknown"
                pretty_name = pretty_name_match.group(1) if pretty_name_match else "Linux"

                observations.append(ObservationData(
                    category="system",
                    control="system.os_distribution",
                    value=distro_id,
                    source="/etc/os-release"
                ))
                observations.append(ObservationData(
                    category="system",
                    control="system.os_version",
                    value=version_id,
                    source="/etc/os-release"
                ))
                observations.append(ObservationData(
                    category="system",
                    control="system.os_pretty_name",
                    value=pretty_name,
                    source="/etc/os-release"
                ))

            # 2. Hostname
            hostname_content = await ctx.read_file("/etc/hostname")
            if hostname_content:
                raw_evidence["/etc/hostname"] = hostname_content
                observations.append(ObservationData(
                    category="system",
                    control="system.hostname",
                    value=hostname_content.strip(),
                    source="/etc/hostname"
                ))

            # 3. Kernel version via uname -a
            uname_res = await ctx.run_command("system.uname")
            if uname_res.get("stdout"):
                raw_evidence["uname"] = uname_res["stdout"].strip()
                tokens = uname_res["stdout"].strip().split()
                kernel_release = tokens[2] if len(tokens) > 2 else "unknown"
                arch = tokens[-1] if tokens else "unknown"

                observations.append(ObservationData(
                    category="system",
                    control="system.kernel_release",
                    value=kernel_release,
                    source="uname -a",
                    command_executed=uname_res.get("command")
                ))
                observations.append(ObservationData(
                    category="system",
                    control="system.architecture",
                    value=arch,
                    source="uname -a",
                    command_executed=uname_res.get("command")
                ))

            # 4. Machine ID
            machine_id = await ctx.read_file("/etc/machine-id")
            if machine_id:
                raw_evidence["/etc/machine-id"] = machine_id.strip()
                observations.append(ObservationData(
                    category="system",
                    control="system.machine_id",
                    value=machine_id.strip(),
                    source="/etc/machine-id"
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
                error_message=f"System collector failed: {str(e)}",
                duration_ms=(time.monotonic() - start_time) * 1000.0
            )
