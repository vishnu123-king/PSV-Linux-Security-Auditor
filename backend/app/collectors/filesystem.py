import time
from typing import Any, Dict, List
from backend.app.collectors.base import BaseCollector, CollectorResult, ExecutionContext, ObservationData


class FilesystemCollector(BaseCollector):
    name = "filesystem"
    category = "filesystem"
    description = "Checks mount options (noexec, nosuid, nodev), core dump limits, and world-writable files"

    async def collect(self, ctx: ExecutionContext) -> CollectorResult:
        start_time = time.monotonic()
        observations: List[ObservationData] = []
        raw_evidence: Dict[str, Any] = {}

        try:
            # 1. Mount options inspection
            mount_res = await ctx.run_command("filesystem.df_mounts")
            tmp_options = []
            shm_options = []
            var_tmp_options = []

            if mount_res.get("stdout"):
                raw_evidence["mount"] = mount_res["stdout"]
                for line in mount_res["stdout"].splitlines():
                    parts = line.split()
                    if len(parts) >= 6 and parts[2] == "/tmp":
                        opts = parts[5].strip("()").split(",")
                        tmp_options = [o.strip() for o in opts]
                    elif len(parts) >= 6 and parts[2] == "/dev/shm":
                        opts = parts[5].strip("()").split(",")
                        shm_options = [o.strip() for o in opts]
                    elif len(parts) >= 6 and parts[2] == "/var/tmp":
                        opts = parts[5].strip("()").split(",")
                        var_tmp_options = [o.strip() for o in opts]

            observations.append(ObservationData(
                category="filesystem",
                control="filesystem.tmp_nodev",
                value="nodev" in tmp_options,
                source="mount"
            ))
            observations.append(ObservationData(
                category="filesystem",
                control="filesystem.tmp_nosuid",
                value="nosuid" in tmp_options,
                source="mount"
            ))
            observations.append(ObservationData(
                category="filesystem",
                control="filesystem.tmp_noexec",
                value="noexec" in tmp_options,
                source="mount"
            ))
            observations.append(ObservationData(
                category="filesystem",
                control="filesystem.shm_nodev",
                value="nodev" in shm_options,
                source="mount"
            ))
            observations.append(ObservationData(
                category="filesystem",
                control="filesystem.shm_nosuid",
                value="nosuid" in shm_options,
                source="mount"
            ))
            observations.append(ObservationData(
                category="filesystem",
                control="filesystem.shm_noexec",
                value="noexec" in shm_options,
                source="mount"
            ))

            # 2. Core dump limits (/etc/security/limits.conf)
            limits_content = await ctx.read_file("/etc/security/limits.conf")
            hard_core_zero = False
            if limits_content:
                raw_evidence["/etc/security/limits.conf"] = limits_content
                for line in limits_content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 4:
                        domain, lim_type, item, value = parts[:4]
                        if domain == "*" and lim_type == "hard" and item == "core" and value == "0":
                            hard_core_zero = True

            observations.append(ObservationData(
                category="filesystem",
                control="filesystem.core_dumps_restricted",
                value=hard_core_zero,
                source="/etc/security/limits.conf"
            ))

            # 3. World-writable files in /etc or /bin
            ww_res = await ctx.run_command("filesystem.find_world_writable")
            ww_files = []
            if ww_res.get("stdout"):
                ww_files = [f for f in ww_res["stdout"].splitlines() if f.strip()]
            raw_evidence["world_writable_files"] = ww_files

            observations.append(ObservationData(
                category="filesystem",
                control="filesystem.world_writable_system_files",
                value=len(ww_files),
                source="find /etc /bin /sbin -perm -0002"
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
                error_message=f"Filesystem collector failed: {str(e)}",
                duration_ms=(time.monotonic() - start_time) * 1000.0
            )
