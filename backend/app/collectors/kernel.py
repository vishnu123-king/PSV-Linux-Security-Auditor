import re
import time
from typing import Any, Dict, List
from backend.app.collectors.base import BaseCollector, CollectorResult, ExecutionContext, ObservationData


class KernelCollector(BaseCollector):
    name = "kernel"
    category = "kernel"
    description = "Inspects kernel self-protection mechanisms and runtime sysctl parameters"

    async def collect(self, ctx: ExecutionContext) -> CollectorResult:
        start_time = time.monotonic()
        observations: List[ObservationData] = []
        raw_evidence: Dict[str, Any] = {}

        try:
            sysctl_res = await ctx.run_command("kernel.sysctl_all")
            sysctl_map: Dict[str, str] = {}

            if sysctl_res.get("stdout"):
                raw_evidence["sysctl"] = sysctl_res["stdout"]
                for line in sysctl_res["stdout"].splitlines():
                    if "=" in line:
                        k, v = line.split("=", 1)
                        sysctl_map[k.strip()] = v.strip()

            def get_int_param(key: str, default: int = -1) -> int:
                val = sysctl_map.get(key)
                if val is not None and val.isdigit():
                    return int(val)
                return default

            # 1. ASLR (randomize_va_space == 2)
            aslr_val = get_int_param("kernel.randomize_va_space", 0)
            observations.append(ObservationData(
                category="kernel",
                control="kernel.randomize_va_space",
                value=aslr_val,
                source="sysctl kernel.randomize_va_space"
            ))

            # 2. kptr_restrict (>= 1)
            kptr_val = get_int_param("kernel.kptr_restrict", 0)
            observations.append(ObservationData(
                category="kernel",
                control="kernel.kptr_restrict",
                value=kptr_val,
                source="sysctl kernel.kptr_restrict"
            ))

            # 3. dmesg_restrict (== 1)
            dmesg_val = get_int_param("kernel.dmesg_restrict", 0)
            observations.append(ObservationData(
                category="kernel",
                control="kernel.dmesg_restrict",
                value=dmesg_val,
                source="sysctl kernel.dmesg_restrict"
            ))

            # 4. protected_hardlinks (== 1)
            hardlinks = get_int_param("fs.protected_hardlinks", 0)
            observations.append(ObservationData(
                category="kernel",
                control="kernel.protected_hardlinks",
                value=hardlinks == 1,
                source="sysctl fs.protected_hardlinks"
            ))

            # 5. protected_symlinks (== 1)
            symlinks = get_int_param("fs.protected_symlinks", 0)
            observations.append(ObservationData(
                category="kernel",
                control="kernel.protected_symlinks",
                value=symlinks == 1,
                source="sysctl fs.protected_symlinks"
            ))

            # 6. suid_dumpable (== 0)
            suid_dump = get_int_param("fs.suid_dumpable", 2)
            observations.append(ObservationData(
                category="kernel",
                control="kernel.suid_dumpable",
                value=suid_dump,
                source="sysctl fs.suid_dumpable"
            ))

            # 7. unprivileged_bpf_disabled (>= 1)
            bpf_val = get_int_param("kernel.unprivileged_bpf_disabled", 0)
            observations.append(ObservationData(
                category="kernel",
                control="kernel.unprivileged_bpf_disabled",
                value=bpf_val,
                source="sysctl kernel.unprivileged_bpf_disabled"
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
                error_message=f"Kernel collector failed: {str(e)}",
                duration_ms=(time.monotonic() - start_time) * 1000.0
            )
