import json
import time
from typing import Any, Dict, List
from backend.app.collectors.base import BaseCollector, CollectorResult, ExecutionContext, ObservationData


class ContainersCollector(BaseCollector):
    name = "containers"
    category = "containers"
    description = "Inspects Docker daemon security configurations, user namespaces, and container runtime isolation"

    async def collect(self, ctx: ExecutionContext) -> CollectorResult:
        start_time = time.monotonic()
        observations: List[ObservationData] = []
        raw_evidence: Dict[str, Any] = {}

        try:
            # 1. /etc/docker/daemon.json
            daemon_json = await ctx.read_file("/etc/docker/daemon.json")
            has_docker_config = False
            userns_remap = False
            live_restore = False
            no_new_privileges = False
            icc_disabled = False

            if daemon_json:
                has_docker_config = True
                raw_evidence["/etc/docker/daemon.json"] = daemon_json
                try:
                    cfg = json.loads(daemon_json)
                    if "userns-remap" in cfg and cfg["userns-remap"]:
                        userns_remap = True
                    if cfg.get("live-restore") is True:
                        live_restore = True
                    if cfg.get("no-new-privileges") is True:
                        no_new_privileges = True
                    if cfg.get("icc") is False:
                        icc_disabled = True
                except Exception:
                    pass

            observations.append(ObservationData(
                category="containers",
                control="containers.docker_installed",
                value=has_docker_config,
                source="/etc/docker/daemon.json"
            ))
            observations.append(ObservationData(
                category="containers",
                control="containers.userns_remap_enabled",
                value=userns_remap,
                source="/etc/docker/daemon.json"
            ))
            observations.append(ObservationData(
                category="containers",
                control="containers.live_restore_enabled",
                value=live_restore,
                source="/etc/docker/daemon.json"
            ))
            observations.append(ObservationData(
                category="containers",
                control="containers.no_new_privileges_default",
                value=no_new_privileges,
                source="/etc/docker/daemon.json"
            ))
            observations.append(ObservationData(
                category="containers",
                control="containers.inter_container_communication_disabled",
                value=icc_disabled,
                source="/etc/docker/daemon.json"
            ))

            # 2. Check docker ps if docker is available
            ps_res = await ctx.run_command("containers.docker_ps")
            container_count = 0
            if ps_res.get("exit_code") == 0 and ps_res.get("stdout"):
                lines = [l for l in ps_res["stdout"].splitlines() if l.strip()]
                container_count = len(lines)
                raw_evidence["docker_ps"] = ps_res["stdout"]

            observations.append(ObservationData(
                category="containers",
                control="containers.running_container_count",
                value=container_count,
                source="docker ps"
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
                error_message=f"Containers collector failed: {str(e)}",
                duration_ms=(time.monotonic() - start_time) * 1000.0
            )
