import asyncio
from datetime import datetime, timezone
import logging
import time
from typing import Any, Dict, List, Optional, Set
from sqlalchemy import select
from backend.app.collectors import get_all_collectors
from backend.app.collectors.base import CollectorResult, ExecutionContext, ObservationData
from backend.app.core.config import get_settings
from backend.app.core.database import async_session_factory
from backend.app.core.event_bus import event_bus
from backend.app.engine.local_context import LocalExecutionContext
from backend.app.engine.rule_engine import RuleEngine
from backend.app.engine.rule_loader import rule_loader
from backend.app.engine.ssh import SSHExecutionContext
from backend.app.models.entities import (
    Assessment,
    AssessmentStatus,
    AuditEvent,
    CredentialReference,
    Evidence,
    Finding,
    FindingSeverity,
    FindingStatus,
    Host,
    Observation,
    Profile,
    RuleResult,
)

logger = logging.getLogger(__name__)


# In-memory WebSocket connection registry for broadcasting real-time progress
class AssessmentBroadcastManager:
    def __init__(self) -> None:
        self._connections: Dict[str, Set[Any]] = {}

    def register(self, assessment_id: str, ws: Any) -> None:
        if assessment_id not in self._connections:
            self._connections[assessment_id] = set()
        self._connections[assessment_id].add(ws)

    def unregister(self, assessment_id: str, ws: Any) -> None:
        if assessment_id in self._connections:
            self._connections[assessment_id].discard(ws)
            if not self._connections[assessment_id]:
                del self._connections[assessment_id]

    async def broadcast(self, assessment_id: str, event_type: str, data: Dict[str, Any]) -> None:
        if assessment_id not in self._connections:
            return
        payload = {"event": event_type, "timestamp": datetime.now(timezone.utc).isoformat(), "data": data}
        dead_connections = set()
        for ws in self._connections[assessment_id]:
            try:
                await ws.send_json(payload)
            except Exception:
                dead_connections.add(ws)
        for dead in dead_connections:
            self.unregister(assessment_id, dead)


broadcast_manager = AssessmentBroadcastManager()


class SimulatedTargetExecutionContext(ExecutionContext):
    """
    Realistic simulated test environment target used for disposable testing
    or local dev without requiring an external SSH server.
    """
    def __init__(self, hostname: str = "test-host-01") -> None:
        self.hostname = hostname

    async def read_file(self, path: str, max_bytes: int = 262144) -> Optional[str]:
        if path == "/etc/os-release":
            return 'NAME="Ubuntu"\nVERSION="24.04 LTS (Noble Numbat)"\nID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04 LTS"\n'
        elif path == "/etc/hostname":
            return f"{self.hostname}\n"
        elif path == "/etc/machine-id":
            return "4a18f8e438c84d69a244b706c9e03d42\n"
        elif path == "/etc/passwd":
            return (
                "root:x:0:0:root:/root:/bin/bash\n"
                "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
                "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
                "sync:x:4:65534:sync:/bin:/bin/sync\n"
                "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
                "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
                "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
                "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
                "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
                "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n"
                "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n"
                "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
                "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
                "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n"
                "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n"
                "gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\n"
                "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
                "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"
                "systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n"
                "ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"
            )
        elif path == "/etc/shadow":
            return (
                "root:$6$rounds=4096$rounds$saltsalt$h9W8.secureHashExample...:19500:0:99999:7:::\n"
                "daemon:*:19500:0:99999:7:::\n"
                "bin:*:19500:0:99999:7:::\n"
                "nobody:*:19500:0:99999:7:::\n"
                "ubuntu:$6$saltsalt$roundsExampleHash...:19500:0:90:7:::\n"
            )
        elif path == "/etc/login.defs":
            return "PASS_MAX_DAYS 90\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\nENCRYPT_METHOD SHA512\n"
        elif path == "/etc/ssh/sshd_config":
            # Realistic configuration with a few intentional compliance gaps
            return (
                "# PSV Auditor Target SSHD Config\n"
                "Port 22\n"
                "PermitRootLogin yes\n"              # Finding: Root login enabled
                "PasswordAuthentication yes\n"       # Finding: Password auth enabled
                "PermitEmptyPasswords no\n"
                "X11Forwarding yes\n"                # Finding: X11 forwarding enabled
                "MaxAuthTries 6\n"                   # Finding: MaxAuthTries > 4
                "ClientAliveInterval 0\n"            # Finding: No idle timeout
                "ClientAliveCountMax 3\n"
                "HostbasedAuthentication no\n"
                "IgnoreRhosts yes\n"
                "LoginGraceTime 120\n"
            )
        elif path == "/etc/sudoers":
            return (
                "Defaults env_reset\n"
                "Defaults mail_badpass\n"
                "Defaults secure_path=\"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\"\n"
                "root ALL=(ALL:ALL) ALL\n"
                "%admin ALL=(ALL) ALL\n"
                "%sudo ALL=(ALL:ALL) ALL\n"
                "ubuntu ALL=(ALL) NOPASSWD: ALL\n"    # Finding: NOPASSWD wildcard escalation
            )
        elif path == "/etc/security/limits.conf":
            return "# /etc/security/limits.conf\n* hard core 0\n"
        elif path == "/etc/sysctl.conf":
            return (
                "net.ipv4.ip_forward = 1\n"          # Finding: IP forwarding enabled
                "net.ipv4.conf.all.send_redirects = 1\n"
                "net.ipv4.conf.all.accept_redirects = 0\n"
                "net.ipv4.conf.all.accept_source_route = 0\n"
                "net.ipv4.tcp_syncookies = 1\n"
            )
        elif path == "/etc/security/pwquality.conf":
            return "minlen = 10\nretry = 3\ndcredit = -1\nucredit = -1\nlcredit = -1\n"
        elif path == "/etc/pam.d/common-auth":
            return "auth required pam_faillock.so preauth audit deny=5 unlock_time=900\nauth [success=1 default=ignore] pam_unix.so nullok\n"
        elif path == "/etc/pam.d/common-password":
            return "password requisite pam_pwquality.so retry=3\npassword [success=1 default=ignore] pam_unix.so obscure sha512 remember=5\n"
        elif path == "/etc/audit/auditd.conf":
            return "max_log_file_action = ROTATE\nspace_left_action = SYSLOG\n"
        elif path == "/etc/systemd/journald.conf":
            return "[Journal]\nStorage=persistent\nCompress=yes\n"
        elif path == "/etc/docker/daemon.json":
            return '{"live-restore": true, "no-new-privileges": false, "icc": false}\n'
        return None

    async def run_command(self, command_id: str) -> Dict[str, Any]:
        if command_id == "system.uname":
            return {"command": "uname -a", "stdout": "Linux test-server-01 6.8.0-31-generic #31-Ubuntu SMP PREEMPT_DYNAMIC x86_64", "exit_code": 0}
        elif command_id == "system.uptime":
            return {"command": "uptime", "stdout": " 12:00:00 up 14 days,  3:12,  2 users,  load average: 0.15, 0.12, 0.08", "exit_code": 0}
        elif command_id == "filesystem.df_mounts":
            return {"command": "mount", "stdout": "/dev/sda1 on / type ext4 (rw,relatime)\ntmpfs on /tmp type tmpfs (rw,nosuid,nodev)\ntmpfs on /dev/shm type tmpfs (rw,nosuid,nodev)\n", "exit_code": 0}
        elif command_id == "filesystem.find_world_writable":
            return {"command": "find /etc ...", "stdout": "", "exit_code": 0}
        elif command_id == "network.ss_listening_ports":
            return {"command": "ss -tulpn", "stdout": "LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"sshd\",pid=1024,fd=3))\nLISTEN 0 128 0.0.0.0:80 0.0.0.0:* users:((\"nginx\",pid=1200,fd=6))\n", "exit_code": 0}
        elif command_id == "firewall.ufw_status":
            return {"command": "ufw status verbose", "stdout": "Status: inactive\n", "exit_code": 0}
        elif command_id == "firewall.iptables_status":
            return {"command": "iptables -L -n -v", "stdout": "Chain INPUT (policy ACCEPT 0 packets, 0 bytes)\n", "exit_code": 0}
        elif command_id == "services.systemctl_list_units":
            return {"command": "systemctl list-units", "stdout": "sshd.service loaded active running OpenSSH Daemon\nnginx.service loaded active running NGINX\nsystemd-journald.service loaded active running Journal Service\nchrony.service loaded active running Chrony NTP\n", "exit_code": 0}
        elif command_id == "services.systemctl_status_chrony":
            return {"command": "systemctl is-active chrony", "stdout": "active\n", "exit_code": 0}
        elif command_id == "services.systemctl_status_systemd_timesyncd":
            return {"command": "systemctl is-active systemd-timesyncd", "stdout": "inactive\n", "exit_code": 0}
        elif command_id == "kernel.sysctl_all":
            return {"command": "sysctl -a", "stdout": "kernel.randomize_va_space = 2\nkernel.kptr_restrict = 1\nkernel.dmesg_restrict = 1\nfs.protected_hardlinks = 1\nfs.protected_symlinks = 1\nfs.suid_dumpable = 0\nkernel.unprivileged_bpf_disabled = 1\n", "exit_code": 0}
        elif command_id == "logging.auditctl_status":
            return {"command": "auditctl -s", "stdout": "enabled 1\nflag 1\npid 640\nrate_limit 0\nbacklog_limit 8192\nlost 0\nbacklog 0\n", "exit_code": 0}
        elif command_id == "logging.auditctl_rules":
            return {"command": "auditctl -l", "stdout": "-w /etc/passwd -p wa -k identity_mod\n-w /etc/shadow -p wa -k identity_mod\n-w /etc/sudoers -p wa -k sudo_mod\n", "exit_code": 0}
        elif command_id == "containers.docker_ps":
            return {"command": "docker ps", "stdout": "c8f912a|nginx:alpine|web_proxy\n", "exit_code": 0}
        return {"command": command_id, "stdout": "", "stderr": "", "exit_code": 0}

    def get_target_metadata(self) -> Dict[str, Any]:
        return {"hostname": self.hostname, "is_simulated": True}


class AssessmentOrchestrator:
    """
    Core Assessment Execution Engine.
    Coordinates connection, collection, normalization, evaluation, and DB persistence.
    """

    async def execute_assessment(self, assessment_id: str) -> None:
        logger.info(f"Starting execution for assessment {assessment_id}")
        start_time = time.monotonic()
        rule_engine = RuleEngine()

        async with async_session_factory() as db:
            # 1. Fetch Assessment and Host
            result = await db.execute(select(Assessment).where(Assessment.id == assessment_id))
            assessment = result.scalar_one_or_none()
            if not assessment:
                logger.error(f"Assessment {assessment_id} not found")
                return

            host_result = await db.execute(select(Host).where(Host.id == assessment.host_id))
            host = host_result.scalar_one_or_none()
            if not host:
                assessment.status = AssessmentStatus.FAILED
                assessment.error_message = f"Host {assessment.host_id} not found"
                await db.commit()
                return

            # Check credentials if present
            credential = None
            if host.credential_id:
                cred_res = await db.execute(select(CredentialReference).where(CredentialReference.id == host.credential_id))
                credential = cred_res.scalar_one_or_none()

            # State transition: CONNECTING
            assessment.status = AssessmentStatus.CONNECTING
            assessment.started_at = datetime.now(timezone.utc)
            assessment.progress_percent = 5
            await db.commit()
            await broadcast_manager.broadcast(assessment_id, "assessment_started", {
                "assessment_id": assessment_id,
                "host_id": host.id,
                "status": "CONNECTING"
            })

            # 2. Establish Execution Context
            is_simulated = bool(host.tags.get("simulated") is True)
            is_local = bool(host.tags.get("local") is True or host.tags.get("connector") == "local" or (host.hostname in ["localhost", "127.0.0.1"] and not credential))

            ctx: ExecutionContext
            ssh_ctx: Optional[SSHExecutionContext] = None

            if is_simulated:
                logger.info(f"Target '{host.hostname}' evaluated using simulated test environment.")
                ctx = SimulatedTargetExecutionContext(hostname=host.hostname)
            elif is_local:
                logger.info(f"Auditing local machine '{host.hostname}' using LocalExecutionContext.")
                ctx = LocalExecutionContext(hostname=host.hostname)
            else:
                try:
                    ssh_ctx = SSHExecutionContext(
                        hostname=host.hostname,
                        port=host.port,
                        username=credential.username if credential else "root",
                        client_keys=[credential.encrypted_secret] if credential and credential.auth_type == "ssh_key" else None,
                        password=credential.encrypted_secret if credential and credential.auth_type == "password" else None,
                        known_hosts="ignore" if host.tags.get("skip_host_key_verify") or host.tags.get("test") else "known_hosts"
                    )
                    await ssh_ctx.connect()
                    ctx = ssh_ctx
                except Exception as e:
                    logger.error(f"SSH connection failed to {host.hostname}: {e}")
                    assessment.status = AssessmentStatus.FAILED
                    assessment.error_message = f"SSH connection failed: {str(e)}"
                    assessment.completed_at = datetime.now(timezone.utc)
                    await db.commit()
                    await broadcast_manager.broadcast(assessment_id, "assessment_failed", {
                        "assessment_id": assessment_id,
                        "error": str(e)
                    })
                    return

            try:
                # State transition: DISCOVERING & COLLECTING
                assessment.status = AssessmentStatus.COLLECTING
                assessment.progress_percent = 15
                await db.commit()

                collectors = get_all_collectors()
                total_collectors = len(collectors)
                completed_collectors: List[str] = []
                all_observations_data: List[ObservationData] = []
                failed_collectors: Set[str] = set()
                collector_evidences: Dict[str, Dict[str, Any]] = {}

                for idx, collector in enumerate(collectors, start=1):
                    assessment.current_collector = collector.name
                    # Compute progress: 15% to 65% across collectors
                    assessment.progress_percent = int(15 + (idx / total_collectors) * 50)
                    await db.commit()

                    await broadcast_manager.broadcast(assessment_id, "collector_started", {
                        "collector": collector.name,
                        "progress": assessment.progress_percent
                    })

                    try:
                        res: CollectorResult = await collector.collect(ctx)
                        if res.success:
                            completed_collectors.append(collector.name)
                            all_observations_data.extend(res.observations)
                            collector_evidences[collector.name] = res.raw_evidence
                            await broadcast_manager.broadcast(assessment_id, "collector_completed", {
                                "collector": collector.name,
                                "observation_count": len(res.observations)
                            })
                        else:
                            failed_collectors.add(collector.name)
                            logger.warning(f"Collector {collector.name} reported failure: {res.error_message}")
                            await broadcast_manager.broadcast(assessment_id, "collector_failed", {
                                "collector": collector.name,
                                "error": res.error_message
                            })
                    except Exception as err:
                        failed_collectors.add(collector.name)
                        logger.error(f"Unhandled exception in collector {collector.name}: {err}")
                        await broadcast_manager.broadcast(assessment_id, "collector_failed", {
                            "collector": collector.name,
                            "error": str(err)
                        })

                assessment.completed_collectors = completed_collectors

                # State transition: NORMALIZING
                assessment.status = AssessmentStatus.NORMALIZING
                assessment.progress_percent = 70
                await db.commit()

                # Build observations map for fast rule evaluation
                observations_map: Dict[str, Any] = {}
                for obs_data in all_observations_data:
                    observations_map[obs_data.control] = obs_data.value
                    # Persist Observation entity to DB
                    obs_entity = Observation(
                        assessment_id=assessment_id,
                        collector=obs_data.category,
                        category=obs_data.category,
                        control=obs_data.control,
                        value=obs_data.value,
                        source=obs_data.source,
                        command_executed=obs_data.command_executed,
                        collected_at=obs_data.collected_at
                    )
                    db.add(obs_entity)

                await db.flush()

                # State transition: EVALUATING
                assessment.status = AssessmentStatus.EVALUATING
                assessment.progress_percent = 75
                await db.commit()

                # Load rules
                all_rules = rule_loader.load_all_rules()
                control_collector_map = rule_loader.get_control_collector_map()

                # Filter by profile if not default
                rules_to_eval = all_rules

                passed_count = 0
                failed_count = 0
                warn_count = 0
                unknown_count = 0
                critical_count = 0
                high_count = 0
                medium_count = 0
                low_count = 0

                for r_idx, rule_dict in enumerate(rules_to_eval, start=1):
                    eval_result = rule_engine.evaluate_rule(
                        rule_dict=rule_dict,
                        observations_map=observations_map,
                        failed_collectors=failed_collectors,
                        control_collector_map=control_collector_map,
                        target_distro=host.os_distribution
                    )

                    sev = rule_dict.get("severity", "MEDIUM")

                    if eval_result.result == RuleResult.PASS:
                        passed_count += 1
                    elif eval_result.result == RuleResult.FAIL:
                        failed_count += 1
                        if sev == "CRITICAL":
                            critical_count += 1
                        elif sev == "HIGH":
                            high_count += 1
                        elif sev == "MEDIUM":
                            medium_count += 1
                        elif sev == "LOW":
                            low_count += 1
                    elif eval_result.result == RuleResult.WARN:
                        warn_count += 1
                    elif eval_result.result == RuleResult.UNKNOWN:
                        unknown_count += 1

                    # If FAIL or UNKNOWN, create Finding record
                    if eval_result.result in (RuleResult.FAIL, RuleResult.UNKNOWN, RuleResult.WARN):
                        finding_status = FindingStatus.OPEN
                        f_severity = FindingSeverity(sev) if sev in FindingSeverity.__members__ else FindingSeverity.MEDIUM

                        finding_entity = Finding(
                            assessment_id=assessment_id,
                            host_id=host.id,
                            rule_id=rule_dict["id"],
                            title=rule_dict["name"],
                            category=rule_dict.get("category", "general"),
                            severity=f_severity,
                            status=finding_status,
                            result=eval_result.result,
                            control=rule_dict["control"],
                            expected_value=eval_result.expected_value,
                            actual_value=eval_result.actual_value,
                            rationale=rule_dict.get("rationale", ""),
                            remediation_guidance=rule_dict.get("remediation_guidance", ""),
                            verification_method=rule_dict.get("verification_method", "")
                        )
                        db.add(finding_entity)
                        await db.flush()

                        # Attach Evidence
                        rel_collector = control_collector_map.get(rule_dict["control"], "system")
                        collector_ev = collector_evidences.get(rel_collector, {})
                        raw_ev_str = str(collector_ev.get(rule_dict["control"]) or collector_ev or "No raw output recorded")

                        evidence_entity = Evidence(
                            finding_id=finding_entity.id,
                            source_file=None,
                            command_executed=None,
                            raw_output=raw_ev_str,
                            normalized_data={"actual": eval_result.actual_value, "expected": eval_result.expected_value}
                        )
                        db.add(evidence_entity)

                        await broadcast_manager.broadcast(assessment_id, "finding_created", {
                            "finding_id": finding_entity.id,
                            "rule_id": rule_dict["id"],
                            "title": rule_dict["name"],
                            "severity": sev,
                            "result": eval_result.result.value
                        })

                # Compute final compliance score
                total_evaluated = passed_count + failed_count + warn_count
                compliance_score = round((passed_count / max(1, total_evaluated)) * 100.0, 1)

                duration = time.monotonic() - start_time
                assessment.status = AssessmentStatus.COMPLETED
                assessment.progress_percent = 100
                assessment.total_rules = len(rules_to_eval)
                assessment.passed_rules = passed_count
                assessment.failed_rules = failed_count
                assessment.warn_rules = warn_count
                assessment.unknown_rules = unknown_count
                assessment.critical_count = critical_count
                assessment.high_count = high_count
                assessment.medium_count = medium_count
                assessment.low_count = low_count
                assessment.compliance_score = compliance_score
                assessment.completed_at = datetime.now(timezone.utc)
                assessment.duration_seconds = duration

                # Update host last seen
                host.last_seen = datetime.now(timezone.utc)
                host.last_assessment_status = "COMPLETED"

                # Record Audit Event
                audit_log = AuditEvent(
                    action="assessment.completed",
                    resource_type="assessment",
                    resource_id=assessment_id,
                    details={
                        "host_id": host.id,
                        "compliance_score": compliance_score,
                        "findings": failed_count,
                        "duration": round(duration, 2)
                    }
                )
                db.add(audit_log)

                await db.commit()

                await broadcast_manager.broadcast(assessment_id, "assessment_completed", {
                    "assessment_id": assessment_id,
                    "compliance_score": compliance_score,
                    "passed": passed_count,
                    "failed": failed_count,
                    "critical": critical_count,
                    "high": high_count,
                    "duration_seconds": round(duration, 2)
                })

                logger.info(
                    f"Assessment {assessment_id} completed successfully in {duration:.2f}s: "
                    f"Score: {compliance_score}% | Pass: {passed_count} | Fail: {failed_count} | Unknown: {unknown_count}"
                )

            finally:
                if ssh_ctx:
                    await ssh_ctx.close()


orchestrator = AssessmentOrchestrator()


async def process_job(payload: Dict[str, Any]) -> None:
    assessment_id = payload.get("assessment_id")
    if assessment_id:
        await orchestrator.execute_assessment(assessment_id)


def start_worker_listener() -> None:
    event_bus.register_consumer(process_job)


def main() -> None:
    """CLI Worker entrypoint for `psv-worker` or `python -m backend.app.workers.assessment_worker`."""
    import sys
    from backend.app.core.logging import setup_logging
    setup_logging()

    logger.info("Starting PSV Assessment Worker Daemon...")

    async def run() -> None:
        await event_bus.connect()
        start_worker_listener()
        logger.info("Worker subscribed and waiting for assessment jobs. Press Ctrl+C to terminate.")
        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            pass
        finally:
            await event_bus.close()

    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        logger.info("Worker stopped by user.")
        sys.exit(0)


if __name__ == "__main__":
    main()
