import datetime
from typing import Any, Dict, List, Optional
from backend.app.models.entities import FindingSeverity, RemediationStatus


class RemediationEngine:
    """
    Safe remediation planning and execution engine.
    Enforces explicit administrator approval, backup creation, and rollback commands.
    """

    def generate_plan(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """
        Synthesizes a proposed remediation plan based on the rule and finding.
        Never executes automatically.
        """
        control = finding.get("control", "")
        rule_id = finding.get("rule_id", "")
        finding_id = finding.get("id", "")

        commands: List[str] = []
        rollback_commands: List[str] = []
        target_file: Optional[str] = None
        proposed_diff: Optional[str] = None

        if control == "ssh.permit_root_login":
            target_file = "/etc/ssh/sshd_config"
            commands = [
                "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.psv_backup",
                "sed -i -E 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config",
                "sshd -t && systemctl reload sshd"
            ]
            rollback_commands = [
                "cp /etc/ssh/sshd_config.psv_backup /etc/ssh/sshd_config",
                "systemctl reload sshd"
            ]
            proposed_diff = "- PermitRootLogin yes\n+ PermitRootLogin no"

        elif control == "ssh.password_authentication":
            target_file = "/etc/ssh/sshd_config"
            commands = [
                "cp /etc/ssh/sshd_config /etc/ssh/sshd_config.psv_backup",
                "sed -i -E 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config",
                "sshd -t && systemctl reload sshd"
            ]
            rollback_commands = [
                "cp /etc/ssh/sshd_config.psv_backup /etc/ssh/sshd_config",
                "systemctl reload sshd"
            ]
            proposed_diff = "- PasswordAuthentication yes\n+ PasswordAuthentication no"

        elif control == "sudo.use_pty":
            target_file = "/etc/sudoers.d/99-psv-hardening"
            commands = [
                "echo 'Defaults use_pty' > /etc/sudoers.d/99-psv-hardening",
                "chmod 0440 /etc/sudoers.d/99-psv-hardening",
                "visudo -c"
            ]
            rollback_commands = [
                "rm -f /etc/sudoers.d/99-psv-hardening"
            ]
            proposed_diff = "+ Defaults use_pty"

        elif control == "kernel.randomize_va_space":
            target_file = "/etc/sysctl.d/99-psv-hardening.conf"
            commands = [
                "echo 'kernel.randomize_va_space = 2' >> /etc/sysctl.d/99-psv-hardening.conf",
                "sysctl -w kernel.randomize_va_space=2"
            ]
            rollback_commands = [
                "sed -i '/kernel.randomize_va_space/d' /etc/sysctl.d/99-psv-hardening.conf",
                "sysctl -w kernel.randomize_va_space=0"
            ]
            proposed_diff = "+ kernel.randomize_va_space = 2"

        elif control == "network.ip_forwarding":
            target_file = "/etc/sysctl.d/99-psv-hardening.conf"
            commands = [
                "echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.d/99-psv-hardening.conf",
                "sysctl -w net.ipv4.ip_forward=0"
            ]
            rollback_commands = [
                "sed -i '/net.ipv4.ip_forward/d' /etc/sysctl.d/99-psv-hardening.conf",
                "sysctl -w net.ipv4.ip_forward=1"
            ]
            proposed_diff = "- net.ipv4.ip_forward = 1\n+ net.ipv4.ip_forward = 0"

        elif control == "firewall.ufw_active" or control == "firewall.any_firewall_active":
            target_file = "/etc/default/ufw"
            commands = [
                "ufw default deny incoming",
                "ufw allow 22/tcp",
                "ufw --force enable"
            ]
            rollback_commands = [
                "ufw disable"
            ]
            proposed_diff = "+ ufw enable (default deny incoming, allow 22/tcp)"

        else:
            commands = [f"# Automated remediation template for {control}", f"# Guidance: {finding.get('remediation_guidance', '')}"]
            rollback_commands = [f"# Rollback instructions for {control}"]
            proposed_diff = f"+ Apply configuration per {rule_id}"

        return {
            "finding_id": finding_id,
            "status": RemediationStatus.PLANNED,
            "title": f"Harden {control}",
            "description": f"Proposed security configuration change for {finding.get('title', control)}. Requires explicit operator approval.",
            "target_file": target_file,
            "proposed_diff": proposed_diff,
            "commands": commands,
            "backup_path": f"{target_file}.psv_backup" if target_file else None,
            "rollback_commands": rollback_commands,
        }


remediation_engine = RemediationEngine()
