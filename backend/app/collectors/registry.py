"""
Predefined Safe Command and File Registry.

Per requirement #22:
- Do not create an arbitrary shell API.
- Collectors may use only registered, immutable commands.
- Never concatenate user input into shell commands.
- Prefer direct file reading where practical.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set


@dataclass(frozen=True)
class SafeCommand:
    identifier: str
    command_args: List[str]
    description: str
    timeout_seconds: int = 15
    max_output_bytes: int = 524288  # 512 KB
    requires_root: bool = False


# Immutable registry of allowed command execution definitions
SAFE_COMMAND_REGISTRY: Dict[str, SafeCommand] = {
    # System
    "system.uname": SafeCommand(
        identifier="system.uname",
        command_args=["uname", "-a"],
        description="Inspect kernel and architecture"
    ),
    "system.uptime": SafeCommand(
        identifier="system.uptime",
        command_args=["uptime"],
        description="System uptime"
    ),
    "system.systemd_detect_virt": SafeCommand(
        identifier="system.systemd_detect_virt",
        command_args=["systemd-detect-virt"],
        description="Detect virtualization technology"
    ),

    # Identity
    "identity.getent_passwd": SafeCommand(
        identifier="identity.getent_passwd",
        command_args=["getent", "passwd"],
        description="Enumerate local and directory service user accounts"
    ),
    "identity.getent_group": SafeCommand(
        identifier="identity.getent_group",
        command_args=["getent", "group"],
        description="Enumerate system groups"
    ),
    "identity.lastlog": SafeCommand(
        identifier="identity.lastlog",
        command_args=["lastlog", "-b", "90"],
        description="Check dormant user accounts inactive over 90 days"
    ),

    # Sudo
    "sudo.version": SafeCommand(
        identifier="sudo.version",
        command_args=["sudo", "-V"],
        description="Check installed sudo version"
    ),

    # Filesystem
    "filesystem.df_mounts": SafeCommand(
        identifier="filesystem.df_mounts",
        command_args=["mount"],
        description="Verify filesystem mount options (nodev, nosuid, noexec)"
    ),
    "filesystem.find_world_writable": SafeCommand(
        identifier="filesystem.find_world_writable",
        command_args=["find", "/etc", "/var/log", "/bin", "/sbin", "-xdev", "-type", "f", "-perm", "-0002"],
        description="Locate world-writable critical system files"
    ),
    "filesystem.find_suid_bins": SafeCommand(
        identifier="filesystem.find_suid_bins",
        command_args=["find", "/usr/bin", "/usr/sbin", "/bin", "/sbin", "-xdev", "-type", "f", "-perm", "-4000"],
        description="Enumerate SUID executables"
    ),

    # Networking
    "network.ss_listening_ports": SafeCommand(
        identifier="network.ss_listening_ports",
        command_args=["ss", "-tulpn"],
        description="List all active listening TCP and UDP sockets"
    ),
    "network.ip_addr": SafeCommand(
        identifier="network.ip_addr",
        command_args=["ip", "-br", "addr"],
        description="List network interface addresses"
    ),

    # Firewall
    "firewall.ufw_status": SafeCommand(
        identifier="firewall.ufw_status",
        command_args=["ufw", "status", "verbose"],
        description="Check Uncomplicated Firewall state"
    ),
    "firewall.iptables_status": SafeCommand(
        identifier="firewall.iptables_status",
        command_args=["iptables", "-L", "-n", "-v"],
        description="Inspect legacy packet filtering chains",
        requires_root=True
    ),
    "firewall.nftables_status": SafeCommand(
        identifier="firewall.nftables_status",
        command_args=["nft", "list", "ruleset"],
        description="Inspect modern nftables rulesets",
        requires_root=True
    ),

    # Services
    "services.systemctl_list_units": SafeCommand(
        identifier="services.systemctl_list_units",
        command_args=["systemctl", "list-units", "--type=service", "--state=running", "--no-pager", "--no-legend"],
        description="List running systemd services"
    ),
    "services.systemctl_status_chrony": SafeCommand(
        identifier="services.systemctl_status_chrony",
        command_args=["systemctl", "is-active", "chrony"],
        description="Verify chrony NTP time sync active"
    ),
    "services.systemctl_status_systemd_timesyncd": SafeCommand(
        identifier="services.systemctl_status_systemd_timesyncd",
        command_args=["systemctl", "is-active", "systemd-timesyncd"],
        description="Verify systemd-timesyncd active"
    ),

    # Kernel
    "kernel.sysctl_all": SafeCommand(
        identifier="kernel.sysctl_all",
        command_args=["sysctl", "-a"],
        description="Dump kernel runtime parameters"
    ),

    # Logging
    "logging.auditctl_status": SafeCommand(
        identifier="logging.auditctl_status",
        command_args=["auditctl", "-s"],
        description="Check Linux auditd daemon status"
    ),
    "logging.auditctl_rules": SafeCommand(
        identifier="logging.auditctl_rules",
        command_args=["auditctl", "-l"],
        description="Check configured auditd rules"
    ),
    "logging.systemctl_status_journald": SafeCommand(
        identifier="logging.systemctl_status_journald",
        command_args=["systemctl", "is-active", "systemd-journald"],
        description="Verify systemd-journald active"
    ),

    # Containers
    "containers.docker_info": SafeCommand(
        identifier="containers.docker_info",
        command_args=["docker", "info", "--format", "{{json .}}"],
        description="Query Docker daemon configuration and security options"
    ),
    "containers.docker_ps": SafeCommand(
        identifier="containers.docker_ps",
        command_args=["docker", "ps", "--format", "{{.ID}}|{{.Image}}|{{.Names}}"],
        description="Query active Docker containers"
    ),
    "containers.podman_info": SafeCommand(
        identifier="containers.podman_info",
        command_args=["podman", "info", "--format", "json"],
        description="Query rootless Podman engine status"
    )
}

# Whitelist of safe, read-only system configuration files
SAFE_FILE_PATHS: Set[str] = {
    "/etc/os-release",
    "/etc/issue",
    "/etc/hostname",
    "/etc/machine-id",
    "/etc/passwd",
    "/etc/group",
    "/etc/shadow",
    "/etc/login.defs",
    "/etc/securetty",
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d/*.conf",
    "/etc/sudoers",
    "/etc/sudoers.d/*",
    "/etc/fstab",
    "/etc/security/limits.conf",
    "/etc/security/limits.d/*.conf",
    "/etc/sysctl.conf",
    "/etc/sysctl.d/*.conf",
    "/etc/pam.d/common-auth",
    "/etc/pam.d/common-password",
    "/etc/pam.d/common-account",
    "/etc/pam.d/common-session",
    "/etc/pam.d/system-auth",
    "/etc/pam.d/password-auth",
    "/etc/pam.d/login",
    "/etc/security/pwquality.conf",
    "/etc/audit/auditd.conf",
    "/etc/rsyslog.conf",
    "/etc/rsyslog.d/*.conf",
    "/etc/systemd/journald.conf",
    "/etc/docker/daemon.json"
}


def get_safe_command(identifier: str) -> Optional[SafeCommand]:
    return SAFE_COMMAND_REGISTRY.get(identifier)
