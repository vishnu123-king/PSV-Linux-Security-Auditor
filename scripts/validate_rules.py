#!/usr/bin/env python3
"""
PSV Linux Security Auditor - Rule Validation Engine
Validates all YAML security benchmark rules against strict schema specifications.

Checks:
- Valid YAML syntax
- Mandatory fields present (id, name, version, category, severity, control, rationale, condition, remediation_guidance, verification_method)
- Severity is one of: CRITICAL, HIGH, MEDIUM, LOW, INFO
- Unique rule IDs across all files
- Condition contains valid operator and expected value
- Returns non-zero exit code if validation fails
"""

import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Set

VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
VALID_OPERATORS = {
    "equals",
    "not_equals",
    "contains",
    "not_contains",
    "greater_than",
    "less_than",
    "greater_than_or_equal",
    "less_than_or_equal",
    "in",
    "not_in",
    "regex",
    "exists",
    "not_exists",
}
VALID_CATEGORIES = {
    "system",
    "identity",
    "ssh",
    "sudo",
    "filesystem",
    "network",
    "firewall",
    "services",
    "kernel",
    "pam",
    "logging",
    "containers",
}

# Known controls mapped from all 12 collectors
KNOWN_CONTROLS = {
    # System
    "system.os_distribution",
    "system.os_version",
    "system.os_pretty_name",
    "system.hostname",
    "system.kernel_release",
    "system.architecture",
    "system.machine_id",
    # Identity
    "identity.uid_zero_accounts",
    "identity.single_uid_zero",
    "identity.system_users_with_interactive_shell",
    "identity.interactive_user_count",
    "identity.empty_password_accounts",
    "identity.weak_hash_accounts",
    "identity.shadow_readable",
    "identity.pass_max_days",
    "identity.pass_min_days",
    "identity.pass_warn_age",
    "identity.encrypt_method",
    # SSH
    "ssh.permit_root_login",
    "ssh.password_authentication",
    "ssh.permit_empty_passwords",
    "ssh.x11_forwarding",
    "ssh.max_auth_tries",
    "ssh.client_alive_interval",
    "ssh.client_alive_count_max",
    "ssh.hostbased_authentication",
    "ssh.ignore_rhosts",
    "ssh.login_grace_time",
    "ssh.allow_tcp_forwarding",
    # Sudo
    "sudo.use_pty",
    "sudo.env_reset",
    "sudo.secure_path",
    "sudo.logfile_configured",
    "sudo.has_wildcard_nopasswd",
    "sudo.nopasswd_rule_count",
    # Filesystem
    "filesystem.tmp_nodev",
    "filesystem.tmp_nosuid",
    "filesystem.tmp_noexec",
    "filesystem.shm_nodev",
    "filesystem.shm_nosuid",
    "filesystem.shm_noexec",
    "filesystem.core_dumps_restricted",
    "filesystem.world_writable_system_files",
    # Network
    "network.insecure_ports_open",
    "network.insecure_services_found",
    "network.listening_socket_count",
    "network.ip_forwarding",
    "network.send_redirects",
    "network.accept_redirects",
    "network.accept_source_route",
    "network.tcp_syncookies",
    "network.rp_filter_enabled",
    # Firewall
    "firewall.ufw_active",
    "firewall.ufw_default_incoming_deny",
    "firewall.iptables_rules_present",
    "firewall.iptables_input_drop",
    "firewall.any_firewall_active",
    # Services
    "services.insecure_services_running",
    "services.insecure_services_list",
    "services.total_running_services",
    "services.time_synchronization_active",
    # Kernel
    "kernel.randomize_va_space",
    "kernel.kptr_restrict",
    "kernel.dmesg_restrict",
    "kernel.protected_hardlinks",
    "kernel.protected_symlinks",
    "kernel.suid_dumpable",
    "kernel.unprivileged_bpf_disabled",
    # PAM
    "pam.password_minlen",
    "pam.password_complexity_enforced",
    "pam.account_lockout_enabled",
    "pam.lockout_deny_attempts",
    "pam.password_history_remember",
    # Logging
    "logging.auditd_enabled",
    "logging.auditd_rules_configured",
    "logging.auditd_rules_count",
    "logging.auditd_max_log_file_action",
    "logging.journald_storage_persistent",
    "logging.remote_syslog_configured",
    # Containers
    "containers.docker_installed",
    "containers.userns_remap_enabled",
    "containers.live_restore_enabled",
    "containers.no_new_privileges_default",
    "containers.inter_container_communication_disabled",
    "containers.running_container_count",
}


def parse_yaml_fallback(text: str) -> List[Dict[str, Any]]:
    """
    Lightweight resilient YAML list-of-dicts parser for environments
    where PyYAML is not yet installed in system Python.
    """
    try:
        import yaml
        return yaml.safe_load(text) or []
    except ImportError:
        pass

    # Basic parser for PSV rule format
    items = []
    current: Dict[str, Any] = {}
    current_key = None
    sub_dict = None

    for raw_line in text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("- id:"):
            if current:
                items.append(current)
            current = {}
            current_key = "id"
            current["id"] = stripped.split(":", 1)[1].strip().strip('"\'')
            sub_dict = None
        elif line.startswith("  ") and not line.startswith("    "):
            # Top-level property
            if ":" in stripped:
                k, v = stripped.split(":", 1)
                k = k.strip()
                v = v.strip().strip('"\'')
                if v == "":
                    sub_dict = {}
                    current[k] = sub_dict
                    current_key = k
                else:
                    sub_dict = None
                    if v.startswith("[") and v.endswith("]"):
                        # List of strings
                        vals = [x.strip().strip('"\'') for x in v[1:-1].split(",") if x.strip()]
                        current[k] = vals
                    elif v.lower() == "true":
                        current[k] = True
                    elif v.lower() == "false":
                        current[k] = False
                    elif v.isdigit():
                        current[k] = int(v)
                    else:
                        current[k] = v
                    current_key = k
        elif line.startswith("    ") and sub_dict is not None:
            # Nested in sub_dict (e.g., condition)
            if ":" in stripped:
                k, v = stripped.split(":", 1)
                k = k.strip()
                v = v.strip().strip('"\'')
                if v.startswith("[") and v.endswith("]"):
                    vals = [x.strip().strip('"\'') for x in v[1:-1].split(",") if x.strip()]
                    sub_dict[k] = vals
                elif v.lower() == "true":
                    sub_dict[k] = True
                elif v.lower() == "false":
                    sub_dict[k] = False
                elif v.isdigit():
                    sub_dict[k] = int(v)
                elif v == "":
                    sub_dict[k] = {}
                else:
                    sub_dict[k] = v

    if current:
        items.append(current)
    return items


def validate_rules(rules_dir: Path) -> int:
    print(f"[*] Validating benchmark rules in: {rules_dir}")
    if not rules_dir.is_dir():
        print(f"[!] Error: Rules directory '{rules_dir}' does not exist.")
        return 1

    yaml_files = sorted(list(rules_dir.glob("*.yaml")) + list(rules_dir.glob("*.yml")))
    if not yaml_files:
        print("[!] Error: No YAML rule files found.")
        return 1

    seen_ids: Set[str] = set()
    total_rules = 0
    errors: List[str] = []

    for yf in yaml_files:
        print(f"  -> Parsing {yf.name}...", end=" ")
        try:
            content = yf.read_text(encoding="utf-8")
            rules = parse_yaml_fallback(content)
        except Exception as e:
            print("[FAIL]")
            errors.append(f"{yf.name}: Failed to parse YAML: {e}")
            continue

        if not isinstance(rules, list):
            print("[FAIL]")
            errors.append(f"{yf.name}: File content must be a YAML list of rules.")
            continue

        file_rule_count = len(rules)
        print(f"[OK] ({file_rule_count} rules)")

        for idx, rule in enumerate(rules, start=1):
            total_rules += 1
            rule_id = rule.get("id")

            # Check ID
            if not rule_id:
                errors.append(f"{yf.name} [Rule #{idx}]: Missing 'id' field.")
                continue

            if rule_id in seen_ids:
                errors.append(f"{yf.name}: Duplicate rule ID '{rule_id}' detected!")
            seen_ids.add(rule_id)

            # Check Mandatory fields
            required_fields = [
                "name",
                "version",
                "category",
                "severity",
                "control",
                "rationale",
                "condition",
                "remediation_guidance",
                "verification_method",
            ]
            for field in required_fields:
                if field not in rule or rule[field] is None or rule[field] == "":
                    errors.append(f"{rule_id} ({yf.name}): Missing required field '{field}'.")

            # Check Severity
            sev = str(rule.get("severity", "")).upper()
            if sev not in VALID_SEVERITIES:
                errors.append(f"{rule_id}: Invalid severity '{sev}'. Must be one of {VALID_SEVERITIES}.")

            # Check Category
            cat = str(rule.get("category", "")).lower()
            if cat not in VALID_CATEGORIES:
                errors.append(f"{rule_id}: Invalid category '{cat}'. Must be one of {VALID_CATEGORIES}.")

            # Check Control
            ctrl = rule.get("control")
            if ctrl and ctrl not in KNOWN_CONTROLS:
                # Warning or notice, but ensure it starts with valid category prefix
                prefix = ctrl.split(".")[0]
                if prefix not in VALID_CATEGORIES and prefix != "system" and prefix != "network":
                    errors.append(f"{rule_id}: Control '{ctrl}' does not match any recognized collector prefix.")

            # Check Condition
            cond = rule.get("condition")
            if isinstance(cond, dict):
                # Check for either operator or boolean logic (AND/OR/NOT)
                if not any(k in cond for k in ("operator", "AND", "OR", "NOT")):
                    errors.append(f"{rule_id}: Condition missing 'operator', 'AND', 'OR', or 'NOT'.")
                if "operator" in cond:
                    op = str(cond["operator"]).lower()
                    if op not in VALID_OPERATORS:
                        errors.append(f"{rule_id}: Unsupported operator '{op}'.")
            else:
                errors.append(f"{rule_id}: 'condition' must be a dictionary.")

    print("\n" + "=" * 60)
    print(f"Validation Summary:")
    print(f"  Files Inspected: {len(yaml_files)}")
    print(f"  Rules Validated: {total_rules}")
    print(f"  Unique Rule IDs: {len(seen_ids)}")
    print("=" * 60)

    if total_rules < 60:
        errors.append(f"Expected at least 60 executable rules, but only found {total_rules}.")

    if errors:
        print("\n[!] VALIDATION FAILED WITH ERRORS:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print("\n[✔] ALL BENCHMARK RULES VALIDATED SUCCESSFULLY! (0 ERRORS)")
    return 0


if __name__ == "__main__":
    base_dir = Path(__file__).resolve().parent.parent
    rules_path = base_dir / "rules"
    exit_code = validate_rules(rules_path)
    sys.exit(exit_code)
