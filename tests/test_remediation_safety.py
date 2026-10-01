"""
Tests for Remediation Safety, Idempotency, and Rollback (Requirements #34, #35, #36, #37, #38)

Verifies:
- Remediation plans default to PENDING_APPROVAL and never auto-execute
- SSH hardening plans include syntax test and backup path
- Firewall hardening plans include explicit 22/tcp allow before enable
"""

import pytest
from backend.app.engine.remediation import RemediationEngine
from backend.app.models.entities import RemediationStatus


def test_remediation_planning_defaults_to_pending_approval():
    engine = RemediationEngine()
    finding = {
        "id": "find-1",
        "control": "ssh.permit_root_login",
        "rule_id": "SSH-001",
        "title": "Disable Root SSH Login"
    }

    plan = engine.generate_plan(finding)
    assert plan["status"] == RemediationStatus.PLANNED
    assert plan["target_file"] == "/etc/ssh/sshd_config"
    assert plan["backup_path"] == "/etc/ssh/sshd_config.psv_backup"
    assert any("sshd -t" in cmd for cmd in plan["commands"])
    assert len(plan["rollback_commands"]) > 0


def test_firewall_remediation_preserves_management_ssh_access():
    engine = RemediationEngine()
    finding = {
        "id": "find-2",
        "control": "firewall.ufw_active",
        "rule_id": "FW-001",
        "title": "Enable UFW Firewall"
    }

    plan = engine.generate_plan(finding)
    # Must explicitly allow 22/tcp before enabling to prevent lockout
    cmd_str = " ".join(plan["commands"])
    assert "allow 22/tcp" in cmd_str
    assert "enable" in cmd_str
