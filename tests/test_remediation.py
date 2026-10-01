from backend.app.engine.remediation import remediation_engine
from backend.app.models.entities import RemediationStatus


def test_remediation_plan_generation():
    finding = {
        "id": "find-123",
        "control": "ssh.permit_root_login",
        "rule_id": "SSH-001",
        "title": "Disable SSH Root Login",
        "remediation_guidance": "Set PermitRootLogin no"
    }

    plan = remediation_engine.generate_plan(finding)
    assert plan["status"] == RemediationStatus.PLANNED
    assert plan["target_file"] == "/etc/ssh/sshd_config"
    assert len(plan["commands"]) > 0
    assert len(plan["rollback_commands"]) > 0
    assert "PermitRootLogin no" in plan["proposed_diff"]
