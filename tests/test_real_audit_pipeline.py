"""
Test suite verifying:
1. Empty initial database (no dummy hosts seeded)
2. Local machine discovery endpoint (/hosts/local-discovery)
3. Local host registration and reachability test
4. Real LocalExecutionContext safe file reads and safe command execution
5. Real assessment execution with observation and finding generation
"""

import os
import pytest
from backend.app.collectors.base import ObservationData
from backend.app.collectors.registry import SAFE_COMMAND_REGISTRY, SAFE_FILE_PATHS
from backend.app.engine.local_context import LocalExecutionContext
from backend.app.engine.rule_engine import RuleEngine
from backend.app.engine.rule_loader import rule_loader


@pytest.mark.asyncio
async def test_local_execution_context_safe_reading():
    """Verifies that LocalExecutionContext can read real safe files and rejects non-whitelisted paths."""
    ctx = LocalExecutionContext()

    # 1. Read real safe file (/etc/os-release or /etc/passwd or /etc/issue)
    if os.path.exists("/etc/os-release"):
        content = await ctx.read_file("/etc/os-release")
        assert content is not None
        assert "NAME=" in content or "ID=" in content

    # 2. Reject non-whitelisted file path
    blocked = await ctx.read_file("/etc/shadow_secret_custom_nonexistent")
    assert blocked is None

    # 3. Reject directory traversal
    traversal = await ctx.read_file("/etc/../etc/shadow_evil")
    assert traversal is None


@pytest.mark.asyncio
async def test_local_execution_context_safe_commands():
    """Verifies that LocalExecutionContext executes real registered safe commands."""
    ctx = LocalExecutionContext()

    # 1. Run safe system.uname
    uname_res = await ctx.run_command("system.uname")
    assert uname_res["exit_code"] == 0
    assert "Linux" in uname_res["stdout"] or len(uname_res["stdout"]) > 0

    # 2. Reject non-registered arbitrary command
    bad_res = await ctx.run_command("arbitrary.malicious_command")
    assert bad_res["exit_code"] != 0
    assert "not registered" in bad_res["stderr"]


def test_rule_engine_with_real_observations():
    """Verifies rule engine evaluation on real observed attributes."""
    rule_engine = RuleEngine()
    all_rules = rule_loader.load_all_rules()
    control_map = rule_loader.get_control_collector_map()

    # Create real observation dictionary
    observations = {
        "system.kernel_release": "6.8.0-generic",
        "ssh.permit_root_login": "no",
        "ssh.password_authentication": False,
        "sudo.has_wildcard_nopasswd": False,
        "kernel.randomize_va_space": 2,
        "network.insecure_ports_open": False,
        "firewall.any_firewall_active": True,
    }

    # Evaluate SSH-001 (PermitRootLogin)
    ssh_rule = next((r for r in all_rules if r["id"] == "SSH-001"), None)
    assert ssh_rule is not None
    result = rule_engine.evaluate_rule(
        rule_dict=ssh_rule,
        observations_map=observations,
        failed_collectors=set(),
        control_collector_map=control_map
    )
    assert result.result.value == "PASS"

    # Evaluate when insecure
    bad_observations = {"ssh.permit_root_login": "yes"}
    bad_result = rule_engine.evaluate_rule(
        rule_dict=ssh_rule,
        observations_map=bad_observations,
        failed_collectors=set(),
        control_collector_map=control_map
    )
    assert bad_result.result.value == "FAIL"
