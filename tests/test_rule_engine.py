import pytest
from backend.app.engine.rule_engine import RuleEngine
from backend.app.models.entities import RuleResult


def test_rule_engine_operators():
    engine = RuleEngine()
    obs = {
        "ssh.password_authentication": False,
        "ssh.max_auth_tries": 4,
        "identity.uid_zero_accounts": ["root"],
        "kernel.randomize_va_space": 2,
    }

    # Test equals
    res, _, _, _ = engine.evaluate_condition(
        {"operator": "equals", "actual": "ssh.password_authentication", "expected": False},
        obs, set(), {}
    )
    assert res == RuleResult.PASS

    # Test less_than_or_equal
    res, _, _, _ = engine.evaluate_condition(
        {"operator": "less_than_or_equal", "actual": "ssh.max_auth_tries", "expected": 4},
        obs, set(), {}
    )
    assert res == RuleResult.PASS

    # Test contains
    res, _, _, _ = engine.evaluate_condition(
        {"operator": "contains", "actual": "identity.uid_zero_accounts", "expected": "root"},
        obs, set(), {}
    )
    assert res == RuleResult.PASS


def test_rule_engine_collector_failure_behavior():
    """
    Requirement #20: If a collector failed, any rule evaluating that control must NOT become PASS;
    it must become UNKNOWN with reason recorded.
    """
    engine = RuleEngine()
    obs = {}
    failed_collectors = {"firewall"}
    control_map = {"firewall.ufw_active": "firewall"}

    res, _, _, msg = engine.evaluate_condition(
        {"operator": "equals", "actual": "firewall.ufw_active", "expected": True},
        obs, failed_collectors, control_map
    )
    assert res == RuleResult.UNKNOWN
    assert "Collector 'firewall' failed to execute" in msg
