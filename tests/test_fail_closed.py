"""
Unit and Integration Tests for Fail-Closed Security Invariant (Requirement #5 & #20)

Invariant:
If a collector fails or times out:
collector failed -> must NOT become PASS.
It MUST become UNKNOWN with diagnostic failure reason recorded.
"""

import pytest
from backend.app.engine.rule_engine import RuleEngine
from backend.app.models.entities import RuleResult


def test_collector_success_produces_deterministic_pass_or_fail():
    engine = RuleEngine()
    # Mock successful observations
    observations = {
        "ssh.permit_root_login": "no",
        "ssh.password_authentication": False,
        "firewall.ufw_active": True,
        "sudo.has_wildcard_nopasswd": True,  # Non-compliant
    }
    failed_collectors = set()
    control_map = {
        "ssh.permit_root_login": "ssh",
        "ssh.password_authentication": "ssh",
        "firewall.ufw_active": "firewall",
        "sudo.has_wildcard_nopasswd": "sudo",
    }

    # 1. Compliant rule should evaluate to PASS
    rule_pass = {
        "id": "SSH-001",
        "control": "ssh.permit_root_login",
        "condition": {"operator": "in", "actual": "ssh.permit_root_login", "expected": ["no", "prohibit-password"]},
    }
    res_pass = engine.evaluate_rule(rule_pass, observations, failed_collectors, control_map)
    assert res_pass.result == RuleResult.PASS

    # 2. Non-compliant rule should evaluate to FAIL
    rule_fail = {
        "id": "SUDO-001",
        "control": "sudo.has_wildcard_nopasswd",
        "condition": {"operator": "equals", "actual": "sudo.has_wildcard_nopasswd", "expected": false},
    }
    res_fail = engine.evaluate_rule(rule_fail, observations, failed_collectors, control_map)
    assert res_fail.result == RuleResult.FAIL


def test_collector_failure_strictly_evaluates_to_unknown_never_pass():
    """
    Critical security test:
    When firewall collector fails, firewall rules must evaluate to UNKNOWN, NEVER PASS.
    """
    engine = RuleEngine()
    observations = {}  # No observations because collector crashed
    failed_collectors = {"firewall"}
    control_map = {
        "firewall.ufw_active": "firewall",
        "firewall.any_firewall_active": "firewall",
    }

    rule_firewall = {
        "id": "FW-001",
        "name": "Enable Host-Based Firewall",
        "control": "firewall.any_firewall_active",
        "condition": {"operator": "equals", "actual": "firewall.any_firewall_active", "expected": true},
    }

    res = engine.evaluate_rule(rule_firewall, observations, failed_collectors, control_map)

    # Must be UNKNOWN
    assert res.result == RuleResult.UNKNOWN
    # Must NEVER be PASS
    assert res.result != RuleResult.PASS
    # Failure diagnostics must be captured
    assert "Collector 'firewall' failed to execute" in res.message
    assert res.collector_failed is True


def test_missing_observation_evaluates_to_unknown():
    engine = RuleEngine()
    observations = {}  # Empty observations
    failed_collectors = set()
    control_map = {}

    rule = {
        "id": "NET-006",
        "control": "network.tcp_syncookies",
        "condition": {"operator": "equals", "actual": "network.tcp_syncookies", "expected": true},
    }

    res = engine.evaluate_rule(rule, observations, failed_collectors, control_map)
    assert res.result == RuleResult.UNKNOWN
    assert "Missing observation" in res.message
