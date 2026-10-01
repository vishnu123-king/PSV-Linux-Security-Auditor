"""
Unit Tests for PSV Typer CLI Control Surface
Tests CLI commands: version, doctor, server status, host list, host add-local, audit list, audit run, finding list.
"""

from unittest.mock import MagicMock, patch
from typer.testing import CliRunner
from psv.main import cli_app

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(cli_app, ["version"])
    assert result.exit_code == 0
    assert "PSV Linux Security Auditor CLI" in result.output


def test_cli_config_show():
    result = runner.invoke(cli_app, ["config", "show"])
    assert result.exit_code == 0
    assert "PSV CLI Configuration" in result.output
    assert "Server API URL" in result.output


@patch("psv.commands.server.psv_client.request")
def test_cli_server_status(mock_request):
    mock_request.side_effect = [
        {"status": "healthy", "version": "1.0.0"},  # /health
        {
            "total_hosts": 1,
            "total_assessments": 1,
            "open_findings": 2,
            "critical_findings": 0,
            "average_compliance_score": 92.5,
        },  # /stats
    ]

    result = runner.invoke(cli_app, ["server", "status"])
    assert result.exit_code == 0
    assert "Server Health" in result.output
    assert "92.5%" in result.output


@patch("psv.commands.server.psv_client.request")
def test_cli_doctor(mock_request):
    mock_request.side_effect = [
        {"app": "PSV Linux Security Auditor", "version": "1.0.0"},  # /health
        {"database": "ready", "broker": "ready"},                  # /ready
        [{"id": "SSH-001"}, {"id": "SUDO-001"}]                   # /rules
    ]

    result = runner.invoke(cli_app, ["doctor"])
    assert result.exit_code == 0
    assert "Python Environment" in result.output
    assert "Control Plane API" in result.output
    assert "YAML Security Rules" in result.output


@patch("psv.commands.hosts.psv_client.request")
def test_cli_host_list_empty(mock_request):
    mock_request.return_value = []
    result = runner.invoke(cli_app, ["host", "list"])
    assert result.exit_code == 0
    assert "No hosts registered" in result.output


@patch("psv.commands.hosts.psv_client.request")
def test_cli_host_list(mock_request):
    mock_request.return_value = [
        {
            "id": "host-test-1",
            "name": "local-linux",
            "hostname": "127.0.0.1",
            "port": 22,
            "environment": "production",
            "os_distribution": "Linux",
            "os_version": "6.8.0",
            "last_assessment_status": "COMPLETED",
        }
    ]

    result = runner.invoke(cli_app, ["host", "list"])
    assert result.exit_code == 0
    assert "local-linux" in result.output
    assert "127.0.0.1" in result.output


@patch("psv.commands.hosts.psv_client.request")
def test_cli_host_add_local(mock_request):
    mock_request.side_effect = [
        # /hosts/local-discovery
        {
            "hostname": "my-local-machine",
            "addresses": ["192.168.1.50", "127.0.0.1"],
            "default_address": "192.168.1.50",
            "os_distribution": "Kali Linux",
            "os_version": "2026.2",
            "kernel_version": "6.8.0",
            "arch": "x86_64"
        },
        # POST /hosts
        {
            "id": "host-local-uuid-1234",
            "name": "my-local-machine",
            "hostname": "192.168.1.50",
            "port": 22,
            "environment": "production"
        },
        # POST /hosts/{id}/test
        {
            "success": True,
            "latency_ms": 1.2,
            "message": "Local machine diagnostics verified.",
            "banner": "Linux 6.8.0"
        }
    ]

    result = runner.invoke(cli_app, ["host", "add-local"])
    assert result.exit_code == 0
    assert "Successfully registered local host" in result.output
    assert "Kali Linux" in result.output


@patch("psv.commands.audits.psv_client.request")
def test_cli_audit_list_empty(mock_request):
    mock_request.return_value = []
    result = runner.invoke(cli_app, ["audit", "list"])
    assert result.exit_code == 0
    assert "No assessments found" in result.output


@patch("psv.commands.audits.psv_client.request")
def test_cli_audit_list(mock_request):
    mock_request.return_value = [
        {
            "id": "ass-001-uuid",
            "host_id": "host-1",
            "host_name": "local-linux",
            "profile_id": "cis-linux-server",
            "status": "COMPLETED",
            "compliance_score": 88.5,
            "critical_count": 0,
            "high_count": 2,
            "duration_seconds": 3.4
        }
    ]

    result = runner.invoke(cli_app, ["audit", "list"])
    assert result.exit_code == 0
    assert "local-linux" in result.output
    assert "88.5%" in result.output


@patch("psv.commands.findings.psv_client.request")
def test_cli_finding_list(mock_request):
    mock_request.return_value = [
        {
            "id": "find-1234",
            "severity": "CRITICAL",
            "rule_id": "SUDO-001",
            "title": "Restrict Wildcard NOPASSWD",
            "control": "sudo.has_wildcard_nopasswd",
            "status": "OPEN",
        }
    ]

    result = runner.invoke(cli_app, ["finding", "list"])
    assert result.exit_code == 0
    assert "SUDO-001" in result.output
    assert "CRITICAL" in result.output
