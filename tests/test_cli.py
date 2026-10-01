"""
Unit Tests for PSV Typer CLI Control Surface
Tests CLI commands: version, doctor, config show, server status, host list, finding list.
"""

from unittest.mock import MagicMock, patch
from typer.testing import CliRunner
from cli.psv.main import cli_app

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(cli_app, ["version"])
    assert result.exit_code == 0
    assert "PSV Linux Security Auditor CLI version" in result.output


def test_cli_config_show():
    result = runner.invoke(cli_app, ["config", "show"])
    assert result.exit_code == 0
    assert "PSV CLI Configuration" in result.output
    assert "Server API URL" in result.output


@patch("cli.psv.client.psv_client.request")
def test_cli_server_status(mock_request):
    mock_request.side_effect = [
        {"status": "healthy", "version": "1.0.0"},  # /health
        {
            "total_hosts": 3,
            "total_assessments": 5,
            "open_findings": 2,
            "critical_findings": 0,
            "average_compliance_score": 92.5,
        },  # /stats
    ]

    result = runner.invoke(cli_app, ["server", "status"])
    assert result.exit_code == 0
    assert "Server Health" in result.output
    assert "92.5%" in result.output


@patch("cli.psv.client.psv_client.request")
def test_cli_host_list(mock_request):
    mock_request.return_value = [
        {
            "id": "host-test-1",
            "name": "prod-db-01",
            "hostname": "192.168.1.10",
            "port": 22,
            "environment": "production",
            "os_distribution": "Ubuntu",
            "os_version": "24.04",
            "last_assessment_status": "COMPLETED",
        }
    ]

    result = runner.invoke(cli_app, ["host", "list"])
    assert result.exit_code == 0
    assert "prod-db-01" in result.output
    assert "192.168.1.10" in result.output


@patch("cli.psv.client.psv_client.request")
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
