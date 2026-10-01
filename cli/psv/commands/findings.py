from typing import Optional
import typer
from cli.psv.client import psv_client
from cli.psv.output import (
    console,
    create_table,
    get_severity_styled,
    get_status_styled,
    print_error,
    print_json,
    print_panel,
    print_success,
)

app = typer.Typer(help="Inspect and triage security findings")


@app.command("list")
def list_findings(
    host_id: Optional[str] = typer.Option(None, "--host", "-h", help="Filter by host ID"),
    assessment_id: Optional[str] = typer.Option(None, "--assessment", "-a", help="Filter by assessment ID"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    status: Optional[str] = typer.Option(None, "--status", help="Filter by status (OPEN, ACKNOWLEDGED, SUPPRESSED, RESOLVED)"),
    format: str = typer.Option("table", "--format", "-f")
):
    """List security findings across managed hosts."""
    try:
        params = {}
        if host_id:
            params["host_id"] = host_id
        if assessment_id:
            params["assessment_id"] = assessment_id
        if severity:
            params["severity"] = severity
        if status:
            params["status"] = status

        findings = psv_client.request("GET", "/findings", params=params)

        if format == "json":
            print_json(findings)
            return

        table = create_table(["ID", "Severity", "Rule ID", "Title", "Control", "Status"], title="Security Findings")
        for f in findings:
            table.add_row(
                f["id"][:8],
                get_severity_styled(f["severity"]),
                f["rule_id"],
                f["title"][:40],
                f["control"],
                get_status_styled(f["status"])
            )
        console.print(table)
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


@app.command("show")
def show_finding(
    finding_id: str = typer.Argument(..., help="Finding ID"),
    format: str = typer.Option("table", "--format", "-f")
):
    """Inspect detailed rationale, evidence, and remediation for a finding."""
    try:
        f = psv_client.request("GET", f"/findings/{finding_id}")
        evidence = psv_client.request("GET", f"/findings/{finding_id}/evidence")

        if format == "json":
            print_json({"finding": f, "evidence": evidence})
            return

        details = f"""[bold]Finding ID:[/bold] {f['id']}
[bold]Rule:[/bold] {f['rule_id']} - {f['title']}
[bold]Severity:[/bold] {f['severity']} | [bold]Status:[/bold] {f['status']}
[bold]Control Key:[/bold] {f['control']}
[bold]Actual Value:[/bold] [red]{f['actual_value']}[/red]
[bold]Expected Value:[/bold] [green]{f['expected_value']}[/green]

[bold]Rationale:[/bold]
{f['rationale']}

[bold]Remediation Guidance:[/bold]
{f['remediation_guidance']}

[bold]Verification Method:[/bold]
{f['verification_method']}"""

        print_panel(details, title=f"Finding: {f['rule_id']}")

        if evidence:
            console.print("\n[bold]Collected Evidence:[/bold]")
            for ev in evidence:
                console.print(f"[dim]{ev.get('raw_output')}[/dim]")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


@app.command("acknowledge")
def ack_finding(finding_id: str = typer.Argument(..., help="Finding ID")):
    """Acknowledge a finding to mark it as under review."""
    try:
        res = psv_client.request("POST", f"/findings/{finding_id}/acknowledge", json_data={"acknowledged_by": "cli_operator"})
        print_success(f"Finding {finding_id} acknowledged.")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


@app.command("suppress")
def suppress_finding(
    finding_id: str = typer.Argument(..., help="Finding ID"),
    reason: str = typer.Option(..., "--reason", "-r", help="Business or technical justification for exception")
):
    """Mark a finding as suppressed (approved business risk acceptance)."""
    try:
        res = psv_client.request("POST", f"/findings/{finding_id}/suppress", json_data={"reason": reason})
        print_success(f"Finding {finding_id} suppressed. Reason: '{reason}'")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


@app.command("resolve")
def resolve_finding(finding_id: str = typer.Argument(..., help="Finding ID")):
    """Mark a finding as resolved."""
    try:
        res = psv_client.request("POST", f"/findings/{finding_id}/resolve")
        print_success(f"Finding {finding_id} marked as resolved.")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)
