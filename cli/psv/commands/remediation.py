from typing import Optional
import typer
from psv.client import psv_client
from psv.output import (
    console,
    create_table,
    get_status_styled,
    print_error,
    print_json,
    print_panel,
    print_success,
    print_warning,
)

app = typer.Typer(help="Plan, approve, execute, and rollback security remediation")


@app.command("plan")
def create_plan(
    finding_id: str = typer.Argument(..., help="Finding ID to plan hardening fix for"),
    format: str = typer.Option("table", "--format", "-f")
):
    """Generate a safe, dry-run remediation plan for a finding."""
    try:
        plan = psv_client.request("POST", "/remediation/plan", json_data={"finding_id": finding_id})

        if format == "json":
            print_json(plan)
            return

        cmd_list = "\n".join([f"  $ {c}" for c in plan.get("commands", [])])
        rollback_list = "\n".join([f"  $ {c}" for c in plan.get("rollback_commands", [])])

        text = f"""[bold]Remediation ID:[/bold] {plan['id']}
[bold]Status:[/bold] {plan['status']}
[bold]Target File:[/bold] {plan.get('target_file') or 'N/A'}
[bold]Backup Path:[/bold] {plan.get('backup_path') or 'N/A'}

[bold]Proposed Changes (Diff):[/bold]
[dim]{plan.get('proposed_diff') or 'None'}[/dim]

[bold]Commands To Execute (Requires Approval):[/bold]
{cmd_list}

[bold]Rollback Procedure:[/bold]
{rollback_list}"""

        print_panel(text, title=f"Remediation Plan: {plan['title']}")
        print_warning("Remediation is NOT executed automatically. An authorized administrator must run 'psv remediation approve <id>'.")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


@app.command("approve")
def approve_plan(
    remediation_id: str = typer.Argument(..., help="Remediation ID to approve"),
    approver: str = typer.Option("cli_admin", "--approver", "-a", help="Approving administrator name")
):
    """Provide explicit sign-off and approval for proposed hardening changes."""
    try:
        res = psv_client.request("POST", f"/remediation/{remediation_id}/approve", json_data={"approved_by": approver})
        print_success(f"Remediation {remediation_id} approved by {approver}. Ready for execution.")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


@app.command("execute")
def execute_plan(
    remediation_id: str = typer.Argument(..., help="Remediation ID to execute"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt")
):
    """Apply approved remediation commands on the target host."""
    if not confirm:
        sure = typer.confirm(f"Execute approved remediation commands for plan {remediation_id}?")
        if not sure:
            raise typer.Abort()

    try:
        res = psv_client.request("POST", f"/remediation/{remediation_id}/execute")
        print_success(f"Remediation applied successfully: {res.get('execution_output')}")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


@app.command("rollback")
def rollback_plan(
    remediation_id: str = typer.Argument(..., help="Remediation ID to rollback"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt")
):
    """Rollback applied remediation to restored backup configuration."""
    if not confirm:
        sure = typer.confirm(f"Rollback remediation {remediation_id} to previous state?")
        if not sure:
            raise typer.Abort()

    try:
        res = psv_client.request("POST", f"/remediation/{remediation_id}/rollback")
        print_success(f"Rollback complete: {res.get('execution_output')}")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)
