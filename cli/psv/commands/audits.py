import time
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

app = typer.Typer(help="Execute and inspect security assessments")


def resolve_host_id(host_query: str) -> str:
    """Resolves a host name or ID prefix to an exact Host ID."""
    try:
        hosts = psv_client.request("GET", "/hosts")
        for h in hosts:
            if h["id"] == host_query or h["id"].startswith(host_query) or h["name"].lower() == host_query.lower():
                return h["id"]
    except Exception:
        pass
    return host_query


@app.command("list")
def list_audits(
    host: Optional[str] = typer.Option(None, "--host", "-h", help="Filter by host ID or host name"),
    status: Optional[str] = typer.Option(None, "--status", "-s", help="Filter by status (QUEUED, RUNNING, COMPLETED, FAILED)"),
    limit: Optional[int] = typer.Option(None, "--limit", "-l", help="Limit number of assessments returned"),
    format: str = typer.Option("table", "--format", "-f")
):
    """List historical and active security audits."""
    try:
        host_id = resolve_host_id(host) if host else None
        params = {}
        if host_id:
            params["host_id"] = host_id
        if status:
            params["status"] = status

        audits = psv_client.request("GET", "/assessments", params=params)

        if limit and isinstance(audits, list):
            audits = audits[:limit]

        if format == "json":
            print_json(audits)
            return

        if not audits:
            console.print("[dim]No assessments found.[/dim]")
            console.print("Run [bold cyan]psv audit run <host_id>[/bold cyan] to execute a security assessment.")
            return

        table = create_table(
            ["ID", "Host", "Profile", "Status", "Score", "Critical", "High", "Duration"],
            title="Security Assessments"
        )
        for a in audits:
            score_str = f"{a.get('compliance_score', 0)}%"
            dur_str = f"{a.get('duration_seconds', 0):.1f}s" if a.get("duration_seconds") else "N/A"
            table.add_row(
                a["id"][:8],
                a.get("host_name") or a["host_id"][:8],
                a["profile_id"],
                get_status_styled(a["status"]),
                score_str,
                f"[bold red]{a.get('critical_count', 0)}[/bold red]",
                f"[red]{a.get('high_count', 0)}[/red]",
                dur_str
            )
        console.print(table)
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


@app.command("run")
def run_audit(
    host_id: str = typer.Argument(..., help="Host ID, prefix, or name to audit"),
    profile: str = typer.Option("cis-linux-server", "--profile", "-p", help="Security profile ID"),
    wait: bool = typer.Option(True, "--wait/--no-wait", help="Block and stream progress until complete"),
    format: str = typer.Option("table", "--format", "-f")
):
    """Trigger a new security assessment job against a target host."""
    try:
        resolved_id = resolve_host_id(host_id)
        payload = {
            "host_id": resolved_id,
            "profile_id": profile,
            "triggered_by": "cli"
        }
        res = psv_client.request("POST", "/assessments", json_data=payload)
        assessment_id = res["id"]

        if not wait:
            if format == "json":
                print_json(res)
            else:
                print_success(f"Assessment enqueued: {assessment_id[:8]} (Status: {res['status']})")
                console.print(f"Run [bold cyan]psv audit status {assessment_id[:8]}[/bold cyan] to check status.")
            return

        console.print(f"[bold cyan]▶[/bold cyan] Assessment initiated: [bold]{assessment_id[:8]}[/bold]. Streaming execution status...")

        # Poll status until complete or failed
        last_progress = -1
        while True:
            current = psv_client.request("GET", f"/assessments/{assessment_id}")
            st = current["status"]
            pct = current.get("progress_percent", 0)
            col = current.get("current_collector")

            if pct != last_progress:
                console.print(f"  [dim]Progress: {pct}% | Collector: {col or 'initializing'} | State: {st}[/dim]")
                last_progress = pct

            if st in ("COMPLETED", "FAILED", "CANCELLED"):
                if format == "json":
                    print_json(current)
                    return

                if st == "COMPLETED":
                    print_success(f"Assessment completed in {current.get('duration_seconds', 0):.2f}s!")
                    summary_box = f"""[bold]Target Host:[/bold] {current.get('host_name')}
[bold]Status:[/bold] {current['status']}
[bold]Compliance Score:[/bold] {current.get('compliance_score')}%

[bold]Controls Summary:[/bold]
  [green]PASS:[/green]    {current.get('passed_rules', 0)}
  [red]FAIL:[/red]    {current.get('failed_rules', 0)}
  [yellow]WARN:[/yellow]    {current.get('warn_rules', 0)}
  [dim]UNKNOWN:[/dim] {current.get('unknown_rules', 0)}

[bold]Findings Severity:[/bold]
  [bold red]CRITICAL:[/bold red] {current.get('critical_count', 0)}
  [red]HIGH:[/red]     {current.get('high_count', 0)}
  [yellow]MEDIUM:[/yellow]   {current.get('medium_count', 0)}
  [blue]LOW:[/blue]      {current.get('low_count', 0)}"""
                    print_panel(summary_box, title=f"Audit Summary #{assessment_id[:8]}")
                    console.print(f"Run [bold cyan]psv finding list --assessment {assessment_id[:8]}[/bold cyan] to view detailed findings.")
                else:
                    print_error(f"Assessment terminated in state: {st}. Error: {current.get('error_message')}")
                break

            time.sleep(1.0)

    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


@app.command("status")
def audit_status(
    assessment_id: str = typer.Argument(..., help="Assessment ID or prefix"),
    format: str = typer.Option("table", "--format", "-f")
):
    """Inspect state and results of a specific assessment."""
    try:
        current = psv_client.request("GET", f"/assessments/{assessment_id}")
        if format == "json":
            print_json(current)
            return

        summary = f"""[bold]Assessment ID:[/bold] {current['id']}
[bold]Host ID:[/bold] {current['host_id']} ({current.get('host_name') or 'N/A'})
[bold]Profile:[/bold] {current['profile_id']}
[bold]Status:[/bold] {current['status']} ({current.get('progress_percent', 0)}%)
[bold]Compliance Score:[/bold] {current.get('compliance_score', 0)}%
[bold]Rules Evaluated:[/bold] {current.get('total_rules', 0)} (Passed: {current.get('passed_rules')}, Failed: {current.get('failed_rules')})
[bold]Critical Findings:[/bold] {current.get('critical_count', 0)}
[bold]High Findings:[/bold] {current.get('high_count', 0)}"""
        print_panel(summary, title="Assessment Status")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


@app.command("cancel")
def cancel_audit(assessment_id: str = typer.Argument(..., help="Assessment ID to cancel")):
    """Cancel a running or queued assessment."""
    try:
        res = psv_client.request("POST", f"/assessments/{assessment_id}/cancel")
        print_success(f"Assessment {assessment_id} cancelled.")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)
