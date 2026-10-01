import typer
from cli.psv.client import psv_client
from cli.psv.output import console, create_table, print_error, print_json, print_panel, print_success, print_warning

app = typer.Typer(help="Inspect PSV Auditor server status and diagnostics")


@app.command("status")
def server_status(format: str = typer.Option("table", "--format", "-f", help="Output format: table, json")):
    """Check connectivity and operational health of the FastAPI control plane."""
    try:
        health_data = psv_client.request("GET", "/health")
        stats_data = psv_client.request("GET", "/stats")

        if format == "json":
            print_json({"health": health_data, "stats": stats_data})
            return

        table = create_table(["Metric", "Value"], title="PSV Linux Security Auditor - Server Status")
        table.add_row("Server Health", f"[bold green]{health_data.get('status', 'unknown')}[/bold green]")
        table.add_row("Application Version", str(health_data.get("version", "1.0.0")))
        table.add_row("Total Managed Hosts", str(stats_data.get("total_hosts", 0)))
        table.add_row("Total Assessments Run", str(stats_data.get("total_assessments", 0)))
        table.add_row("Active Open Findings", str(stats_data.get("open_findings", 0)))
        table.add_row("Critical Findings", f"[bold red]{stats_data.get('critical_findings', 0)}[/bold red]")
        table.add_row("Average Compliance Score", f"{stats_data.get('average_compliance_score', 0.0)}%")
        console.print(table)

    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


def doctor_command(format: str = "table"):
    """Verify local environment, configuration, and API reachability."""
    results = []

    # 1. API endpoint check
    try:
        data = psv_client.request("GET", "/health")
        results.append(("Control Plane API", "OK", f"Connected ({psv_client.base_url})"))
    except Exception as e:
        results.append(("Control Plane API", "FAIL", str(e)))

    # 2. Database readiness check
    try:
        ready = psv_client.request("GET", "/ready")
        results.append(("PostgreSQL / SQLite Database", "OK", f"Status: {ready.get('database')}"))
    except Exception as e:
        results.append(("PostgreSQL / SQLite Database", "FAIL", str(e)))

    # 3. Rule pack check
    try:
        rules = psv_client.request("GET", "/rules")
        results.append(("YAML Security Rules Pack", "OK", f"Loaded {len(rules)} benchmark rules"))
    except Exception as e:
        results.append(("YAML Security Rules Pack", "FAIL", str(e)))

    if format == "json":
        print_json(results)
        return

    table = create_table(["Subsystem", "Health", "Diagnostics"], title="PSV System Doctor")
    for sys, st, diag in results:
        status_styled = "[bold green]PASS[/bold green]" if st == "OK" else "[bold red]FAIL[/bold red]"
        table.add_row(sys, status_styled, diag)
    console.print(table)
