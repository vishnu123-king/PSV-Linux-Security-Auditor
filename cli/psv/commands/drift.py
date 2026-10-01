from typing import Optional
import typer
from psv.client import psv_client
from psv.output import console, create_table, print_error, print_json, print_panel

app = typer.Typer(help="Detect configuration drift between historical audits")


@app.command("compare")
def compare_drift(
    host_id: str = typer.Argument(..., help="Host ID to compare drift for"),
    baseline: Optional[str] = typer.Option(None, "--baseline", "-b", help="Baseline assessment ID"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Target assessment ID (defaults to latest)"),
    format: str = typer.Option("table", "--format", "-f")
):
    """Compare two assessments for a host to detect unauthorized or drift changes."""
    try:
        params = {"host_id": host_id}
        if baseline:
            params["baseline_id"] = baseline
        if target:
            params["target_id"] = target

        drift = psv_client.request("GET", "/drift/compare", params=params)

        if format == "json":
            print_json(drift)
            return

        table = create_table(
            ["Control", "Category", "Previous Value", "Current Value", "Description"],
            title=f"Configuration Drift Analysis: {drift['host_name']} ({drift['total_changes']} changes)"
        )
        for c in drift.get("changes", []):
            table.add_row(
                c["control"],
                c["category"],
                str(c.get("previous_value")),
                f"[bold cyan]{c.get('current_value')}[/bold cyan]",
                c["description"]
            )
        console.print(table)
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)
