from typing import Optional
import typer
from cli.psv.client import psv_client
from cli.psv.output import console, create_table, get_severity_styled, print_error, print_json, print_panel

app = typer.Typer(help="Browse and inspect YAML security rules")


@app.command("list")
def list_rules(
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Filter by category (ssh, sudo, kernel, etc.)"),
    severity: Optional[str] = typer.Option(None, "--severity", "-s", help="Filter by severity"),
    format: str = typer.Option("table", "--format", "-f")
):
    """List loaded benchmark security rules."""
    try:
        params = {}
        if category:
            params["category"] = category
        if severity:
            params["severity"] = severity

        rules = psv_client.request("GET", "/rules", params=params)

        if format == "json":
            print_json(rules)
            return

        table = create_table(["ID", "Severity", "Category", "Name", "Control"], title=f"Security Rules ({len(rules)} total)")
        for r in rules:
            table.add_row(
                r["id"],
                get_severity_styled(r["severity"]),
                r["category"],
                r["name"][:45],
                r["control"]
            )
        console.print(table)
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


@app.command("show")
def show_rule(
    rule_id: str = typer.Argument(..., help="Rule identifier e.g. SSH-001"),
    format: str = typer.Option("table", "--format", "-f")
):
    """View full YAML specification, condition, and remediation for a rule."""
    try:
        r = psv_client.request("GET", f"/rules/{rule_id}")
        if format == "json":
            print_json(r)
            return

        text = f"""[bold]Rule ID:[/bold] {r['id']} (v{r.get('version', '1.0.0')})
[bold]Name:[/bold] {r['name']}
[bold]Severity:[/bold] {r['severity']} | [bold]Category:[/bold] {r['category']}
[bold]Target Control:[/bold] {r['control']}

[bold]Rationale:[/bold]
{r['rationale']}

[bold]Condition Specification:[/bold]
{r.get('condition')}

[bold]Remediation Guidance:[/bold]
{r['remediation_guidance']}

[bold]Verification Method:[/bold]
{r['verification_method']}"""

        print_panel(text, title=f"Rule: {r['id']}")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)
