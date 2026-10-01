import typer
from cli.psv.client import psv_client
from cli.psv.output import console, create_table, print_error, print_json, print_panel

app = typer.Typer(help="Manage audit compliance profiles")


@app.command("list")
def list_profiles(format: str = typer.Option("table", "--format", "-f")):
    """List available assessment profiles."""
    try:
        profiles = psv_client.request("GET", "/profiles")
        if format == "json":
            print_json(profiles)
            return

        table = create_table(["ID", "Name", "Default", "Rules Count", "Description"], title="Security Profiles")
        for p in profiles:
            table.add_row(
                p["id"],
                p["name"],
                "[green]YES[/green]" if p.get("is_system_default") else "NO",
                str(p.get("rule_count", 0)),
                p["description"][:45]
            )
        console.print(table)
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


@app.command("show")
def show_profile(
    profile_id: str = typer.Argument(..., help="Profile ID"),
    format: str = typer.Option("table", "--format", "-f")
):
    """Show details of a specific assessment profile."""
    try:
        p = psv_client.request("GET", f"/profiles/{profile_id}")
        if format == "json":
            print_json(p)
            return

        text = f"""[bold]Profile ID:[/bold] {p['id']}
[bold]Name:[/bold] {p['name']}
[bold]System Default:[/bold] {p.get('is_system_default')}
[bold]Description:[/bold]
{p['description']}"""
        print_panel(text, title=f"Profile: {p['name']}")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)
