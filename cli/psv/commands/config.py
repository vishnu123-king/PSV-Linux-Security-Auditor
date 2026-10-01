"""
PSV CLI - Config Command

Hardening Requirements #52, #53:
- Never displays token secrets in 'psv config show'; outputs 'configured' or 'Not Set'.
"""

import typer
from cli.psv.config import CONFIG_FILE, cli_config
from cli.psv.output import console, print_panel, print_success

app = typer.Typer(help="Manage CLI configuration and credentials")


@app.command("show")
def config_show():
    """Display active CLI configuration (secrets are completely masked)."""
    masked_token = "configured" if cli_config.api_token else "Not Set"
    text = f"""[bold]Config File:[/bold] {CONFIG_FILE}
[bold]Server API URL:[/bold] {cli_config.api_url}
[bold]Auth Token:[/bold] {masked_token}"""
    print_panel(text, title="PSV CLI Configuration")


@app.command("set")
def config_set(
    key: str = typer.Argument(..., help="Config key e.g. server.url or auth.token"),
    value: str = typer.Argument(..., help="Value to set")
):
    """Set a CLI configuration setting."""
    try:
        cli_config.save_setting(key, value)
        print_success(f"Config setting '{key}' updated successfully.")
    except Exception as e:
        typer.secho(f"Error saving setting: {e}", fg=typer.colors.RED)
        raise typer.Exit(code=1)
