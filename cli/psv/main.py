import sys
from pathlib import Path
import typer
from psv import __version__

# Ensure backend package is discoverable
for candidate in [Path.cwd(), Path(__file__).resolve().parent.parent.parent]:
    if (candidate / "backend").is_dir() and str(candidate) not in sys.path:
        sys.path.insert(0, str(candidate))
from psv.commands.audits import app as audits_app
from psv.commands.config import app as config_app
from psv.commands.drift import app as drift_app
from psv.commands.findings import app as findings_app
from psv.commands.hosts import app as hosts_app
from psv.commands.profiles import app as profiles_app
from psv.commands.remediation import app as remediation_app
from psv.commands.reports import app as reports_app
from psv.commands.rules import app as rules_app
from psv.commands.server import app as server_app, doctor_command
from psv.commands.verification import app as verification_app
from psv.output import console, print_panel

cli_app = typer.Typer(
    name="psv",
    help="PSV Linux Security Auditor - First-Class Command Line Control Surface",
    no_args_is_help=True
)

# Register subcommands
cli_app.add_typer(server_app, name="server")
cli_app.add_typer(hosts_app, name="host")
cli_app.add_typer(audits_app, name="audit")
cli_app.add_typer(findings_app, name="finding")
cli_app.add_typer(rules_app, name="rule")
cli_app.add_typer(profiles_app, name="profile")
cli_app.add_typer(drift_app, name="drift")
cli_app.add_typer(reports_app, name="report")
cli_app.add_typer(remediation_app, name="remediation")
cli_app.add_typer(verification_app, name="verify")
cli_app.add_typer(config_app, name="config")


@cli_app.command("version")
def version():
    """Print the PSV CLI and auditor platform version."""
    console.print(f"[bold cyan]PSV Linux Security Auditor CLI[/bold cyan] version [bold green]{__version__}[/bold green]")


@cli_app.command("start")
def start(
    host: str = typer.Option("0.0.0.0", "--host", "-h", help="Host network interface to bind"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to listen on"),
    reload: bool = typer.Option(False, "--reload", "-r", help="Enable auto-reload for development")
):
    """Start the FastAPI backend control plane server directly."""
    import uvicorn
    app_dir = None
    for candidate in [Path.cwd(), Path(__file__).resolve().parent.parent.parent]:
        if (candidate / "backend").is_dir():
            app_dir = str(candidate)
            if app_dir not in sys.path:
                sys.path.insert(0, app_dir)
            break

    console.print(f"[bold green]Starting PSV Control Plane on http://{host}:{port}...[/bold green]")
    uvicorn.run("backend.app.main:app", host=host, port=port, reload=reload, app_dir=app_dir)


@cli_app.command("doctor")
def doctor(format: str = typer.Option("table", "--format", "-f", help="Output format: table, json")):
    """Run diagnostics on API connectivity, database status, and rules."""
    doctor_command(format=format)


if __name__ == "__main__":
    cli_app()
