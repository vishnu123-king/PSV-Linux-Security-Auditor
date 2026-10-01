import typer
from cli.psv import __version__
from cli.psv.commands.audits import app as audits_app
from cli.psv.commands.config import app as config_app
from cli.psv.commands.drift import app as drift_app
from cli.psv.commands.findings import app as findings_app
from cli.psv.commands.hosts import app as hosts_app
from cli.psv.commands.profiles import app as profiles_app
from cli.psv.commands.remediation import app as remediation_app
from cli.psv.commands.reports import app as reports_app
from cli.psv.commands.rules import app as rules_app
from cli.psv.commands.server import app as server_app, doctor_command
from cli.psv.commands.verification import app as verification_app
from cli.psv.output import console, print_panel

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


@cli_app.command("doctor")
def doctor(format: str = typer.Option("table", "--format", "-f", help="Output format: table, json")):
    """Run diagnostics on API connectivity, database status, and rules."""
    doctor_command(format=format)


if __name__ == "__main__":
    cli_app()
