from typing import Optional
import typer
from cli.psv.client import psv_client
from cli.psv.output import console, create_table, print_error, print_json, print_panel, print_success

app = typer.Typer(help="Manage authorized target Linux hosts")


@app.command("list")
def list_hosts(
    env: Optional[str] = typer.Option(None, "--env", "-e", help="Filter by environment (production, staging, dev)"),
    format: str = typer.Option("table", "--format", "-f", help="Output format: table, json")
):
    """List all registered and authorized Linux security audit targets."""
    try:
        params = {"environment": env} if env else {}
        hosts = psv_client.request("GET", "/hosts", params=params)

        if format == "json":
            print_json(hosts)
            return

        table = create_table(["ID", "Name", "Hostname", "Port", "Environment", "OS", "Last Status"], title="Authorized Linux Targets")
        for h in hosts:
            table.add_row(
                h["id"][:8],
                h["name"],
                h["hostname"],
                str(h["port"]),
                h["environment"],
                f"{h.get('os_distribution') or 'Linux'} {h.get('os_version') or ''}",
                h.get("last_assessment_status") or "UNAUDITED"
            )
        console.print(table)
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


@app.command("add")
def add_host(
    name: str = typer.Option(..., "--name", "-n", help="Display name for the target host"),
    hostname: str = typer.Option(..., "--hostname", "-H", help="IP address or FQDN"),
    port: int = typer.Option(22, "--port", "-p", help="SSH port"),
    environment: str = typer.Option("production", "--env", "-e", help="Environment (production, staging, dev)"),
    username: str = typer.Option("root", "--user", "-u", help="SSH login username"),
    format: str = typer.Option("table", "--format", "-f")
):
    """Onboard and register a new authorized Linux target."""
    try:
        payload = {
            "name": name,
            "hostname": hostname,
            "port": port,
            "environment": environment,
            "username": username,
            "tags": {"registered_via": "cli"}
        }
        res = psv_client.request("POST", "/hosts", json_data=payload)
        if format == "json":
            print_json(res)
        else:
            print_success(f"Registered target host '{res['name']}' (ID: {res['id']}).")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


@app.command("show")
def show_host(
    host_id: str = typer.Argument(..., help="Host ID or prefix"),
    format: str = typer.Option("table", "--format", "-f")
):
    """Show detailed metadata and audit history for a specific host."""
    try:
        host = psv_client.request("GET", f"/hosts/{host_id}")
        if format == "json":
            print_json(host)
            return

        info = f"""[bold]Host ID:[/bold] {host['id']}
[bold]Name:[/bold] {host['name']}
[bold]Hostname/IP:[/bold] {host['hostname']}:{host['port']}
[bold]Environment:[/bold] {host['environment']}
[bold]OS:[/bold] {host.get('os_distribution')} {host.get('os_version')} ({host.get('kernel_version') or 'N/A'})
[bold]Last Seen:[/bold] {host.get('last_seen') or 'Never'}
[bold]Last Assessment Status:[/bold] {host.get('last_assessment_status') or 'None'}"""
        print_panel(info, title=f"Host Details: {host['name']}")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


@app.command("test")
def test_host(
    host_id: str = typer.Argument(..., help="Host ID to test SSH connectivity for"),
    format: str = typer.Option("table", "--format", "-f")
):
    """Verify SSH credentials and reachability to target host."""
    try:
        res = psv_client.request("POST", f"/hosts/{host_id}/test")
        if format == "json":
            print_json(res)
            return

        if res["success"]:
            print_success(f"SSH Reachability OK: {res['message']} (Latency: {res.get('latency_ms', 0)}ms)")
            if res.get("banner"):
                console.print(f"  [dim]Banner: {res['banner']}[/dim]")
        else:
            print_error(f"SSH Test FAILED: {res['message']}")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


@app.command("remove")
def remove_host(
    host_id: str = typer.Argument(..., help="Host ID to delete"),
    confirm: bool = typer.Option(False, "--yes", "-y", help="Skip confirmation prompt")
):
    """Delete a managed host from the auditor registry."""
    if not confirm:
        sure = typer.confirm(f"Are you sure you want to remove host {host_id} and all its audit history?")
        if not sure:
            raise typer.Abort()

    try:
        psv_client.request("DELETE", f"/hosts/{host_id}")
        print_success(f"Successfully deleted host {host_id}.")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)
