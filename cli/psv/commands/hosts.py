import socket
from typing import Optional
import typer
from psv.client import psv_client
from psv.output import console, create_table, print_error, print_json, print_panel, print_success, print_warning

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

        if not hosts:
            console.print("[dim]No hosts registered.[/dim]")
            console.print("Run [bold cyan]psv host add-local[/bold cyan] to audit this machine, or [bold cyan]psv host add[/bold cyan] for remote targets.")
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


@app.command("add-local")
def add_local_host(
    name: Optional[str] = typer.Option(None, "--name", "-n", help="Display name for local machine"),
    address: Optional[str] = typer.Option(None, "--address", "-a", help="Explicit network IP or 127.0.0.1"),
    environment: str = typer.Option("production", "--env", "-e", help="Environment (production, staging, dev)"),
    format: str = typer.Option("table", "--format", "-f")
):
    """Onboard and register this local Linux machine for security auditing."""
    try:
        # Discover local system facts from control plane
        discovery = psv_client.request("GET", "/hosts/local-discovery")
        host_name = name or discovery.get("hostname") or socket.gethostname()
        chosen_address = address or discovery.get("default_address") or "127.0.0.1"

        payload = {
            "name": host_name,
            "hostname": chosen_address,
            "port": 22,
            "environment": environment,
            "tags": {
                "local": True,
                "connector": "local",
                "registered_via": "cli",
                "detected_os": discovery.get("os_distribution"),
                "kernel": discovery.get("kernel_version")
            }
        }

        res = psv_client.request("POST", "/hosts", json_data=payload)
        host_id = res["id"]

        # Run connection/diagnostic test
        test_res = psv_client.request("POST", f"/hosts/{host_id}/test")

        if format == "json":
            print_json({"host": res, "test": test_res})
            return

        print_success(f"Successfully registered local host '{res['name']}' (ID: {host_id[:8]}).")
        console.print(f"  [dim]Detected OS:[/dim] [bold]{discovery.get('os_distribution')} {discovery.get('os_version')}[/bold]")
        console.print(f"  [dim]Kernel:[/dim]      [bold]{discovery.get('kernel_version')}[/bold] ({discovery.get('arch')})")
        console.print(f"  [dim]Address:[/dim]     [bold]{chosen_address}[/bold]")

        if test_res.get("success"):
            print_success(f"Local diagnostics check: {test_res.get('message')}")
        else:
            print_warning(f"Diagnostics check warning: {test_res.get('message')}")

        console.print(f"\n[bold cyan]▶ Next Step:[/bold cyan] Run your first security audit:")
        console.print(f"  [bold green]psv audit run {host_id[:8]} --profile cis-linux-server[/bold green]\n")
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
            print_success(f"Registered target host '{res['name']}' (ID: {res['id'][:8]}).")
            console.print(f"Run [bold cyan]psv host test {res['id'][:8]}[/bold cyan] to verify SSH reachability.")
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
[bold]OS:[/bold] {host.get('os_distribution') or 'Linux'} {host.get('os_version') or ''} ({host.get('kernel_version') or 'N/A'})
[bold]Last Seen:[/bold] {host.get('last_seen') or 'Never'}
[bold]Last Assessment Status:[/bold] {host.get('last_assessment_status') or 'None'}"""
        print_panel(info, title=f"Host Details: {host['name']}")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


@app.command("test")
def test_host(
    host_id: str = typer.Argument(..., help="Host ID to test connectivity for"),
    format: str = typer.Option("table", "--format", "-f")
):
    """Verify connectivity, credentials, and collector reachability to target host."""
    try:
        res = psv_client.request("POST", f"/hosts/{host_id}/test")
        if format == "json":
            print_json(res)
            return

        if res.get("success"):
            print_success(f"Reachability OK: {res.get('message', 'Connected')} (Latency: {res.get('latency_ms', 0)}ms)")
            if res.get("banner"):
                console.print(f"  [dim]Banner:[/dim] [italic]{res['banner']}[/italic]")
        else:
            print_error(f"Host Test FAILED: {res.get('message', 'Unknown error')}")
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
