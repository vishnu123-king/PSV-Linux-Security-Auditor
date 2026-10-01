import typer
from psv.client import psv_client
from psv.output import console, create_table, print_error, print_json, print_panel, print_success

app = typer.Typer(help="Trigger verification re-check of a finding")


@app.callback(invoke_without_command=True)
def verify_finding(
    finding_id: str = typer.Argument(..., help="Finding ID to verify"),
    format: str = typer.Option("table", "--format", "-f")
):
    """Re-evaluate the specific security control against target host to confirm fix."""
    try:
        res = psv_client.request("POST", f"/verify/{finding_id}")

        if format == "json":
            print_json(res)
            return

        st = res["status"]
        if st == "PASSED":
            print_success(f"Verification PASSED for finding {finding_id}!")
            console.print(f"  [dim]Command:[/dim] {res['command_used']}")
            console.print(f"  [dim]Output:[/dim]  {res['output']}")
        else:
            print_error(f"Verification FAILED. Target remains in non-compliant state.")
            console.print(f"  [dim]Command:[/dim] {res['command_used']}")
            console.print(f"  [dim]Output:[/dim]  {res['output']}")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)
