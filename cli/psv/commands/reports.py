from typing import Optional
import typer
from psv.client import psv_client
from psv.output import console, create_table, print_error, print_json, print_panel, print_success

app = typer.Typer(help="Generate compliance audit reports")


@app.command("generate")
def generate_report(
    assessment_id: str = typer.Argument(..., help="Assessment ID"),
    format: str = typer.Option("json", "--format", "-f", help="Report format: json or html"),
    output_file: Optional[str] = typer.Option(None, "--output", "-o", help="Save report to file path")
):
    """Generate a formal compliance report (JSON or HTML)."""
    try:
        payload = {"assessment_id": assessment_id, "format": format}
        rep = psv_client.request("POST", "/reports/generate", json_data=payload)

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(rep["content"])
            print_success(f"Report saved to {output_file} (Format: {format}).")
        else:
            if format == "json":
                console.print(rep["content"])
            else:
                print_success(f"Generated HTML report ID {rep['id']}. Use --output report.html to save.")
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)


@app.command("show")
def show_report(report_id: str = typer.Argument(..., help="Report ID")):
    """View report summary metadata."""
    try:
        rep = psv_client.request("GET", f"/reports/{report_id}")
        print_panel(
            f"""[bold]Report ID:[/bold] {rep['id']}
[bold]Assessment ID:[/bold] {rep['assessment_id']}
[bold]Format:[/bold] {rep['format']}
[bold]Generated At:[/bold] {rep['generated_at']}
[bold]Summary:[/bold] {rep['summary']}""",
            title="Audit Report Metadata"
        )
    except Exception as e:
        print_error(str(e))
        raise typer.Exit(code=1)
