import json
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

console = Console()


def print_json(data: Any) -> None:
    console.print(json.dumps(data, indent=2, default=str))


def print_success(message: str) -> None:
    console.print(f"[bold green]✔[/bold green] {message}")


def print_warning(message: str) -> None:
    console.print(f"[bold yellow]▲[/bold yellow] {message}")


def print_error(message: str) -> None:
    console.print(f"[bold red]✖[/bold red] {message}")


def print_panel(content: str, title: Optional[str] = None, border_style: str = "cyan") -> None:
    console.print(Panel(content, title=title, border_style=border_style))


def create_table(columns: List[str], title: Optional[str] = None) -> Table:
    table = Table(title=title, show_header=True, header_style="bold cyan")
    for col in columns:
        table.add_column(col)
    return table


def get_severity_styled(severity: str) -> str:
    sev = str(severity).upper()
    if sev == "CRITICAL":
        return "[bold red]CRITICAL[/bold red]"
    elif sev == "HIGH":
        return "[red]HIGH[/red]"
    elif sev == "MEDIUM":
        return "[yellow]MEDIUM[/yellow]"
    elif sev == "LOW":
        return "[blue]LOW[/blue]"
    return f"[dim]{sev}[/dim]"


def get_status_styled(status: str) -> str:
    st = str(status).upper()
    if st in ("COMPLETED", "PASSED", "RESOLVED", "APPLIED"):
        return f"[bold green]{st}[/bold green]"
    elif st in ("FAILED", "FAIL"):
        return f"[bold red]{st}[/bold red]"
    elif st in ("RUNNING", "COLLECTING", "EVALUATING", "APPROVED"):
        return f"[bold cyan]{st}[/bold cyan]"
    elif st in ("QUEUED", "PENDING_APPROVAL", "ACKNOWLEDGED", "WARN"):
        return f"[bold yellow]{st}[/bold yellow]"
    return f"[dim]{st}[/dim]"
