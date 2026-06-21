"""Human-readable rendering of findings."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .findings import Finding, Severity, sort_findings

_STYLE = {
    Severity.INFO: "dim",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold white on red",
}


def _severity_cell(sev: Severity) -> Text:
    return Text(sev.value.upper(), style=_STYLE.get(sev, ""))


def render(findings: list[Finding], console: Console | None = None) -> None:
    console = console or Console()
    if not findings:
        console.print("[green]no issues found[/green]")
        return

    findings = sort_findings(findings)
    table = Table(show_lines=False, expand=True, pad_edge=False)
    table.add_column("sev", no_wrap=True)
    table.add_column("server", no_wrap=True, style="bold")
    table.add_column("rule", no_wrap=True, style="dim")
    table.add_column("what")

    for f in findings:
        table.add_row(_severity_cell(f.severity), f.server or "-", f.rule, f.title)

    console.print(table)
    console.print()
    for f in findings:
        where = f"  ({f.location})" if f.location else ""
        console.print(f"[{_STYLE.get(f.severity, '')}]{f.severity.value}[/] "
                      f"{f.rule}{where}\n    {f.detail}\n")

    console.print(_counts_line(findings))


def _counts_line(findings: list[Finding]) -> str:
    counts: dict[Severity, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    parts = []
    for sev in reversed(list(Severity)):
        if counts.get(sev):
            parts.append(f"{counts[sev]} {sev.value}")
    return "[bold]" + ", ".join(parts) + "[/bold]"
