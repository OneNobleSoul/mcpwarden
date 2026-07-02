"""Rendering of findings, for humans and for machines."""

from __future__ import annotations

import json
import sys

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


def render_json(findings: list[Finding], stream=None) -> None:
    stream = stream or sys.stdout
    payload = {
        "findings": [f.as_dict() for f in sort_findings(findings)],
        "summary": _counts(findings),
    }
    json.dump(payload, stream, indent=2)
    stream.write("\n")


def _counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1
    return counts


def exit_code(findings: list[Finding], fail_on: Severity | None) -> int:
    if fail_on is None:
        return 0
    return 1 if any(f.severity >= fail_on for f in findings) else 0


def _counts_line(findings: list[Finding]) -> str:
    counts: dict[Severity, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    parts = []
    for sev in reversed(list(Severity)):
        if counts.get(sev):
            parts.append(f"{counts[sev]} {sev.value}")
    return "[bold]" + ", ".join(parts) + "[/bold]"
