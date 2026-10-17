"""Interactive Project 5 Reporting UI for Hunt_Chain."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from rich.box import ROUNDED
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hunt_chain_core.project_5_execution import run_project_5
from hunt_chain_core.ui_styling import (
    GLYPH_ARROW,
    GLYPH_FAIL,
    GLYPH_INFO,
    GLYPH_PROMPT,
    GLYPH_SUCCESS,
    GLYPH_WARN,
    console,
    format_severity,
)


def _run_project_5(
    manager: Any,
    assessment_name: str,
) -> None:
    """Execute Project 5 reporting with Rich console output."""
    header = Text()
    header.append("Stage 5: Findings & Reporting Manager\n", style="bold cyan")
    header.append("Generate submission-ready vulnerability report (Markdown & JSON)", style="dim white")
    console.print(Panel(header, border_style="cyan", box=ROUNDED, padding=(0, 2)))

    try:
        confirm = input(f"\nGenerate vulnerability report for '{assessment_name}'? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        console.print("\n[dim]Report generation cancelled.[/dim]")
        return

    if confirm in ("n", "no"):
        console.print("[dim]Report generation cancelled.[/dim]")
        return

    console.print(f"\n{GLYPH_INFO} Synthesizing pipeline findings, ScopeGuard authorization, and validation proofs...")

    try:
        md_path, json_path, report_data = run_project_5(
            assessment_name=assessment_name,
            runs_directory=manager.runs_directory,
        )
    except Exception as exc:
        console.print(f"\n{GLYPH_FAIL} [red]Report generation failed: {exc}[/red]")
        return

    ex = report_data.executive_summary

    # Summary Panel
    summary_text = Text()
    summary_text.append(f"Target: ", style="bold white")
    summary_text.append(f"{ex.target}\n", style="cyan")
    summary_text.append(f"Scope Reference: ", style="bold white")
    summary_text.append(f"{ex.scope_reference}\n", style="yellow")
    summary_text.append(f"Severity Distribution: ", style="bold white")
    summary_text.append(f"{ex.severity_bar}\n\n", style="bold green")

    summary_text.append(f"Generated Submission-Ready Artifacts:\n", style="bold white")
    summary_text.append(f"  • Markdown: [bold cyan]{md_path}[/bold cyan]\n")
    summary_text.append(f"  • JSON:     [bold cyan]{json_path}[/bold cyan]\n")

    console.print()
    console.print(Panel(summary_text, title=f"[bold green]{GLYPH_SUCCESS} Report Generation Completed[/bold green]", border_style="green", box=ROUNDED))

    # Findings overview table
    table = Table(
        title="[bold cyan]Report Findings Breakdown[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        padding=(0, 1),
    )
    table.add_column("Category", style="bold white", width=30)
    table.add_column("Count", style="bold yellow", justify="right", width=8)
    table.add_column("Triage Action", style="dim white")

    table.add_row("Confirmed Vulnerabilities", str(ex.confirmed_count), "Ready for bug bounty submission")
    table.add_row("Candidates for Manual Review", str(ex.not_confirmed_count), "Requires manual verification before reporting")
    table.add_row("Manual-Only Checklist Items", str(ex.manual_only_count), "Actionable items for manual security audit")

    console.print(table)
    console.print(f"\n{GLYPH_INFO} Tip: You can review [bold cyan]{md_path.name}[/bold cyan] directly in any Markdown viewer before submitting to HackerOne or Bugcrowd.")
