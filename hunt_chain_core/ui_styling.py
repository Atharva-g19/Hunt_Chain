"""Modern terminal UI styling and rendering engine for Hunt_Chain.

Provides rich visual presentation inspired by modern security testing tools:
- ANSI & 256-color support with graceful fallbacks
- Industry-standard status glyphs ([+], [*], [!], [-])
- High-contrast vulnerability severity badges (CRITICAL, HIGH, MEDIUM, LOW)
- Sleek ASCII branding banner
- Multi-stage pipeline assessment summary dashboards
- Formatted vulnerability finding and evidence inspection cards
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import sys

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.box import DOUBLE, HEAVY, ROUNDED, SIMPLE
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Shared global console for Hunt_Chain (legacy_windows=False prevents cp1252 charmap crashes)
console = Console(legacy_windows=False)

# ==============================================================================
# Standard Status Glyphs & Tags
# ==============================================================================

GLYPH_SUCCESS = "[bold green][+][/bold green]"
GLYPH_INFO = "[bold cyan][*][/bold cyan]"
GLYPH_WARN = "[bold yellow][!][/bold yellow]"
GLYPH_FAIL = "[bold red][-][/bold red]"
GLYPH_PROMPT = "[bold magenta][?][/bold magenta]"
GLYPH_ARROW = "[bold cyan]→[/bold cyan]"

# ==============================================================================
# Severity & Status Badges
# ==============================================================================

def format_severity(severity: str | None) -> str:
    """Format a vulnerability severity string with a high-contrast badge."""
    sev = (severity or "info").lower().strip()
    if sev in ("critical", "crit"):
        return "[bold white on red] CRITICAL [/bold white on red]"
    if sev == "high":
        return "[bold white on dark_red]   HIGH   [/bold white on dark_red]"
    if sev in ("medium", "med"):
        return "[bold black on yellow]  MEDIUM  [/bold black on yellow]"
    if sev == "low":
        return "[bold white on blue]   LOW    [/bold white on blue]"
    return "[bold white on cyan]   INFO   [/bold white on cyan]"


def format_stage_status(status: str | None) -> str:
    """Format pipeline stage status with color-coded symbol."""
    st = (status or "NOT RUN").upper().strip()
    if st in ("COMPLETE", "AUTHORIZED", "IN_SCOPE", "SUCCESS", "CONFIRMED", "VALIDATED"):
        return f"[bold green]✔ {st}[/bold green]"
    if st in ("POTENTIAL", "RUNNING", "PARTIAL", "WAITING"):
        return f"[bold yellow]◌ {st}[/bold yellow]"
    if st in ("FAILED", "OUT_OF_SCOPE", "DENIED", "NOT_CONFIRMED", "REJECTED"):
        return f"[bold red]✖ {st}[/bold red]"
    return f"[dim]○ {st}[/dim]"


# ==============================================================================
# Cyber Banner
# ==============================================================================

BANNER_TEXT = r"""
    __  __ __  __ _   __ ______      ______ __  __ ___     ____ _   __
   / / / // / / // | / //_  __/     / ____// / / //   |   /  _// | / /
  / /_/ // / / //  |/ /  / /   ─── / /    / /_/ // /| |   / / /  |/ / 
 / __  // /_/ // /|  /  / /       / /___ / __  // ___ | _/ / / /|  /  
/_/ /_/ \____//_/ |_/  /_/        \____//_/ /_//_/  |_|/___//_/ |_/   
"""

SUBTITLE = (
    "[dim cyan]ScopeGuard[/dim cyan] [bold cyan]➔[/bold cyan] "
    "[dim cyan]Recon[/dim cyan] [bold cyan]➔[/bold cyan] "
    "[dim cyan]Vulnerability Testing[/dim cyan] [bold cyan]➔[/bold cyan] "
    "[dim cyan]Validation & Exploitation[/dim cyan]"
)


def print_banner() -> None:
    """Print the primary Hunt_Chain ASCII logo and toolkit tagline."""
    content = Text()
    content.append("    __  __ __  __ _   __ ______      ______ __  __ ___     ____ _   __\n", style="bold cyan")
    content.append("   / / / // / / // | / //_  __/     / ____// / / //   |   /  _// | / /\n", style="bold cyan")
    content.append("  / /_/ // / / //  |/ /  / /   ─── / /    / /_/ // /| |   / / /  |/ / \n", style="bold blue")
    content.append(" / __  // /_/ // /|  /  / /       / /___ / __  // ___ | _/ / / /|  /  \n", style="bold magenta")
    content.append("/_/ /_/ \\____//_/ |_/  /_/        \\____//_/ /_//_/  |_|/___//_/ |_/   \n", style="bold magenta")
    content.append("HUNT_CHAIN  •  Authorized Security Testing Framework\n", style="bold white")
    content.append("ScopeGuard ➔ Recon ➔ Vulnerability Testing ➔ Validation", style="dim cyan")

    panel = Panel(
        content,
        border_style="cyan",
        box=ROUNDED,
        padding=(1, 2),
    )
    console.print(panel)


# ==============================================================================
# Assessment Overview Dashboard Card
# ==============================================================================

def render_assessment_dashboard(
    manager: Any,
    assessment_name: str,
) -> None:
    """Render an executive dashboard for an active or opened assessment."""
    try:
        manifest = manager.manifest(assessment_name)
    except Exception:
        manifest = {}

    runs_dir = getattr(manager, "runs_directory", Path("Hunt_Chain_Runs"))
    assessment_dir = runs_dir / assessment_name

    projects = manifest.get("projects", {})

    # 1. Project 1: ScopeGuard details
    p1_file = assessment_dir / "authorization_result.json"
    p1_status = "NOT RUN"
    target_summary = "Target not specified"
    if p1_file.is_file():
        try:
            with p1_file.open("r", encoding="utf-8-sig") as f:
                p1_data = json.load(f)
            p1_status = str(p1_data.get("state", "UNKNOWN")).upper()
            target_obj = p1_data.get("target", {})
            if isinstance(target_obj, dict):
                target_summary = (
                    target_obj.get("raw_value")
                    or target_obj.get("normalized_value")
                    or target_obj.get("url")
                    or target_obj.get("host")
                    or target_summary
                )
            elif isinstance(target_obj, str) and target_obj:
                target_summary = target_obj
            elif p1_data.get("target_url"):
                target_summary = p1_data["target_url"]
        except Exception:
            p1_status = "UNKNOWN"

    # 2. Project 2: Recon details
    p2_file = assessment_dir / "attack_surface.json"
    p2_status = "NOT RUN"
    p2_details = "Attack surface not mapped"
    if p2_file.is_file():
        try:
            with p2_file.open("r", encoding="utf-8-sig") as f:
                p2_data = json.load(f)
            p2_status = "COMPLETE"
            endpoints = p2_data.get("endpoints", [])
            endpoints_count = len(endpoints)
            with_params = sum(1 for ep in endpoints if ep.get("parameters"))
            p2_details = f"{endpoints_count} endpoints mapped ({with_params} with parameters)"
            if target_summary == "Target not specified" and p2_data.get("host"):
                scheme = p2_data.get("scheme", "https")
                target_summary = f"{scheme}://{p2_data['host']}"
        except Exception:
            p2_status = "ERROR"

    # 3. Project 3: Vulnerability details
    p3_file = assessment_dir / "vulnerability_result.json"
    p3_status = "NOT RUN"
    p3_details = "Vulnerability tests not executed"
    p3_findings: list[dict[str, Any]] = []
    if p3_file.is_file():
        try:
            with p3_file.open("r", encoding="utf-8-sig") as f:
                p3_data = json.load(f)
            p3_status = "COMPLETE"
            results = p3_data.get("results", [])
            p3_findings = [r for r in results if r.get("status") in ("POTENTIAL", "CONFIRMED", "FAIL")]
            p3_details = f"{len(results)} checks run • {len(p3_findings)} finding(s)"
        except Exception:
            p3_status = "ERROR"

    # 4. Project 4: Validation details
    p4_file = assessment_dir / "project4_validation.json"
    p4_status = "NOT RUN"
    p4_details = "Validation not executed"
    p4_confirmed_count = 0
    p4_not_confirmed_count = 0
    confirmed_findings: list[dict[str, Any]] = []
    if p4_file.is_file():
        try:
            with p4_file.open("r", encoding="utf-8-sig") as f:
                p4_data = json.load(f)
            p4_status = "COMPLETE"
            p4_results = p4_data.get("results", [])
            if not p4_results and isinstance(p4_data, list):
                p4_results = p4_data
            elif not p4_results and isinstance(p4_data, dict) and ("result_id" in p4_data or "decision" in p4_data):
                p4_results = [p4_data]

            for r in p4_results:
                dec = r.get("decision", {})
                if isinstance(dec, dict):
                    is_conf = dec.get("confirmed")
                elif isinstance(dec, str):
                    is_conf = dec.upper() in ("CONFIRMED", "VULNERABLE", "TRUE")
                else:
                    is_conf = bool(r.get("confirmed"))

                if is_conf:
                    p4_confirmed_count += 1
                    confirmed_findings.append(r)
                else:
                    p4_not_confirmed_count += 1
            p4_details = f"{p4_confirmed_count} confirmed • {p4_not_confirmed_count} refuted"
        except Exception:
            p4_status = "ERROR"

    # 5. Project 5: Reporting details
    p5_file = assessment_dir / "report.json"
    p5_status = "NOT RUN"
    p5_details = "Report not generated"
    if p5_file.is_file():
        p5_status = "COMPLETE"
        p5_details = "report.md & report.json generated"

    # Build Stage Table
    stage_table = Table(box=SIMPLE, show_header=True, header_style="bold cyan", padding=(0, 1))
    stage_table.add_column("Pipeline Stage", style="bold white", width=28)
    stage_table.add_column("Status", width=18)
    stage_table.add_column("Details", style="dim white")

    stage_table.add_row("1. ScopeGuard Authorization", format_stage_status(p1_status), f"Policy evaluation ({p1_status})")
    stage_table.add_row("2. Reconnaissance (Recon)", format_stage_status(p2_status), p2_details)
    stage_table.add_row("3. Vulnerability Testing", format_stage_status(p3_status), p3_details)
    stage_table.add_row("4. Validation & Exploitation", format_stage_status(p4_status), p4_details)
    stage_table.add_row("5. Findings & Reporting", format_stage_status(p5_status), p5_details)

    header_text = Text()
    header_text.append(f"Assessment Target : ", style="bold cyan")
    header_text.append(f"{target_summary}\n", style="bold white")
    header_text.append(f"Storage Directory : ", style="bold cyan")
    header_text.append(f"{assessment_dir.resolve()}\n\n", style="dim white")

    # If there are confirmed findings, show high-impact highlights
    highlights_table = None
    if confirmed_findings:
        highlights_table = Table(box=SIMPLE, show_header=True, header_style="bold green", padding=(0, 1))
        highlights_table.add_column("Severity", width=14)
        highlights_table.add_column("Check ID", width=12, style="bold cyan")
        highlights_table.add_column("Title / Verified Vulnerability", style="bold white")

        for f in confirmed_findings[:5]:
            tid = f.get("test_id") or f.get("finding_id") or "FINDING"
            title = f.get("title") or (f.get("candidate", {}).get("title") if isinstance(f.get("candidate"), dict) else "") or "Verified Vulnerability"
            sev = f.get("severity") or (f.get("decision", {}).get("severity") if isinstance(f.get("decision"), dict) else "high")
            highlights_table.add_row(format_severity(sev), tid, title)

    grid = Table.grid(padding=1)
    grid.add_row(header_text)
    grid.add_row(stage_table)
    if highlights_table:
        grid.add_row(Text("\nVerified Exploit Highlights:", style="bold green"))
        grid.add_row(highlights_table)

    dashboard_panel = Panel(
        grid,
        title=f"[bold green]✦ ASSESSMENT DASHBOARD: {assessment_name} ✦[/bold green]",
        border_style="green" if p4_confirmed_count > 0 else "cyan",
        box=ROUNDED,
        padding=(1, 2),
    )
    console.print(dashboard_panel)


# ==============================================================================
# Categories Grid
# ==============================================================================

def render_categories_grid(categories: list[dict[str, Any]]) -> None:
    """Render the 22 vulnerability categories in a balanced, color-coded grid."""
    table = Table(
        title="[bold cyan]Hunt_Chain Vulnerability Families (22 Categories / 168 Checks)[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        padding=(0, 1),
        expand=False,
    )
    table.add_column("#", style="bold yellow", justify="right", width=3)
    table.add_column("Tag", style="bold cyan", width=7)
    table.add_column("Vulnerability Family", style="bold white")
    table.add_column("Chks", style="bold green", justify="center", width=5)

    table.add_column("#", style="bold yellow", justify="right", width=3)
    table.add_column("Tag", style="bold cyan", width=7)
    table.add_column("Vulnerability Family", style="bold white")
    table.add_column("Chks", style="bold green", justify="center", width=5)

    half = (len(categories) + 1) // 2
    for i in range(half):
        c1 = categories[i]
        c2 = categories[i + half] if i + half < len(categories) else None

        row = [
            str(c1["index"]),
            f"[{c1['code']}]",
            c1["name"],
            str(c1["checks"]),
        ]
        if c2:
            row.extend([
                str(c2["index"]),
                f"[{c2['code']}]",
                c2["name"],
                str(c2["checks"]),
            ])
        else:
            row.extend(["", "", "", ""])
        table.add_row(*row)

    console.print(table)


# ==============================================================================
# Finding & Validation Cards
# ==============================================================================

def render_finding_card(
    test_id: str,
    title: str,
    status: str,
    observation: str,
    severity: str = "medium",
    url: str | None = None,
    parameter: str | None = None,
) -> None:
    """Render a standalone, beautifully styled vulnerability finding card."""
    content = Text()
    content.append(f"{format_severity(severity)}  ", style="bold")
    content.append(f"[{test_id}] ", style="bold cyan")
    content.append(f"{title}\n", style="bold white")

    if url:
        content.append(f"Endpoint  : ", style="bold cyan")
        content.append(f"{url}\n", style="white")
    if parameter:
        content.append(f"Parameter : ", style="bold cyan")
        content.append(f"{parameter}\n", style="yellow")

    content.append(f"Status    : ", style="bold cyan")
    content.append(f"{status}\n", style="bold yellow" if status == "POTENTIAL" else "bold green")
    content.append(f"\nObservation:\n", style="bold dim white")
    content.append(f"{observation}", style="dim white")

    border_color = "red" if severity.lower() in ("critical", "high") else "yellow"
    panel = Panel(content, border_style=border_color, box=ROUNDED, padding=(1, 2))
    console.print(panel)


def render_validation_decision_card(
    test_id: str,
    confirmed: bool,
    reason: str,
    severity: str = "high",
    target_url: str | None = None,
    evidence_snippet: str | None = None,
) -> None:
    """Render a confirmed exploit / refuted decision card from Project 4."""
    status_tag = "[bold white on dark_green] CONFIRMED EXPLOIT [/bold white on dark_green]" if confirmed else "[bold white on dark_red] NOT CONFIRMED [/bold white on dark_red]"
    border = "green" if confirmed else "dim red"

    content = Text()
    content.append(f"{status_tag}  ", style="bold")
    content.append(f"{format_severity(severity)}  ", style="bold")
    content.append(f"[{test_id}]\n\n", style="bold cyan")

    if target_url:
        content.append("Validated Target : ", style="bold cyan")
        content.append(f"{target_url}\n", style="white")

    content.append("Validation Proof : ", style="bold cyan")
    content.append(f"{reason}\n", style="white")

    if evidence_snippet:
        content.append("\nObservable Response Evidence:\n", style="bold dim white")
        content.append(f"{evidence_snippet[:300]}\n", style="dim cyan")

    content.append("\nSafety Policy     : ", style="bold cyan")
    content.append("Controlled non-destructive verification • Zero persistent damage", style="dim green")

    panel = Panel(content, border_style=border, box=ROUNDED, padding=(1, 2))
    console.print(panel)
