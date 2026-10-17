from __future__ import annotations

import argparse
import json
from pathlib import Path
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

from rich.box import ROUNDED, SIMPLE
from rich.table import Table
from rich.text import Text

from hunt_chain_core import AssessmentManager
from hunt_chain_core.project_1_runner import run_project_1
from hunt_chain_core.project_2_ui import _run_project_2
from hunt_chain_core.project_3_execution import run_project_3
from hunt_chain_core.project_3_ui import _resolve_categories, _run_project_3
from hunt_chain_core.project_4_execution import (
    list_project4_candidates,
    run_project_4_batch_validation,
)
from hunt_chain_core.project_4_ui import _run_project_4
from hunt_chain_core.project_5_execution import run_project_5
from hunt_chain_core.project_5_ui import _run_project_5
from hunt_chain_core.scope_manager import ScopeManager
from hunt_chain_core.ui_styling import (
    GLYPH_ARROW,
    GLYPH_FAIL,
    GLYPH_INFO,
    GLYPH_PROMPT,
    GLYPH_SUCCESS,
    GLYPH_WARN,
    console,
    format_severity,
    format_stage_status,
    print_banner,
    render_assessment_dashboard,
)

BANNER = r"""
╔══════════════════════════════════════════════════════╗
║                  H U N T _ C H A I N                 ║
║              Authorized Security Toolkit             ║
╚══════════════════════════════════════════════════════╝
"""

ASCII_BANNER = r"""
+------------------------------------------------------+
|                  H U N T _ C H A I N                 |
|              Authorized Security Toolkit             |
+------------------------------------------------------+
"""

PROJECTS = {
    "1": "ScopeGuard",
    "2": "Reconnaissance",
    "3": "Vulnerability Testing",
    "4": "Validation",
    "5": "Reporting",
}


def _pause() -> None:
    try:
        input("\nPress Enter to continue...")
    except (EOFError, KeyboardInterrupt):
        pass


def _print_main_menu() -> None:
    menu_table = Table(
        box=ROUNDED,
        border_style="cyan",
        show_header=False,
        padding=(0, 2),
    )
    menu_table.add_column("Option", style="bold yellow", width=6, justify="right")
    menu_table.add_column("Action", style="bold white", width=24)
    menu_table.add_column("Description", style="dim white")

    menu_table.add_row("[1]", "New Assessment", "Initialize a target scope & assessment run")
    menu_table.add_row("[2]", "Open Assessment", "Launch security pipeline for an existing project")
    menu_table.add_row("[3]", "List Assessments", "Show all registered assessments and their pipeline status")
    menu_table.add_row("[4]", "Assessment Details", "Executive dashboard & artifact inspection")
    menu_table.add_row("[0]", "Exit", "Exit Hunt_Chain framework")

    console.print("\n[bold cyan]Hunt_Chain Navigation Console[/bold cyan]")
    console.print(menu_table)


def _print_assessment_header(
    manager: AssessmentManager,
    name: str,
) -> None:
    render_assessment_dashboard(manager, name)

    menu_table = Table(
        box=ROUNDED,
        border_style="green",
        show_header=False,
        padding=(0, 2),
    )
    menu_table.add_column("Option", style="bold yellow", width=6, justify="right")
    menu_table.add_column("Pipeline Stage", style="bold white", width=28)
    menu_table.add_column("Purpose", style="dim white")

    menu_table.add_row("[1]", "ScopeGuard Authorization", "Define targets, IP/domain rules, and verify authorization")
    menu_table.add_row("[2]", "Reconnaissance (Recon)", "Map endpoints, parameters, technologies & attack surface")
    menu_table.add_row("[3]", "Vulnerability Testing", "Execute 168 checks across 22 vulnerability families")
    menu_table.add_row("[4]", "Validation & Exploitation", "Confirm live exploitability with safety-guaranteed PoCs")
    menu_table.add_row("[5]", "Reporting", "Generate executive audit & compliance reports")
    menu_table.add_row("[0]", "Back", "Return to Main Menu")

    console.print("[bold green]Available Pipeline Actions[/bold green]")
    console.print(menu_table)


def _create_assessment(
    manager: AssessmentManager,
) -> None:
    console.print(f"\n[bold cyan]✦ CREATE NEW ASSESSMENT ✦[/bold cyan]")
    try:
        name = input("Enter assessment name [e.g. audit_2026]: ").strip()
    except (EOFError, KeyboardInterrupt):
        return

    if not name:
        console.print(f"{GLYPH_FAIL} [red]Assessment name is required.[/red]")
        return

    try:
        manager.create(name)
    except (ValueError, FileExistsError) as exc:
        console.print(f"\n{GLYPH_FAIL} [red]Cannot create assessment: {exc}[/red]")
        return

    console.print(f"\n{GLYPH_SUCCESS} [bold green]Assessment '{name}' created successfully.[/bold green]")
    _open_assessment(manager, name)


def _list_assessments(
    manager: AssessmentManager,
) -> None:
    assessments = manager.list_assessments()

    if not assessments:
        console.print(f"\n{GLYPH_WARN} [yellow]No assessments found. Create one with Option 1.[/yellow]\n")
        return

    table = Table(
        title="[bold cyan]Hunt_Chain Registered Assessments[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        padding=(0, 1),
    )
    table.add_column("#", style="bold yellow", justify="right")
    table.add_column("Assessment Name", style="bold white")
    table.add_column("Status")
    table.add_column("Target URL / Host", style="bold cyan")
    table.add_column("Created At", style="dim white")

    runs_dir = getattr(manager, "runs_directory", Path("Hunt_Chain_Runs"))
    for index, name in enumerate(assessments, start=1):
        try:
            manifest = manager.manifest(name)
            status = manifest.get("status", "ACTIVE")
            created_at = manifest.get("created_at", "—")
        except Exception:
            status = "UNKNOWN"
            created_at = "—"

        target_str = "Target not specified"
        p1_path = runs_dir / name / "authorization_result.json"
        if p1_path.is_file():
            try:
                with p1_path.open("r", encoding="utf-8-sig") as h:
                    p1_data = json.load(h)
                t = p1_data.get("target", {})
                if isinstance(t, dict):
                    target_str = (
                        t.get("raw_value")
                        or t.get("normalized_value")
                        or t.get("url")
                        or t.get("host")
                        or target_str
                    )
                elif isinstance(t, str) and t:
                    target_str = t
                elif p1_data.get("target_url"):
                    target_str = p1_data["target_url"]
            except Exception:
                pass

        table.add_row(str(index), name, format_stage_status(status), target_str, created_at)

    console.print(table)


def _show_assessment_details(
    manager: AssessmentManager,
) -> None:
    assessments = manager.list_assessments()

    if not assessments:
        console.print(f"\n{GLYPH_WARN} [yellow]No assessments found.[/yellow]")
        return

    _list_assessments(manager)
    try:
        choice = input("\nEnter assessment number to inspect dashboard [or 'all', 0=Back]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return

    if choice in ("0", "back", ""):
        return

    if choice == "all":
        for name in assessments:
            render_assessment_dashboard(manager, name)
        _pause()
        return

    if choice.isdigit():
        idx = int(choice)
        if 1 <= idx <= len(assessments):
            render_assessment_dashboard(manager, assessments[idx - 1])
            _pause()
            return

    for name in assessments:
        if name.lower() == choice:
            render_assessment_dashboard(manager, name)
            _pause()
            return

    console.print(f"{GLYPH_FAIL} [red]Invalid assessment selection.[/red]")


def _choose_assessment(
    manager: AssessmentManager,
) -> str | None:
    assessments = manager.list_assessments()

    if not assessments:
        console.print(f"\n{GLYPH_WARN} [yellow]No assessments found. Create one first.[/yellow]")
        return None

    _list_assessments(manager)
    try:
        choice = input("\nSelect assessment number or name [0=Back]: ").strip()
    except (EOFError, KeyboardInterrupt):
        return None

    if choice in ("0", "back", ""):
        return None

    if choice.isdigit():
        index = int(choice)
        if 1 <= index <= len(assessments):
            return assessments[index - 1]
        console.print(f"{GLYPH_FAIL} [red]Invalid selection: {index}[/red]")
        return None

    if choice in assessments:
        return choice

    console.print(f"{GLYPH_FAIL} [red]Assessment '{choice}' not found.[/red]")
    return None


def _scope_menu(
    scope_manager: ScopeManager,
) -> Path | None:
    while True:
        table = Table(box=ROUNDED, border_style="cyan", show_header=False, padding=(0, 2))
        table.add_column("Option", style="bold yellow", width=6, justify="right")
        table.add_column("Action", style="bold white", width=24)
        table.add_column("Description", style="dim white")

        table.add_row("[1]", "Create New Scope", "Define new authorized target IP/domain rules")
        table.add_row("[2]", "Edit Existing Scope", "Inspect or modify scope YAML rules in editor")
        table.add_row("[0]", "Back", "Return to assessment menu")

        console.print("\n[bold cyan]ScopeGuard Scope Management[/bold cyan]")
        console.print(table)

        try:
            choice = input("ScopeGuard> ").strip()
        except (EOFError, KeyboardInterrupt):
            return None

        if choice in ("0", "back"):
            return None

        if choice == "1":
            return _create_scope(scope_manager)

        if choice == "2":
            return _edit_scope(scope_manager)

        console.print(f"{GLYPH_FAIL} [red]Invalid selection.[/red]")


def _create_scope(
    scope_manager: ScopeManager,
) -> Path | None:
    console.print(f"\n[bold cyan]Create New Scope[/bold cyan]")
    try:
        name = input("Scope name: ").strip()
    except (EOFError, KeyboardInterrupt):
        return None

    if not name:
        console.print(f"{GLYPH_FAIL} [red]Scope name is required.[/red]")
        return None

    try:
        path = scope_manager.create(name)
    except (ValueError, FileExistsError) as exc:
        console.print(f"\n{GLYPH_FAIL} [red]Cannot create scope: {exc}[/red]")
        return None

    console.print(f"\n{GLYPH_SUCCESS} [bold green]Scope '{name}' created.[/bold green]")
    console.print(f"{GLYPH_INFO} Opening scope definition...")

    try:
        scope_manager.open_in_editor(name)
    except (FileNotFoundError, OSError) as exc:
        console.print(f"{GLYPH_WARN} [yellow]Could not open editor: {exc}[/yellow]")
        console.print(f"Scope created successfully: {path}")
        return path

    try:
        input("\nEdit and save the YAML, then press Enter to continue...")
    except (EOFError, KeyboardInterrupt):
        pass

    return path


def _edit_scope(
    scope_manager: ScopeManager,
) -> Path | None:
    scopes = scope_manager.list_scopes()

    if not scopes:
        console.print(f"\n{GLYPH_WARN} [yellow]No scopes available.[/yellow]")
        return None

    table = Table(
        title="[bold cyan]Available Scopes[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        padding=(0, 1),
    )
    table.add_column("#", style="bold yellow", width=4, justify="right")
    table.add_column("Scope Name", style="bold white", width=30)

    for index, name in enumerate(scopes, start=1):
        table.add_row(str(index), name)

    console.print(table)

    try:
        choice = input("Select scope [0=Back]: ").strip()
    except (EOFError, KeyboardInterrupt):
        return None

    if choice in ("0", "back", ""):
        return None

    try:
        index = int(choice)
    except ValueError:
        console.print(f"{GLYPH_FAIL} [red]Invalid selection.[/red]")
        return None

    if not 1 <= index <= len(scopes):
        console.print(f"{GLYPH_FAIL} [red]Invalid selection.[/red]")
        return None

    name = scopes[index - 1]

    try:
        scope_manager.open_in_editor(name)
    except (FileNotFoundError, OSError) as exc:
        console.print(f"{GLYPH_WARN} [yellow]Could not open scope editor: {exc}[/yellow]")
        return None

    try:
        input("\nEdit and save the YAML, then press Enter to continue...")
    except (EOFError, KeyboardInterrupt):
        pass

    return scope_manager.path_for(name)


def _run_project_1(
    manager: AssessmentManager,
    assessment_name: str,
) -> None:
    console.print(f"\n[bold cyan]✦ STAGE 1: SCOPEGUARD AUTHORIZATION ✦[/bold cyan]")
    scope_manager = ScopeManager()

    scope_path = _scope_menu(scope_manager)
    if scope_path is None:
        return

    scope_name = scope_path.stem

    try:
        targets = scope_manager.included_targets(scope_name)
    except (FileNotFoundError, ValueError, OSError) as exc:
        console.print(f"\n{GLYPH_FAIL} [red]Could not load scope: {exc}[/red]")
        return

    if not targets:
        console.print(f"\n{GLYPH_WARN} [yellow]The selected scope contains no included assets.[/yellow]")
        console.print("Add at least one include rule before running ScopeGuard.")
        return

    table = Table(
        title="[bold cyan]Authorized Scope Assets[/bold cyan]",
        box=ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        padding=(0, 1),
    )
    table.add_column("#", style="bold yellow", width=4, justify="right")
    table.add_column("Asset Type", style="bold cyan", width=14)
    table.add_column("Target Value / Pattern", style="bold white")

    for index, item in enumerate(targets, start=1):
        table.add_row(str(index), f"[{item['type'].upper()}]", item["value"])

    console.print(table)

    if len(targets) == 1:
        selected = targets[0]
        console.print(f"\n{GLYPH_INFO} Auto-selected target: [bold white]{selected['value']}[/bold white]")
    else:
        try:
            choice = input("\nSelect target [0=Back]: ").strip()
        except (EOFError, KeyboardInterrupt):
            return

        if choice in ("0", "back", ""):
            return

        try:
            index = int(choice)
        except ValueError:
            console.print(f"{GLYPH_FAIL} [red]Invalid selection.[/red]")
            return

        if not 1 <= index <= len(targets):
            console.print(f"{GLYPH_FAIL} [red]Invalid selection.[/red]")
            return

        selected = targets[index - 1]

    target = selected["value"].strip()
    if not target:
        console.print(f"{GLYPH_FAIL} [red]Selected scope asset has an empty target.[/red]")
        return

    console.print(f"\n[bold cyan]Scope :[/bold cyan] {scope_name}")
    console.print(f"[bold cyan]Target:[/bold cyan] {target}\n")

    try:
        confirm = input("Run ScopeGuard against this target? [y/N]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        return

    if confirm != "y":
        console.print(f"{GLYPH_WARN} [yellow]ScopeGuard cancelled.[/yellow]")
        return

    console.print(f"\n{GLYPH_INFO} Running ScopeGuard policy evaluation...")

    try:
        run_project_1(
            assessment_name,
            scope_path,
            target,
            manager.runs_directory,
        )
    except (FileNotFoundError, ValueError, RuntimeError, OSError, PermissionError) as exc:
        console.print(f"\n{GLYPH_FAIL} [red]ScopeGuard failed: {exc}[/red]")
        return

    console.print(f"\n{GLYPH_SUCCESS} [bold green]ScopeGuard completed successfully.[/bold green]")
    console.print(f"{GLYPH_INFO} Authorization result registered in assessment history.")


def _run_project_2_safe(
    manager: AssessmentManager,
    assessment_name: str,
) -> None:
    console.print(f"\n[bold cyan]✦ STAGE 2: ATTACK SURFACE RECONNAISSANCE ✦[/bold cyan]")
    try:
        _run_project_2(manager, assessment_name)
    except (FileNotFoundError, ValueError, RuntimeError, OSError) as exc:
        console.print(f"\n{GLYPH_FAIL} [red]Reconnaissance failed: {exc}[/red]")
        return

    console.print(f"\n{GLYPH_SUCCESS} [bold green]Reconnaissance stage finished.[/bold green]")


def _run_project_3_safe(
    manager: AssessmentManager,
    assessment_name: str,
) -> None:
    console.print(f"\n[bold cyan]✦ STAGE 3: VULNERABILITY TESTING ✦[/bold cyan]")
    try:
        _run_project_3(manager, assessment_name)
    except (FileNotFoundError, ValueError, RuntimeError, OSError) as exc:
        console.print(f"\n{GLYPH_FAIL} [red]Vulnerability Testing failed: {exc}[/red]")
        return

    console.print(f"\n{GLYPH_SUCCESS} [bold green]Vulnerability Testing stage finished.[/bold green]")


def _authorization_state(
    manager: AssessmentManager,
    assessment_name: str,
) -> str | None:
    try:
        result_path = (
            manager.get(assessment_name)
            / "authorization_result.json"
        )
        if not result_path.is_file():
            return None

        with result_path.open("r", encoding="utf-8-sig") as handle:
            result = json.load(handle)

        state = result.get("state")
        if state is None:
            return None
        return str(state).upper()
    except (OSError, ValueError, TypeError):
        return None


def _project_available(
    manager: AssessmentManager,
    assessment_name: str,
    project_id: str,
) -> bool:
    try:
        manifest = manager.manifest(assessment_name)
    except Exception:
        return False
    return project_id in manifest.get("projects", {})


def _authorization_allows_testing(
    manager: AssessmentManager,
    assessment_name: str,
) -> bool:
    return _authorization_state(manager, assessment_name) == "IN_SCOPE"


def _open_assessment(
    manager: AssessmentManager,
    name: str,
) -> None:
    while True:
        if not manager.exists(name):
            console.print(f"\n{GLYPH_FAIL} [red]Assessment does not exist: {name}[/red]")
            return

        _print_assessment_header(manager, name)

        try:
            choice = input(f"{name}> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if choice in ("0", "back"):
            return

        if choice == "1":
            _run_project_1(manager, name)
            continue

        if choice == "2":
            if not _project_available(manager, name, "project_1"):
                console.print(f"\n{GLYPH_WARN} [yellow]Cannot run Reconnaissance. Run ScopeGuard (Stage 1) first.[/yellow]")
                continue

            if not _authorization_allows_testing(manager, name):
                state = _authorization_state(manager, name)
                console.print(f"\n{GLYPH_FAIL} [red]Cannot run Reconnaissance: ScopeGuard authorization is not IN_SCOPE.[/red]")
                console.print(f"Current authorization state: {state or 'UNKNOWN'}")
                continue

            _run_project_2_safe(manager, name)
            continue

        if choice == "3":
            if not _project_available(manager, name, "project_1"):
                console.print(f"\n{GLYPH_WARN} [yellow]Cannot run Vulnerability Testing. Run ScopeGuard (Stage 1) first.[/yellow]")
                continue

            if not _project_available(manager, name, "project_2"):
                console.print(f"\n{GLYPH_WARN} [yellow]Cannot run Vulnerability Testing. Run Reconnaissance (Stage 2) first.[/yellow]")
                continue

            _run_project_3_safe(manager, name)
            continue

        if choice == "4":
            if not _project_available(manager, name, "project_1"):
                console.print(f"\n{GLYPH_WARN} [yellow]Cannot run Validation. Run ScopeGuard (Stage 1) first.[/yellow]")
                continue

            if not _authorization_allows_testing(manager, name):
                state = _authorization_state(manager, name)
                console.print(f"\n{GLYPH_FAIL} [red]Cannot run Validation: ScopeGuard authorization is not IN_SCOPE.[/red]")
                console.print(f"Current authorization state: {state or 'UNKNOWN'}")
                continue

            if not _project_available(manager, name, "project_3"):
                console.print(f"\n{GLYPH_WARN} [yellow]Cannot run Validation. Run Vulnerability Testing (Stage 3) first.[/yellow]")
                continue

            _run_project_4(manager, name)
            continue

        if choice == "5":
            if not _project_available(manager, name, "project_1"):
                console.print(f"\n{GLYPH_WARN} [yellow]Cannot run Reporting. Run ScopeGuard (Stage 1) first.[/yellow]")
                continue

            if not _authorization_allows_testing(manager, name):
                state = _authorization_state(manager, name)
                console.print(f"\n{GLYPH_FAIL} [red]Cannot run Reporting: ScopeGuard authorization is not IN_SCOPE.[/red]")
                console.print(f"Current authorization state: {state or 'UNKNOWN'}")
                continue

            _run_project_5(manager, name)
            continue

        console.print(f"\n{GLYPH_FAIL} [red]Invalid selection.[/red]")


def main(argv: list[str] | None = None) -> None:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    parser = argparse.ArgumentParser(
        prog="hunt-chain",
        description="Hunt_Chain — Professional Authorized Security Testing Framework",
        add_help=True,
    )
    parser.add_argument(
        "-l",
        "--list",
        action="store_true",
        help="List all registered assessments and their pipeline status",
    )
    parser.add_argument(
        "-a",
        "--assessment",
        type=str,
        default=None,
        help="Target assessment name for headless execution or inspection",
    )
    parser.add_argument(
        "-s",
        "--summary",
        action="store_true",
        help="Display the executive dashboard and vulnerability overview for an assessment",
    )
    parser.add_argument(
        "--run-p3",
        action="store_true",
        help="Run Project 3 (Vulnerability Testing) non-interactively on the target assessment",
    )
    parser.add_argument(
        "--category",
        type=str,
        default=None,
        help="Category or test ID filter for --run-p3 (e.g. SQLI, XSS, ATO, or 'all')",
    )
    parser.add_argument(
        "--run-p4",
        action="store_true",
        help="Run Project 4 (Validation) batch verification non-interactively on the target assessment",
    )
    parser.add_argument(
        "--report",
        "--run-p5",
        dest="run_p5",
        action="store_true",
        help="Generate Project 5 submission-ready reports (report.md & report.json) for the target assessment",
    )

    args = parser.parse_args(argv)
    manager = AssessmentManager()

    # Headless CLI flags
    if args.list:
        _list_assessments(manager)
        return

    if args.summary:
        target_name = args.assessment
        if not target_name:
            assessments = manager.list_assessments()
            if not assessments:
                console.print(f"{GLYPH_WARN} [yellow]No assessments found.[/yellow]")
                return
            target_name = assessments[0]
        render_assessment_dashboard(manager, target_name)
        return

    if args.run_p3:
        target_name = args.assessment
        if not target_name:
            assessments = manager.list_assessments()
            if not assessments:
                console.print(f"{GLYPH_WARN} [yellow]No assessments found.[/yellow]")
                return
            target_name = assessments[0]

        test_ids: list[str] | None = None
        if args.category:
            resolved_ids, _ = _resolve_categories(args.category)
            test_ids = resolved_ids

        console.print(f"\n{GLYPH_INFO} Running Project 3 headlessly on assessment [bold cyan]{target_name}[/bold cyan]...")
        run_project_3(
            target_name,
            runs_directory=Path(manager.runs_directory).resolve(),
            test_ids=test_ids,
        )
        console.print(f"\n{GLYPH_SUCCESS} Headless Project 3 run completed.")
        return

    if args.run_p4:
        target_name = args.assessment
        if not target_name:
            assessments = manager.list_assessments()
            if not assessments:
                console.print(f"{GLYPH_WARN} [yellow]No assessments found.[/yellow]")
                return
            target_name = assessments[0]

        runs_dir = Path(manager.runs_directory).resolve()
        candidates = list_project4_candidates(target_name, runs_directory=runs_dir)
        if not candidates:
            console.print(f"{GLYPH_INFO} No candidate findings waiting for validation.")
            return

        console.print(f"\n{GLYPH_INFO} Validating {len(candidates)} candidates on [bold cyan]{target_name}[/bold cyan]...")
        res_ids = [c["result_id"] for c in candidates]
        run_project_4_batch_validation(target_name, result_ids=res_ids, runs_directory=runs_dir)
        console.print(f"\n{GLYPH_SUCCESS} Headless Project 4 batch validation completed.")
        return

    if args.run_p5:
        target_name = args.assessment
        if not target_name:
            assessments = manager.list_assessments()
            if not assessments:
                console.print(f"{GLYPH_WARN} [yellow]No assessments found.[/yellow]")
                return
            target_name = assessments[0]

        console.print(f"\n{GLYPH_INFO} Generating Project 5 report headlessly for [bold cyan]{target_name}[/bold cyan]...")
        md_p, json_p, rep = run_project_5(target_name, runs_directory=Path(manager.runs_directory).resolve())
        console.print(f"{GLYPH_SUCCESS} Report generation completed successfully:")
        console.print(f"  Markdown: [bold cyan]{md_p}[/bold cyan]")
        console.print(f"  JSON:     [bold cyan]{json_p}[/bold cyan]")
        return

    # Interactive TUI mode
    print_banner()

    while True:
        _print_main_menu()

        try:
            choice = input("hunt-chain> ").strip()
        except (EOFError, KeyboardInterrupt):
            console.print("\n[dim]Exiting Hunt_Chain...[/dim]")
            break

        if choice == "1":
            _create_assessment(manager)

        elif choice == "2":
            name = _choose_assessment(manager)
            if name is not None:
                _open_assessment(manager, name)

        elif choice == "3":
            _list_assessments(manager)
            _pause()

        elif choice == "4":
            _show_assessment_details(manager)

        elif choice == "0":
            console.print("\n[bold cyan]Exiting Hunt_Chain. Happy hunting![/bold cyan]")
            return

        else:
            console.print(f"\n{GLYPH_FAIL} [red]Invalid selection.[/red]")


if __name__ == "__main__":
    main()
