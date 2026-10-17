"""Interactive Project 4 validation UI with subdomain filtering and batch execution."""

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

from rich.box import ROUNDED, SIMPLE
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hunt_chain_core.project_4_execution import (
    list_project4_candidates,
    run_project_4_batch_validation,
    run_project_4_validation,
)
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
    render_validation_decision_card,
)


def _extract_host(candidate: dict[str, Any]) -> str:
    """Extract lowercase host/subdomain from candidate endpoint URL."""
    endpoint = candidate.get("endpoint") or {}
    url = endpoint.get("url") or ""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or parsed.netloc or ""
        return host.lower() if host else "unknown-host"
    except Exception:
        return "unknown-host"


def _load_validation_history(
    assessment_name: str,
    runs_directory: Path,
) -> dict[str, dict[str, Any]]:
    """Return map of result_id -> prior validation result record."""
    validation_file = (
        runs_directory / assessment_name / "project4_validation.json"
    )
    if not validation_file.is_file():
        return {}

    try:
        with validation_file.open("r", encoding="utf-8-sig") as handle:
            doc = json.load(handle)

        history: dict[str, dict[str, Any]] = {}
        if isinstance(doc, dict):
            if "results" in doc and isinstance(doc["results"], list):
                for item in doc["results"]:
                    if isinstance(item, dict):
                        rid = item.get("result_id") or item.get("finding_id")
                        if rid:
                            history[rid] = item
            elif "result_id" in doc or "finding_id" in doc:
                rid = doc.get("result_id") or doc.get("finding_id")
                if rid:
                    history[rid] = doc
        return history
    except Exception:
        return {}


def _parse_candidate_selection(
    user_input: str,
    displayed_candidates: list[dict[str, Any]],
    domain_tags: dict[str, str],
    tag_to_candidates: dict[str, list[dict[str, Any]]],
) -> tuple[list[dict[str, Any]] | None, str | None]:
    """Parse user selection input into a list of candidates or command."""
    raw = user_input.strip()
    if not raw:
        return None, "ERROR: Please make a selection or type '0' to go back."

    lower_raw = raw.lower()

    if lower_raw in ("0", "back", "exit", "q"):
        return [], "BACK"

    if lower_raw in ("clear", "reset", "c", "all-domains"):
        return None, "CLEAR_FILTER"

    if lower_raw.startswith(("f ", "filter ")):
        parts = raw.split(maxsplit=1)
        term = parts[1].strip() if len(parts) > 1 else ""
        return None, f"KEYWORD_FILTER:{term}"

    if lower_raw.startswith(("d ", "domain ", "host ")):
        parts = raw.split(maxsplit=1)
        term = parts[1].strip() if len(parts) > 1 else ""
        return None, f"DOMAIN_FILTER:{term}"

    if lower_raw in ("all", "*", "a"):
        return list(displayed_candidates), None

    tokens = [t.strip() for t in re.split(r"[,; ]+", raw) if t.strip()]
    selected: list[dict[str, Any]] = []

    for tok in tokens:
        upper_tok = tok.upper()
        if upper_tok in tag_to_candidates:
            selected.extend(tag_to_candidates[upper_tok])
            continue

        if "-" in tok:
            parts = tok.split("-", 1)
            try:
                start = int(parts[0])
                end = int(parts[1])
                if start > end:
                    start, end = end, start
                for idx in range(start, end + 1):
                    if 1 <= idx <= len(displayed_candidates):
                        selected.append(displayed_candidates[idx - 1])
                    else:
                        return (
                            None,
                            f"ERROR: Index {idx} out of range (1..{len(displayed_candidates)}).",
                        )
                continue
            except ValueError:
                return None, f"ERROR: Invalid range format '{tok}'."

        if tok.isdigit():
            idx = int(tok)
            if 1 <= idx <= len(displayed_candidates):
                selected.append(displayed_candidates[idx - 1])
                continue
            return (
                None,
                f"ERROR: Index {idx} out of range (1..{len(displayed_candidates)}).",
            )

        matched_domain = False
        lower_tok = tok.lower()
        for host, tag in domain_tags.items():
            if lower_tok in host:
                selected.extend(tag_to_candidates[tag])
                matched_domain = True
                break

        if not matched_domain:
            return (
                None,
                f"ERROR: Unrecognized selection or domain token '{tok}'.",
            )

    seen: set[str] = set()
    unique_selected: list[dict[str, Any]] = []
    for c in selected:
        rid = c.get("result_id", "")
        if rid not in seen:
            seen.add(rid)
            unique_selected.append(c)

    if not unique_selected:
        return None, "ERROR: No candidates matched your selection."

    return unique_selected, None


def _run_project_4(
    manager: Any,
    assessment_name: str,
) -> None:
    runs_directory = Path(manager.runs_directory).resolve()

    active_domain_filter: str | None = None
    active_keyword_filter: str | None = None

    while True:
        try:
            candidates = list_project4_candidates(
                assessment_name,
                runs_directory=runs_directory,
            )
        except (
            FileNotFoundError,
            ValueError,
            OSError,
            json.JSONDecodeError,
        ) as exc:
            console.print(f"\n{GLYPH_FAIL} [red]Cannot load Project 3 findings: {exc}[/red]")
            return

        if not candidates:
            p3_file = runs_directory / assessment_name / "vulnerability_result.json"
            confirmed_list: list[dict[str, Any]] = []
            if p3_file.is_file():
                try:
                    with p3_file.open("r", encoding="utf-8-sig") as h:
                        doc = json.load(h)
                    for r in doc.get("results", []):
                        if str(r.get("status", "")).upper() in ("CONFIRMED", "FAIL"):
                            confirmed_list.append(r)
                except Exception:
                    pass

            console.print(f"\n[bold cyan]✦ PROJECT 4 — VALIDATION & CONTROLLED EXPLOITATION ✦[/bold cyan]")
            console.print(f"[bold cyan]Assessment :[/bold cyan] [bold white]{assessment_name}[/bold white]\n")

            if confirmed_list:
                table = Table(
                    title="[bold green]Directly Confirmed Project 3 Findings[/bold green]",
                    box=ROUNDED,
                    border_style="green",
                    header_style="bold green",
                    padding=(0, 1),
                )
                table.add_column("#", style="bold yellow", width=4, justify="right")
                table.add_column("Severity", width=14)
                table.add_column("Check ID", style="bold cyan", width=12)
                table.add_column("Vulnerability Finding", style="bold white")
                table.add_column("Target URL", style="dim white")

                for idx, r in enumerate(confirmed_list, start=1):
                    sev = r.get("severity") or r.get("confidence") or "HIGH"
                    meta = r.get("metadata", {})
                    url = meta.get("url") or meta.get("target_url") or "—"
                    table.add_row(str(idx), format_severity(sev), r.get("test_id", "VULN"), r.get("title", ""), url)

                console.print(table)
                console.print(f"\n{GLYPH_INFO} [bold green]All discovered vulnerabilities are already confirmed.[/bold green]")
                console.print(f"{GLYPH_INFO} No unvalidated POTENTIAL candidates in queue.")
            else:
                panel = Panel(
                    "[bold green]No POTENTIAL findings require live validation.[/bold green]\n\n"
                    "All Project 3 checks either passed cleanly or did not observe vulnerable conditions.",
                    title="[bold green]Validation Queue Empty[/bold green]",
                    border_style="green",
                    box=ROUNDED,
                    padding=(1, 2),
                )
                console.print(panel)

            try:
                input("\nPress Enter to return to assessment menu...")
            except (KeyboardInterrupt, EOFError):
                pass
            return

        history = _load_validation_history(
            assessment_name,
            runs_directory,
        )

        domain_groups: dict[str, list[dict[str, Any]]] = {}
        for cand in candidates:
            host = _extract_host(cand)
            domain_groups.setdefault(host, []).append(cand)

        sorted_hosts = sorted(domain_groups.keys())
        domain_tags: dict[str, str] = {
            host: f"D{idx}"
            for idx, host in enumerate(sorted_hosts, start=1)
        }
        tag_to_candidates: dict[str, list[dict[str, Any]]] = {
            domain_tags[host]: domain_groups[host]
            for host in sorted_hosts
        }

        displayed: list[dict[str, Any]] = []
        for cand in candidates:
            host = _extract_host(cand)
            if (
                active_domain_filter
                and active_domain_filter not in host
            ):
                continue
            if active_keyword_filter:
                combined_text = (
                    f"{cand.get('test_id', '')} "
                    f"{cand.get('title', '')} "
                    f"{cand.get('endpoint', {}).get('url', '')}"
                ).lower()
                if active_keyword_filter not in combined_text:
                    continue
            displayed.append(cand)

        console.print(f"\n[bold cyan]✦ PROJECT 4 — VALIDATION & CONTROLLED EXPLOITATION ✦[/bold cyan]")
        console.print(f"[bold cyan]Assessment :[/bold cyan] [bold white]{assessment_name}[/bold white]")
        console.print(f"[bold cyan]Candidates :[/bold cyan] {len(candidates)} candidate(s) queued across {len(sorted_hosts)} host(s)\n")

        if len(sorted_hosts) > 1:
            dom_table = Table(
                title="[bold cyan]Host & Subdomain Targets[/bold cyan]",
                box=ROUNDED,
                border_style="cyan",
                header_style="bold cyan",
                padding=(0, 1),
            )
            dom_table.add_column("Tag", style="bold yellow", width=6)
            dom_table.add_column("Host / Subdomain", style="bold white", width=40)
            dom_table.add_column("Queue Count", style="bold green", justify="center", width=12)

            for host in sorted_hosts:
                tag = domain_tags[host]
                c_count = len(domain_groups[host])
                dom_table.add_row(f"[{tag}]", host, f"{c_count} candidate(s)")
            console.print(dom_table)

        if active_domain_filter or active_keyword_filter:
            filter_desc = []
            if active_domain_filter:
                filter_desc.append(f"domain: '{active_domain_filter}'")
            if active_keyword_filter:
                filter_desc.append(f"keyword: '{active_keyword_filter}'")
            console.print(
                f"\n[bold yellow]Active Filter:[/bold yellow] {', '.join(filter_desc)} "
                f"→ Showing {len(displayed)} of {len(candidates)} candidate(s)"
            )

        if not displayed:
            console.print(f"\n{GLYPH_WARN} [yellow]No candidates match current active filter.[/yellow]")
            console.print("Type 'clear' to reset filters, or '0' to return.")
        else:
            cand_table = Table(
                title=f"[bold cyan]Validation Candidates Queue ({len(displayed)} in view)[/bold cyan]",
                box=ROUNDED,
                border_style="cyan",
                header_style="bold cyan",
                padding=(0, 1),
            )
            cand_table.add_column("#", style="bold yellow", width=4, justify="right")
            cand_table.add_column("Host", style="bold cyan", width=8)
            cand_table.add_column("Check ID", style="bold white", width=10)
            cand_table.add_column("Severity", width=12)
            cand_table.add_column("Vulnerability Candidate", style="bold white")
            cand_table.add_column("Live Proof Status", width=18)

            for index, candidate in enumerate(displayed, start=1):
                endpoint = candidate.get("endpoint") or {}
                host = _extract_host(candidate)
                tag = domain_tags.get(host, "D?")

                rid = candidate.get("result_id", "")
                if rid in history:
                    decision = str(history[rid].get("decision", "")).upper()
                    if decision == "CONFIRMED":
                        status_str = "[bold green]✔ CONFIRMED[/bold green]"
                    elif decision == "NOT_CONFIRMED":
                        status_str = "[bold red]✖ REFUTED[/bold red]"
                    else:
                        status_str = f"[bold yellow]◌ {decision}[/bold yellow]"
                else:
                    status_str = "[bold dim yellow]◌ PENDING[/bold dim yellow]"

                conf = candidate.get("confidence") or "MEDIUM"
                cand_table.add_row(
                    str(index),
                    f"[{tag}]",
                    candidate["test_id"],
                    format_severity(conf),
                    candidate["title"],
                    status_str,
                )

            console.print(cand_table)

        cmd_table = Table(
            box=SIMPLE,
            show_header=False,
            padding=(0, 1),
        )
        cmd_table.add_column("Command Type", style="bold cyan", width=26)
        cmd_table.add_column("Syntax Example", style="bold yellow", width=22)
        cmd_table.add_column("Action", style="dim white")

        cmd_table.add_row("Single / Range / List", "1  or  1-5  or  1,3,7", "Validate selected candidate(s)")
        cmd_table.add_row("Subdomain Tag", "D1  or  D1,D2", "Validate all candidates under tagged subdomain")
        cmd_table.add_row("Batch All", "all  or  *", "Validate all candidates currently in view")
        cmd_table.add_row("Filter Subdomain / Keyword", "d api  or  f auth", "Filter candidate queue by host or vulnerability")
        cmd_table.add_row("Clear Filter", "clear  or  reset", "Reset view to all candidates")
        cmd_table.add_row("Back to Assessment", "0  or  back", "Return to assessment menu")

        cmd_panel = Panel(
            cmd_table,
            title="[bold cyan]Validation Navigation & Batch Controls[/bold cyan]",
            border_style="cyan",
            box=ROUNDED,
            padding=(0, 1),
        )
        console.print(cmd_panel)

        try:
            choice = input("Select candidate(s)> ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return

        selected, command = _parse_candidate_selection(
            choice,
            displayed,
            domain_tags,
            tag_to_candidates,
        )

        if command == "BACK":
            return

        if command == "CLEAR_FILTER":
            active_domain_filter = None
            active_keyword_filter = None
            continue

        if command and command.startswith("DOMAIN_FILTER:"):
            term = command.split(":", 1)[1].strip().lower()
            active_domain_filter = term if term else None
            continue

        if command and command.startswith("KEYWORD_FILTER:"):
            term = command.split(":", 1)[1].strip().lower()
            active_keyword_filter = term if term else None
            continue

        if command and command.startswith("ERROR:"):
            console.print(f"\n{GLYPH_FAIL} [red]{command[6:].strip()}[/red]")
            input("Press Enter to continue...")
            continue

        if not selected:
            console.print(f"\n{GLYPH_WARN} [yellow]No candidates selected.[/yellow]")
            input("Press Enter to continue...")
            continue

        # Single Candidate Confirmation & Execution
        if len(selected) == 1:
            item = selected[0]
            url = item.get("endpoint", {}).get("url", "")
            console.print(f"\n{GLYPH_INFO} [bold cyan]Selected Candidate for Verification:[/bold cyan]")
            console.print(f"  • Test ID  : [bold white]{item['test_id']}[/bold white]")
            console.print(f"  • Title    : [bold white]{item['title']}[/bold white]")
            console.print(f"  • Endpoint : [dim]{url}[/dim]")
            console.print(f"\n{GLYPH_INFO} Project 4 will perform bounded, non-destructive live verification.")

            try:
                confirm = input("\nRun live validation? [Y/n]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                return

            if confirm and confirm != "y":
                console.print(f"{GLYPH_WARN} [yellow]Validation cancelled.[/yellow]")
                continue

            try:
                result_path = run_project_4_validation(
                    assessment_name,
                    test_id=item["test_id"],
                    target_id=item["target_id"],
                    endpoint_id=item["endpoint_id"],
                    result_id=item["result_id"],
                    runs_directory=runs_directory,
                )
                console.print(f"\n{GLYPH_SUCCESS} [bold green]Live validation completed.[/bold green]")

                history_now = _load_validation_history(
                    assessment_name,
                    runs_directory,
                )
                rec = history_now.get(item["result_id"], {})
                decision = str(rec.get("decision", "COMPLETED")).upper()
                is_conf = decision == "CONFIRMED" or bool(rec.get("confirmed"))
                severity = rec.get("severity") or item.get("confidence") or "HIGH"
                reason = rec.get("reason") or rec.get("observation", "Proof evaluated against target response.")
                evidence = rec.get("observable_evidence") or rec.get("proof") or rec.get("observation")

                render_validation_decision_card(
                    test_id=item["test_id"],
                    confirmed=is_conf,
                    reason=reason,
                    severity=severity,
                    target_url=url,
                    evidence_snippet=str(evidence) if evidence else None,
                )
            except Exception as exc:
                console.print(f"\n{GLYPH_FAIL} [red]Validation failed: {exc}[/red]")

        else:
            sel_hosts: dict[str, int] = {}
            for c in selected:
                h = _extract_host(c)
                sel_hosts[h] = sel_hosts.get(h, 0) + 1

            console.print(f"\n{GLYPH_INFO} [bold cyan]Batch Validation Execution:[/bold cyan] {len(selected)} candidate(s) selected")
            for h, count in sel_hosts.items():
                console.print(f"  • {h}: [bold yellow]{count}[/bold yellow] candidate(s)")

            console.print(f"\n{GLYPH_INFO} Controlled non-destructive live validation will run across all {len(selected)} candidates.")

            try:
                confirm = input(f"\nRun batch validation on {len(selected)} candidates? [Y/n]: ").strip().lower()
            except (KeyboardInterrupt, EOFError):
                return

            if confirm and confirm != "y":
                console.print(f"{GLYPH_WARN} [yellow]Batch validation cancelled.[/yellow]")
                continue

            try:
                selected_rids = [c["result_id"] for c in selected]
                result_path = run_project_4_batch_validation(
                    assessment_name,
                    result_ids=selected_rids,
                    runs_directory=runs_directory,
                )
                console.print(f"\n{GLYPH_SUCCESS} [bold green]Batch validation completed.[/bold green]")

                history_now = _load_validation_history(
                    assessment_name,
                    runs_directory,
                )

                batch_table = Table(
                    title="[bold cyan]Batch Validation Results[/bold cyan]",
                    box=ROUNDED,
                    border_style="cyan",
                    header_style="bold cyan",
                    padding=(0, 1),
                )
                batch_table.add_column("Check ID", style="bold cyan", width=12)
                batch_table.add_column("Vulnerability Title", style="bold white")
                batch_table.add_column("Validation Verdict", width=22)

                conf_count = 0
                not_conf_count = 0
                for c in selected:
                    rid = c["result_id"]
                    rec = history_now.get(rid, {})
                    dec = str(rec.get("decision", "UNKNOWN")).upper()
                    if dec == "CONFIRMED":
                        conf_count += 1
                        v_badge = "[bold green]✔ CONFIRMED EXPLOIT[/bold green]"
                    elif dec == "NOT_CONFIRMED":
                        not_conf_count += 1
                        v_badge = "[bold red]✖ NOT CONFIRMED[/bold red]"
                    else:
                        v_badge = f"[bold yellow]◌ {dec}[/bold yellow]"
                    batch_table.add_row(c["test_id"], c["title"], v_badge)

                console.print(batch_table)

                summary_panel = Panel(
                    f"Total Candidates Validated : [bold white]{len(selected)}[/bold white]\n"
                    f"Confirmed Live Exploits     : [bold green]{conf_count}[/bold green]\n"
                    f"Refuted / Safe Findings     : [bold red]{not_conf_count}[/bold red]",
                    title="[bold green]✦ Batch Execution Summary ✦[/bold green]" if conf_count > 0 else "[bold cyan]✦ Batch Execution Summary ✦[/bold cyan]",
                    border_style="green" if conf_count > 0 else "cyan",
                    box=ROUNDED,
                    padding=(1, 2),
                )
                console.print(summary_panel)
            except Exception as exc:
                console.print(f"\n{GLYPH_FAIL} [red]Batch validation failed: {exc}[/red]")

        try:
            input("\nPress Enter to return to Project 4 menu...")
        except (KeyboardInterrupt, EOFError):
            pass

