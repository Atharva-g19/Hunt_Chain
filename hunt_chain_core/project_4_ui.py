"""Interactive Project 4 validation UI with subdomain filtering and batch execution."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from hunt_chain_core.project_4_execution import (
    list_project4_candidates,
    run_project_4_batch_validation,
    run_project_4_validation,
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
    manager,
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
            print(f"\nCannot load Project 3 findings: {exc}")
            return

        if not candidates:
            print(
                "\nNo Project 3 POTENTIAL findings require validation."
            )
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

        print("\n" + "=" * 65)
        print("Project 4 — Validation & Controlled Exploitation")
        print("=" * 65)
        print(f"Assessment  : {assessment_name}")
        print(
            f"Candidates  : {len(candidates)} total across "
            f"{len(sorted_hosts)} subdomain(s)"
        )

        if len(sorted_hosts) > 1:
            print("\nSubdomain Breakdown:")
            for host in sorted_hosts:
                tag = domain_tags[host]
                c_count = len(domain_groups[host])
                print(f"  [{tag}] {host:<42s} ({c_count:2d} candidates)")

        if active_domain_filter or active_keyword_filter:
            filter_desc = []
            if active_domain_filter:
                filter_desc.append(f"domain: '{active_domain_filter}'")
            if active_keyword_filter:
                filter_desc.append(f"keyword: '{active_keyword_filter}'")
            print(
                f"\n[Active Filter: {', '.join(filter_desc)}] "
                f"-> Showing {len(displayed)} of {len(candidates)} candidates"
            )

        print("-" * 65)

        if not displayed:
            print("No candidates match current active filter.")
            print("Type 'clear' to reset filters, or '0' to go back.")
        else:
            for index, candidate in enumerate(displayed, start=1):
                endpoint = candidate.get("endpoint") or {}
                host = _extract_host(candidate)
                tag = domain_tags.get(host, "D?")

                rid = candidate.get("result_id", "")
                if rid in history:
                    decision = history[rid].get("decision", "")
                    if decision == "CONFIRMED":
                        status_str = "[VULNERABLE / CONFIRMED]"
                    elif decision == "NOT_CONFIRMED":
                        status_str = "[NOT CONFIRMED]"
                    else:
                        status_str = f"[{decision}]"
                else:
                    status_str = "[PENDING]"

                print(
                    f"{index:2d}. [{tag}] {candidate['test_id']} | "
                    f"{candidate.get('confidence') or 'UNKNOWN'} | "
                    f"{candidate['title']}  {status_str}"
                )
                print(
                    f"    {endpoint.get('method', 'GET')} "
                    f"{endpoint.get('url', '')}"
                )
                print(
                    f"    result_id={candidate['result_id']}"
                )

        print("-" * 65)
        print("Selection & Batch Commands:")
        print("  • Single / Range / List  : 1   or   1-5   or   1,3,7-10")
        print("  • By Subdomain Tag       : D1  or   D1,D3")
        print("  • All Candidates         : 'all' / '*' (validates all in view)")
        print("  • Filter by Subdomain    : d <host>  (e.g. 'd api' or 'd admin')")
        print("  • Filter by Keyword      : f <term>  (e.g. 'f auth' or 'f idor')")
        print("  • Clear Filter           : 'clear' / 'reset'")
        print("  • 0 / Back               : Return to Assessment Menu")
        print("-" * 65)

        try:
            choice = input("Select candidate(s): ").strip()
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
            print(f"\n{command[6:].strip()}")
            input("Press Enter to continue...")
            continue

        if not selected:
            print("\nNo candidates selected.")
            input("Press Enter to continue...")
            continue

        # Confirmation
        if len(selected) == 1:
            item = selected[0]
            print("\nSelected finding:")
            print(f"  Test ID : {item['test_id']}")
            print(f"  Target  : {item['target_id']}")
            print(f"  Endpoint: {item['endpoint_id']}")
            print(f"  Title   : {item['title']}")
            print(
                f"  URL     : {item.get('endpoint', {}).get('url', '')}"
            )
            print()
            print(
                "Project 4 will perform bounded live validation defined "
                "by the candidate's Project 4 validation profile."
            )
            confirm = input("Run validation? [Y/n]: ").strip().lower()
            if confirm and confirm != "y":
                print("Validation cancelled.")
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
                print(f"\n[+] Validation completed.")
                print(f"Output: {result_path}")
            except Exception as exc:
                print(f"\n[-] Validation failed: {exc}")

        else:
            sel_hosts: dict[str, int] = {}
            for c in selected:
                h = _extract_host(c)
                sel_hosts[h] = sel_hosts.get(h, 0) + 1

            print(f"\nBatch Validation Selected: {len(selected)} candidate(s)")
            print(f"Subdomain breakdown ({len(sel_hosts)} subdomain(s)):")
            for h, count in sel_hosts.items():
                print(f"  • {h}: {count} candidate(s)")
            print()
            print(
                f"Project 4 will perform bounded live validation "
                f"across all {len(selected)} selected candidates in batch."
            )
            confirm = input(
                f"Run batch validation on {len(selected)} candidates? [Y/n]: "
            ).strip().lower()
            if confirm and confirm != "y":
                print("Batch validation cancelled.")
                continue

            try:
                selected_rids = [c["result_id"] for c in selected]
                result_path = run_project_4_batch_validation(
                    assessment_name,
                    result_ids=selected_rids,
                    runs_directory=runs_directory,
                )
                print(f"\n[+] Batch validation completed.")
                print(f"Output: {result_path}")
            except Exception as exc:
                print(f"\n[-] Batch validation failed: {exc}")

        input("\nPress Enter to return to Project 4 menu...")
