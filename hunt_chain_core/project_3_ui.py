from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from rich.box import ROUNDED, SIMPLE
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from hunt_chain_core.project_3_execution import (
    run_project_3,
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
    render_categories_grid,
    render_finding_card,
)

CATEGORIES: list[dict[str, object]] = [
    {
        "index": 1,
        "code": "ATO",
        "name": "Account Takeover",
        "checks": 8,
        "ids": [f"ATO-0{i}" for i in range(1, 9)],
        "aliases": ["ato", "account", "account takeover"],
    },
    {
        "index": 2,
        "code": "AUTH",
        "name": "Authentication Bypass",
        "checks": 10,
        "ids": [f"AUTH-{i:02d}" for i in range(1, 11)],
        "aliases": ["auth", "authentication", "bypass"],
    },
    {
        "index": 3,
        "code": "BOPLA",
        "name": "Mass Assignment / BOPLA",
        "checks": 8,
        "ids": [f"BOPLA-0{i}" for i in range(1, 9)],
        "aliases": ["bopla", "mass assignment", "object property"],
    },
    {
        "index": 4,
        "code": "BUSINESS",
        "name": "Business Logic",
        "checks": 10,
        "ids": [f"BUSINESS-{i:02d}" for i in range(1, 11)],
        "aliases": ["business", "logic", "business logic"],
    },
    {
        "index": 5,
        "code": "CLICK",
        "name": "Clickjacking",
        "checks": 4,
        "ids": [f"CLICK-0{i}" for i in range(1, 5)],
        "aliases": ["click", "clickjacking"],
    },
    {
        "index": 6,
        "code": "CORS",
        "name": "CORS Misconfiguration",
        "checks": 6,
        "ids": [f"CORS-0{i}" for i in range(1, 7)],
        "aliases": ["cors"],
    },
    {
        "index": 7,
        "code": "CSRF",
        "name": "CSRF",
        "checks": 7,
        "ids": [f"CSRF-0{i}" for i in range(1, 8)],
        "aliases": ["csrf", "xsrf"],
    },
    {
        "index": 8,
        "code": "BFLA",
        "name": "Function Auth / BFLA",
        "checks": 8,
        "ids": [f"BFLA-0{i}" for i in range(1, 9)],
        "aliases": ["bfla", "function auth", "function authorization"],
    },
    {
        "index": 9,
        "code": "IDOR",
        "name": "IDOR / BOLA",
        "checks": 10,
        "ids": [f"IDOR-{i:02d}" for i in range(1, 11)],
        "aliases": ["idor", "bola"],
    },
    {
        "index": 10,
        "code": "INFO",
        "name": "Information Disclosure",
        "checks": 8,
        "ids": [f"INFO-0{i}" for i in range(1, 9)],
        "aliases": ["info", "disclosure", "information disclosure"],
    },
    {
        "index": 11,
        "code": "INVENTORY",
        "name": "Inventory Management",
        "checks": 6,
        "ids": [f"INVENTORY-0{i}" for i in range(1, 7)],
        "aliases": ["inventory", "inventory management"],
    },
    {
        "index": 12,
        "code": "REDIRECT",
        "name": "Open Redirect",
        "checks": 6,
        "ids": [f"REDIRECT-0{i}" for i in range(1, 7)],
        "aliases": ["redirect", "open redirect"],
    },
    {
        "index": 13,
        "code": "PATH",
        "name": "Path Traversal / Upload",
        "checks": 8,
        "ids": [f"PATH-0{i}" for i in range(1, 9)],
        "aliases": ["path", "traversal", "upload", "path traversal"],
    },
    {
        "index": 14,
        "code": "RCE",
        "name": "Remote Code Execution",
        "checks": 8,
        "ids": [f"RCE-0{i}" for i in range(1, 9)],
        "aliases": ["rce", "command injection", "code execution"],
    },
    {
        "index": 15,
        "code": "RESOURCE",
        "name": "Rate Limit / Resource",
        "checks": 6,
        "ids": [f"RESOURCE-0{i}" for i in range(1, 7)],
        "aliases": ["resource", "rate limit", "dos", "consumption"],
    },
    {
        "index": 16,
        "code": "MISCONFIG",
        "name": "Security Misconfig",
        "checks": 8,
        "ids": [f"MISCONFIG-0{i}" for i in range(1, 9)],
        "aliases": ["misconfig", "security misconfiguration", "config"],
    },
    {
        "index": 17,
        "code": "SQLI",
        "name": "SQL Injection",
        "checks": 10,
        "ids": [f"SQLI-{i:02d}" for i in range(1, 11)],
        "aliases": ["sqli", "sql", "sql injection"],
    },
    {
        "index": 18,
        "code": "SSRF",
        "name": "SSRF",
        "checks": 10,
        "ids": [f"SSRF-{i:02d}" for i in range(1, 11)],
        "aliases": ["ssrf", "server side request forgery"],
    },
    {
        "index": 19,
        "code": "SUBDOMAIN",
        "name": "Subdomain Takeover",
        "checks": 5,
        "ids": [f"SUBDOMAIN-0{i}" for i in range(1, 6)],
        "aliases": ["subdomain", "takeover", "subdomain takeover"],
    },
    {
        "index": 20,
        "code": "THIRD",
        "name": "Third-Party API",
        "checks": 7,
        "ids": [f"THIRD-0{i}" for i in range(1, 8)],
        "aliases": ["third", "third party", "api"],
    },
    {
        "index": 21,
        "code": "XSS",
        "name": "Cross-Site Scripting",
        "checks": 8,
        "ids": [f"XSS-0{i}" for i in range(1, 9)],
        "aliases": ["xss", "cross site scripting"],
    },
    {
        "index": 22,
        "code": "XXE",
        "name": "XML External Entity",
        "checks": 7,
        "ids": [f"XXE-0{i}" for i in range(1, 8)],
        "aliases": ["xxe", "xml"],
    },
]


def _print_categories_table() -> None:
    render_categories_grid(CATEGORIES)


def _resolve_categories(user_input: str) -> tuple[list[str] | None, list[str]]:
    import re

    cleaned = user_input.strip()
    if not cleaned:
        default_cat = CATEGORIES[16]  # SQL Injection default
        return list(default_cat["ids"]), [f"{default_cat['name']} ({default_cat['code']})"]

    if cleaned in ("0", "back"):
        return [], ["Back"]

    if cleaned.lower() == "all":
        return None, ["All 22 Categories (Full Scan)"]

    if cleaned.lower() in ("critical", "high"):
        high_codes = {"RCE", "SQLI", "SSRF", "ATO", "AUTH", "IDOR"}
        crit_ids = [tid for c in CATEGORIES if c["code"] in high_codes for tid in c["ids"]]
        crit_names = [f"{c['name']} ({c['code']})" for c in CATEGORIES if c["code"] in high_codes]
        return crit_ids, crit_names

    if cleaned.lower() == "owasp":
        owasp_codes = {"SQLI", "AUTH", "IDOR", "MISCONFIG", "XSS", "SSRF", "BOPLA", "BFLA"}
        o_ids = [tid for c in CATEGORIES if c["code"] in owasp_codes for tid in c["ids"]]
        o_names = [f"{c['name']} ({c['code']})" for c in CATEGORIES if c["code"] in owasp_codes]
        return o_ids, o_names

    matched_ids: list[str] = []
    matched_names: list[str] = []
    seen_codes: set[str] = set()
    all_known_ids = {tid for c in CATEGORIES for tid in c["ids"]}

    phrases = [p.strip() for p in re.split(r"[,;]+", cleaned) if p.strip()]

    def try_match_token(tok: str) -> bool:
        lower_tok = tok.lower()
        if lower_tok == "all":
            return False

        # Range format e.g. 1-5
        if "-" in tok and not tok.upper().startswith(tuple(c["code"] for c in CATEGORIES)):
            parts = tok.split("-", 1)
            if parts[0].isdigit() and parts[1].isdigit():
                start, end = int(parts[0]), int(parts[1])
                if start > end:
                    start, end = end, start
                range_matched = False
                for idx in range(start, end + 1):
                    for cat in CATEGORIES:
                        if cat["index"] == idx:
                            if cat["code"] not in seen_codes:
                                seen_codes.add(cat["code"])
                                matched_ids.extend(cat["ids"])
                                matched_names.append(f"{cat['name']} ({cat['code']})")
                            range_matched = True
                            break
                if range_matched:
                    return True

        for cat in CATEGORIES:
            if (
                str(cat["index"]) == tok
                or cat["code"].lower() == lower_tok
                or lower_tok in [a.lower() for a in cat["aliases"]]
            ):
                if cat["code"] not in seen_codes:
                    seen_codes.add(cat["code"])
                    matched_ids.extend(cat["ids"])
                    matched_names.append(f"{cat['name']} ({cat['code']})")
                return True

        upper_tok = tok.upper()
        if upper_tok in all_known_ids:
            if upper_tok not in seen_codes:
                seen_codes.add(upper_tok)
                matched_ids.append(upper_tok)
                matched_names.append(upper_tok)
            return True

        return False

    for phrase in phrases:
        if phrase.lower() == "all":
            return None, ["All 22 Categories (Full Scan)"]

        if try_match_token(phrase):
            continue

        sub_tokens = [t.strip() for t in phrase.split() if t.strip()]
        for sub_tok in sub_tokens:
            try_match_token(sub_tok)

    if not matched_ids:
        default_cat = CATEGORIES[16]
        return list(default_cat["ids"]), [f"{default_cat['name']} ({default_cat['code']})"]

    return matched_ids, matched_names


def _load_result_summary(
    result_path: Path,
) -> dict[str, Any]:
    if not result_path.is_file():
        return {}

    try:
        with result_path.open(
            "r",
            encoding="utf-8-sig",
        ) as handle:
            data = json.load(handle)
    except (OSError, ValueError, TypeError):
        return {}

    results = data.get("results", [])

    summary: dict[str, Any] = {
        "total": len(results),
        "confirmed": 0,
        "potential": 0,
        "not_detected": 0,
        "skipped": 0,
        "error": 0,
        "findings": [],
    }

    for result in results:
        status = str(result.get("status", "")).upper()
        meta = result.get("metadata", {})
        url = meta.get("url") or meta.get("target_url")
        params = meta.get("candidate_parameters") or meta.get("parameters") or []
        param_str = ", ".join(params) if isinstance(params, list) else str(params)

        if status in ("CONFIRMED", "FAIL"):
            summary["confirmed"] += 1
            summary["findings"].append({
                "status": "CONFIRMED",
                "test_id": result.get("test_id", "UNKNOWN"),
                "title": result.get("title", ""),
                "severity": result.get("severity") or result.get("confidence") or "HIGH",
                "observation": result.get("observation", ""),
                "url": url,
                "parameter": param_str or None,
            })
        elif status == "POTENTIAL":
            summary["potential"] += 1
            summary["findings"].append({
                "status": "POTENTIAL",
                "test_id": result.get("test_id", "UNKNOWN"),
                "title": result.get("title", ""),
                "severity": result.get("confidence") or "MEDIUM",
                "observation": result.get("observation", ""),
                "url": url,
                "parameter": param_str or None,
            })
        elif status in ("NOT_DETECTED", "PASS"):
            summary["not_detected"] += 1
        elif status == "SKIPPED":
            summary["skipped"] += 1
        elif status == "ERROR":
            summary["error"] += 1
        else:
            summary["not_detected"] += 1

    return summary


def _run_project_3(
    manager: Any,
    assessment_name: str,
) -> None:
    console.print(f"\n[bold cyan]✦ PROJECT 3 — VULNERABILITY TESTING ✦[/bold cyan]")

    runs_directory = Path(manager.runs_directory).resolve()
    assessment_directory = (runs_directory / assessment_name).resolve()

    authorization_artifact = assessment_directory / "authorization_result.json"
    attack_surface_artifact = assessment_directory / "attack_surface.json"
    result_path = assessment_directory / "vulnerability_result.json"

    if not authorization_artifact.is_file():
        console.print(f"\n{GLYPH_FAIL} [red]Project 1 authorization result does not exist.[/red]")
        console.print(f"{GLYPH_INFO} Run ScopeGuard (Stage 1) first.")
        return

    if not attack_surface_artifact.is_file():
        console.print(f"\n{GLYPH_FAIL} [red]Project 2 attack surface does not exist.[/red]")
        console.print(f"{GLYPH_INFO} Run Reconnaissance (Stage 2) first.")
        return

    scope_table = Table(
        box=ROUNDED,
        border_style="cyan",
        show_header=False,
        padding=(0, 2),
    )
    scope_table.add_column("Option", style="bold yellow", width=6, justify="right")
    scope_table.add_column("Testing Scope", style="bold white", width=28)
    scope_table.add_column("Details", style="dim white")

    scope_table.add_row("[1]", "Full Scan (All Categories)", "Run all 168 registered checks across all 22 families")
    scope_table.add_row("[2]", "Select Vulnerability Family", "Choose one or more categories (e.g. SQLI, XSS, ATO, or 1-22)")
    scope_table.add_row("[3]", "Specific Tester ID(s)", "Target precise checks (e.g. SQLI-08, ATO-01, CORS-02)")
    scope_table.add_row("[0]", "Back", "Return to assessment menu")

    console.print("\n[bold cyan]Select Vulnerability Testing Scope[/bold cyan]")
    console.print(scope_table)

    try:
        scope_choice = input("Select testing scope [0-3, default=1]: ").strip()
    except (EOFError, KeyboardInterrupt):
        return

    if scope_choice in ("0", "back"):
        return

    test_ids: list[str] | None = None
    if scope_choice == "2":
        _print_categories_table()
        try:
            cat_choice = input(
                "\nSelect category number(s) or code(s) (e.g. 17 or SQLI or 1,2,17) [0=Back, default=17]: "
            ).strip()
        except (EOFError, KeyboardInterrupt):
            return

        if cat_choice in ("0", "back"):
            return
        test_ids, matched_names = _resolve_categories(cat_choice)
        if test_ids is None:
            console.print(f"\n{GLYPH_INFO} Running all 168 registered vulnerability testers (Full scan)...")
        else:
            console.print(f"\n{GLYPH_INFO} Selected: [bold white]{', '.join(matched_names)}[/bold white]")
            console.print(f"{GLYPH_INFO} Running {len(test_ids)} check(s)...")
    elif scope_choice == "3":
        try:
            custom = input("Enter tester ID(s) separated by spaces [e.g. SQLI-08 ATO-01, 0=Back]: ").strip()
        except (EOFError, KeyboardInterrupt):
            return

        if custom in ("0", "back"):
            return
        if custom:
            test_ids = [tid.strip().upper() for tid in custom.replace(",", " ").split() if tid.strip()]
            console.print(f"\n{GLYPH_INFO} Running custom test IDs: {', '.join(test_ids)} ({len(test_ids)} checks)...")
        else:
            console.print(f"\n{GLYPH_INFO} No test IDs specified. Running all 168 testers...")
    elif scope_choice in ("1", "", "all"):
        console.print(f"\n{GLYPH_INFO} Running all 168 registered vulnerability testers (Full scan)...")
    else:
        resolved_ids, matched_names = _resolve_categories(scope_choice)
        if resolved_ids and len(resolved_ids) < 168:
            test_ids = resolved_ids
            console.print(f"\n{GLYPH_INFO} Selected: [bold white]{', '.join(matched_names)}[/bold white]")
            console.print(f"{GLYPH_INFO} Running {len(test_ids)} check(s)...")
        else:
            console.print(f"\n{GLYPH_INFO} Running all 168 registered vulnerability testers...")

    console.print(f"{GLYPH_INFO} Using Project 1 authorization & Project 2 attack surface...")

    try:
        run_project_3(
            assessment_name,
            runs_directory=runs_directory,
            test_ids=test_ids,
            cookie=None,
        )
    except (FileNotFoundError, RuntimeError, ValueError, OSError) as exc:
        console.print(f"\n{GLYPH_FAIL} [red]Project 3 FAILED: {exc}[/red]")
        return

    console.print(f"\n{GLYPH_SUCCESS} [bold green]Project 3 Testing Completed Successfully.[/bold green]")

    summary = _load_result_summary(result_path)

    if summary:
        stats_table = Table(
            title="[bold cyan]Vulnerability Testing Execution Metrics[/bold cyan]",
            box=ROUNDED,
            border_style="cyan",
            header_style="bold cyan",
            padding=(0, 2),
        )
        stats_table.add_column("Metric", style="bold white", width=26)
        stats_table.add_column("Count", style="bold yellow", width=10, justify="center")
        stats_table.add_column("Assessment Impact", style="bold cyan")

        stats_table.add_row("Total Checks Run", str(summary["total"]), "All targeted test signatures evaluated")
        if summary.get("confirmed", 0) > 0:
            stats_table.add_row("Directly Confirmed", f"[bold red]{summary['confirmed']}[/bold red]", "[bold red]Exploits verified directly in testing[/bold red]")
        if summary.get("potential", 0) > 0:
            stats_table.add_row("Potential Candidates", f"[bold yellow]{summary['potential']}[/bold yellow]", "[bold yellow]Candidates queued for Project 4 Live Validation[/bold yellow]")
        stats_table.add_row("Passed / Clean", str(summary["not_detected"]), "No vulnerability indicator observed")
        if summary.get("error", 0) > 0:
            stats_table.add_row("Errors / Timeouts", str(summary["error"]), "Target connection or endpoint timeout")
        if summary.get("skipped", 0) > 0:
            stats_table.add_row("Skipped Checks", str(summary["skipped"]), "Requirements not met by attack surface")

        console.print(stats_table)

        findings = summary.get("findings", [])
        if findings:
            console.print("\n[bold green]✦ Discovered Findings ✦[/bold green]")
            if len(findings) <= 5:
                for f in findings:
                    render_finding_card(
                        test_id=f["test_id"],
                        title=f["title"],
                        status=f["status"],
                        observation=f.get("observation") or "Potential vulnerability indicator detected during targeted checks.",
                        severity=f["severity"],
                        url=f.get("url"),
                        parameter=f.get("parameter"),
                    )
            else:
                f_table = Table(
                    box=ROUNDED,
                    border_style="cyan",
                    header_style="bold cyan",
                    padding=(0, 1),
                )
                f_table.add_column("Severity", width=14)
                f_table.add_column("Status", width=14)
                f_table.add_column("Check ID", style="bold cyan", width=12)
                f_table.add_column("Vulnerability Finding", style="bold white")

                for f in findings:
                    st_badge = "[bold green]CONFIRMED[/bold green]" if f["status"] == "CONFIRMED" else "[bold yellow]POTENTIAL[/bold yellow]"
                    f_table.add_row(format_severity(f["severity"]), st_badge, f["test_id"], f["title"])
                console.print(f_table)

        if summary.get("potential", 0) > 0:
            advice_panel = Panel(
                f"[bold yellow]→ NEXT STEP: Proceed to Project 4 (Validation & Controlled Exploitation)[/bold yellow]\n\n"
                f"[white]{summary['potential']} potential vulnerability candidate(s) are ready for bounded live validation.\n"
                f"Validation tests live exploitability safely with observable proof.[/white]",
                title="[bold yellow]Pipeline Recommendation[/bold yellow]",
                border_style="yellow",
                box=ROUNDED,
                padding=(1, 2),
            )
            console.print(advice_panel)
        elif summary.get("confirmed", 0) > 0:
            advice_panel = Panel(
                f"[bold green]→ FINDINGS CONFIRMED: Vulnerabilities directly proven.[/bold green]\n\n"
                f"[white]Vulnerabilities were proven during testing. Audit logs are preserved in assessment artifacts.[/white]",
                title="[bold green]Confirmed Findings[/bold green]",
                border_style="green",
                box=ROUNDED,
                padding=(1, 2),
            )
            console.print(advice_panel)

    console.print(f"\n{GLYPH_INFO} Artifact saved: [dim]{result_path}[/dim]")

