from __future__ import annotations

import json
from pathlib import Path

from hunt_chain_core.project_3_execution import (
    run_project_3,
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
    print()
    print("=" * 84)
    print("Vulnerability Categories (22 Families / 168 Checks):")
    print("=" * 84)
    half = (len(CATEGORIES) + 1) // 2
    for i in range(half):
        c1 = CATEGORIES[i]
        tag1 = f"[{c1['code']}]"
        col1 = f"  {c1['index']:2d}. {tag1:<11s} {c1['name']} ({c1['checks']})"
        if i + half < len(CATEGORIES):
            c2 = CATEGORIES[i + half]
            tag2 = f"[{c2['code']}]"
            col2 = f"  {c2['index']:2d}. {tag2:<11s} {c2['name']} ({c2['checks']})"
            print(f"{col1:<46s} {col2}")
        else:
            print(col1)
    print("=" * 84)


def _resolve_categories(user_input: str) -> tuple[list[str] | None, list[str]]:
    import re

    cleaned = user_input.strip()
    if not cleaned:
        default_cat = CATEGORIES[16]  # SQL Injection default
        return list(default_cat["ids"]), [f"{default_cat['name']} ({default_cat['code']})"]

    tokens = [t.strip().lower() for t in re.split(r"[,; ]+", cleaned) if t.strip()]
    if "all" in tokens or "0" in tokens:
        return None, ["All 22 Categories (Full Scan)"]

    matched_ids: list[str] = []
    matched_names: list[str] = []
    seen_codes: set[str] = set()

    for tok in tokens:
        found = False
        for cat in CATEGORIES:
            if (
                str(cat["index"]) == tok
                or cat["code"].lower() == tok
                or tok in cat["aliases"]
            ):
                if cat["code"] not in seen_codes:
                    seen_codes.add(cat["code"])
                    matched_ids.extend(cat["ids"])
                    matched_names.append(f"{cat['name']} ({cat['code']})")
                found = True
                break

        if not found:
            upper_tok = tok.upper()
            all_known_ids = {tid for c in CATEGORIES for tid in c["ids"]}
            if upper_tok in all_known_ids:
                if upper_tok not in seen_codes:
                    seen_codes.add(upper_tok)
                    matched_ids.append(upper_tok)
                    matched_names.append(upper_tok)

    if not matched_ids:
        default_cat = CATEGORIES[16]
        return list(default_cat["ids"]), [f"{default_cat['name']} ({default_cat['code']})"]

    return matched_ids, matched_names


def _load_result_summary(
    result_path: Path,
) -> dict[str, int]:
    if not result_path.is_file():
        return {}

    try:
        with result_path.open(
            "r",
            encoding="utf-8",
        ) as handle:
            data = json.load(handle)
    except (OSError, ValueError, TypeError):
        return {}

    results = data.get("results", [])

    summary = {
        "total": len(results),
        "not_detected": 0,
        "potential": 0,
        "skipped": 0,
    }

    for result in results:
        status = str(
            result.get("status", "")
        ).upper()

        if status == "NOT_DETECTED":
            summary["not_detected"] += 1
        elif status == "POTENTIAL":
            summary["potential"] += 1
        elif status == "SKIPPED":
            summary["skipped"] += 1

    return summary


def _run_project_3(
    manager,
    assessment_name: str,
) -> None:
    print()
    print("=" * 60)
    print("Project 3 — Vulnerability Testing")
    print("=" * 60)

    runs_directory = (
        Path(
            manager.runs_directory
        ).resolve()
    )

    assessment_directory = (
        runs_directory / assessment_name
    ).resolve()

    authorization_artifact = (
        assessment_directory
        / "authorization_result.json"
    )

    attack_surface_artifact = (
        assessment_directory
        / "attack_surface.json"
    )

    result_path = (
        assessment_directory
        / "vulnerability_result.json"
    )

    print()
    print(f"Assessment : {assessment_name}")
    print()

    if not authorization_artifact.is_file():
        print("Authorization : NOT AVAILABLE")
        print()
        print("Cannot run Project 3.")
        print("Project 1 authorization result does not exist.")
        print("Run Project 1 first.")
        return

    print("Authorization : AVAILABLE")

    if not attack_surface_artifact.is_file():
        print("Attack Surface: NOT AVAILABLE")
        print()
        print("Cannot run Project 3.")
        print("Project 2 attack surface result does not exist.")
        print("Run Project 2 first.")
        return

    print("Attack Surface: AVAILABLE")

    print()
    print("-" * 60)
    print("Project 3 Scope Options:")
    print("  1. Run All Testers (Full scan — 168 checks across 22 categories)")
    print("  2. Select Vulnerability Category / Family (22 categories available)")
    print("  3. Run Specific Tester(s) (e.g. SQLI-08, ATO-01)")
    print("-" * 60)
    scope_choice = input("Select testing scope [1-3, default=1]: ").strip()

    test_ids: list[str] | None = None
    if scope_choice == "2":
        _print_categories_table()
        cat_choice = input(
            "\nSelect category number(s) or code(s) (e.g. 17 or SQLI or 1,2,17) [default=17]: "
        ).strip()
        test_ids, matched_names = _resolve_categories(cat_choice)
        print()
        if test_ids is None:
            print("Running all 168 registered vulnerability testers (Full scan)...")
        else:
            print(f"Selected: {', '.join(matched_names)}")
            print(f"Running {len(test_ids)} check(s)...")
    elif scope_choice == "3":
        custom = input("Enter tester ID(s) separated by spaces [e.g. SQLI-08 ATO-01]: ").strip()
        if custom:
            test_ids = [tid.strip().upper() for tid in custom.replace(",", " ").split() if tid.strip()]
            print()
            print(f"Running custom test IDs: {', '.join(test_ids)} ({len(test_ids)} checks)...")
        else:
            print()
            print("No test IDs specified. Running all 168 testers...")
    elif scope_choice in ("1", "", "all"):
        print()
        print("Running all 168 registered vulnerability testers (Full scan)...")
    else:
        resolved_ids, matched_names = _resolve_categories(scope_choice)
        if resolved_ids and len(resolved_ids) < 168:
            test_ids = resolved_ids
            print()
            print(f"Selected: {', '.join(matched_names)}")
            print(f"Running {len(test_ids)} check(s)...")
        else:
            print()
            print("Running all 168 registered vulnerability testers...")

    print()
    print("Using Project 1 authorization...")
    print("Using Project 2 attack surface...")
    print()

    try:
        run_project_3(
            assessment_name,
            runs_directory=runs_directory,
            test_ids=test_ids,
        )
    except (
        FileNotFoundError,
        RuntimeError,
        ValueError,
        OSError,
    ) as exc:
        print()
        print("=" * 60)
        print("Project 3 FAILED")
        print("=" * 60)
        print(f"Error: {exc}")
        return

    print()
    print("=" * 60)
    print("Project 3 COMPLETED")
    print("=" * 60)

    summary = _load_result_summary(
        result_path
    )

    if summary:
        print()
        print(f"Total Results : {summary['total']}")
        print(
            f"Not Detected  : "
            f"{summary['not_detected']}"
        )
        print(
            f"Potential     : "
            f"{summary['potential']}"
        )
        print(
            f"Skipped       : "
            f"{summary['skipped']}"
        )

    print()
    print(f"Output: {result_path}")
    print()
    print("Vulnerability result saved to assessment.")
