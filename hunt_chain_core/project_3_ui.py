from __future__ import annotations

import json
from pathlib import Path

from hunt_chain_core.project_3_execution import (
    run_project_3,
)


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
    print("  1. Run All Testers (Full scan — 168 checks)")
    print("  2. Run SQL Injection Family (SQLI-01 through SQLI-10)")
    print("  3. Run Specific Tester(s) (e.g. SQLI-08)")
    print("-" * 60)
    scope_choice = input("Select testing scope [1-3, default=1]: ").strip()

    test_ids = None
    if scope_choice == "2":
        test_ids = [
            "SQLI-01", "SQLI-02", "SQLI-03", "SQLI-04", "SQLI-05",
            "SQLI-06", "SQLI-07", "SQLI-08", "SQLI-09", "SQLI-10",
        ]
        print()
        print("Running SQL Injection Family (10 checks)...")
    elif scope_choice == "3":
        custom = input("Enter tester ID(s) separated by spaces [e.g. SQLI-08]: ").strip()
        if custom:
            test_ids = [tid.strip().upper() for tid in custom.split() if tid.strip()]
            print()
            print(f"Running custom test IDs: {', '.join(test_ids)}...")
        else:
            print()
            print("No test IDs specified. Running all 168 testers...")
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
