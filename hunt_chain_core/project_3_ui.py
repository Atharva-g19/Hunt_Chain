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
    print("Project 3 execution")
    print("-" * 60)
    print()
    print("Using Project 1 authorization...")
    print("Using Project 2 attack surface...")
    print("Loading 168 registered vulnerability testers...")
    print()
    print("Running vulnerability testing...")
    print()

    try:
        run_project_3(
            assessment_name,
            runs_directory=runs_directory,
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
