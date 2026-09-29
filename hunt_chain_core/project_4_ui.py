"""Interactive Project 4 validation UI."""

from __future__ import annotations

import json
from pathlib import Path

from hunt_chain_core.project_4_execution import (
    list_project4_candidates,
    run_project_4_validation,
)


def _run_project_4(
    manager,
    assessment_name: str,
) -> None:
    print("\n" + "=" * 60)
    print("Project 4 — Validation & Controlled Exploitation")
    print("=" * 60)

    runs_directory = Path(
        manager.runs_directory
    ).resolve()

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
            "\nNo Project 3 POTENTIAL findings "
            "require manual validation."
        )
        return

    print()
    print(f"Assessment: {assessment_name}")
    print(f"Candidates : {len(candidates)}")
    print()
    print("-" * 60)

    for index, candidate in enumerate(
        candidates,
        start=1,
    ):
        endpoint = candidate["endpoint"]

        print(
            f"{index}. "
            f"{candidate['test_id']} | "
            f"{candidate.get('confidence') or 'UNKNOWN'} | "
            f"{candidate['title']}"
        )

        print(
            f"   {endpoint.get('method', 'GET')} "
            f"{endpoint.get('url', '')}"
        )

        print(
            f"   result_id={candidate['result_id']}"
        )

    print("-" * 60)
    print("  0. Back")

    choice = input(
        "Select candidate: "
    ).strip()

    if choice == "0":
        return

    try:
        index = int(choice)
    except ValueError:
        print("Invalid selection.")
        return

    if not 1 <= index <= len(candidates):
        print("Invalid selection.")
        return

    selected = candidates[index - 1]

    print()
    print("Selected finding:")
    print(
        f"  Test ID : {selected['test_id']}"
    )
    print(
        f"  Target  : {selected['target_id']}"
    )
    print(
        f"  Endpoint: {selected['endpoint_id']}"
    )
    print(
        f"  Title   : {selected['title']}"
    )
    print()

    print(
        "Project 4 will perform only the bounded "
        "validation defined by the candidate's "
        "Project 4 validation profile."
    )

    confirm = input(
        "Run validation? [y/N]: "
    ).strip().lower()

    if confirm != "y":
        print("Validation cancelled.")
        return

    try:
        result = run_project_4_validation(
            assessment_name,
            test_id=selected["test_id"],
            target_id=selected["target_id"],
            endpoint_id=selected["endpoint_id"],
            result_id=selected["result_id"],
            runs_directory=runs_directory,
        )
    except (
        FileNotFoundError,
        ValueError,
        RuntimeError,
        OSError,
    ) as exc:
        print(
            f"\nProject 4 validation failed: {exc}"
        )
        return

    print()
    print("Project 4 validation completed.")
    print(f"Output: {result}")
