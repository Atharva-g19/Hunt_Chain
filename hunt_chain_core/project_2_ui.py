from __future__ import annotations

from pathlib import Path

from hunt_chain_core.project_2_execution import (
    run_project_2,
)


def _run_project_2(
    manager,
    assessment_name: str,
) -> None:
    print()
    print("Project 2 — Recon")
    print("----------------------------------------")

    runs_directory = Path(
        manager.runs_directory
    ).resolve()

    assessment_directory = (
        runs_directory / assessment_name
    ).resolve()

    authorization_artifact = (
        assessment_directory
        / "authorization_result.json"
    )

    if not authorization_artifact.is_file():
        print(
            "Cannot run Project 2:"
        )
        print(
            "Project 1 authorization result "
            "does not exist for this assessment."
        )
        print(
            "Run Project 1 first."
        )
        return

    try:
        result = run_project_2(
            assessment_name,
            runs_directory=runs_directory,
        )
    except FileNotFoundError as exc:
        print(f"Project 2 failed: {exc}")
        return
    except RuntimeError as exc:
        print(f"Project 2 failed: {exc}")
        return

    print()
    print("Project 2 completed.")
    print("Attack surface saved to assessment.")
