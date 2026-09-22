from __future__ import annotations

from pathlib import Path

from hunt_chain_core import AssessmentManager
from hunt_chain_core.project_2_runner import register_project_2


def run_project_2_result_to_history(
    assessment_name: str,
    attack_surface_result: str | Path,
    runs_directory: str | Path = "Hunt_Chain_Runs",
) -> Path:
    source = Path(attack_surface_result)

    if not source.is_file():
        raise FileNotFoundError(
            f"Project 2 result does not exist: {source}"
        )

    manager = AssessmentManager(runs_directory)

    return register_project_2(
        assessment_name,
        source,
        manager.runs_directory,
    )
