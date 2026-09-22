from __future__ import annotations

from pathlib import Path

from hunt_chain_core import AssessmentManager
from hunt_chain_core.project_3_runner import register_project_3


def run_project_3_result_to_history(
    assessment_name: str,
    vulnerability_result: str | Path,
    runs_directory: str | Path = "Hunt_Chain_Runs",
) -> Path:
    source = Path(vulnerability_result)

    if not source.is_file():
        raise FileNotFoundError(
            f"Project 3 result does not exist: {source}"
        )

    manager = AssessmentManager(runs_directory)

    return register_project_3(
        assessment_name,
        source,
        manager.runs_directory,
    )
