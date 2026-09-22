from pathlib import Path

from hunt_chain_core import AssessmentManager


def register_project_3(
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

    return manager.add_project(
        assessment_name,
        project_id="project_3",
        project_name="Vulnerability Testing",
        source_file=source,
        result_filename="vulnerability_result.json",
    )
