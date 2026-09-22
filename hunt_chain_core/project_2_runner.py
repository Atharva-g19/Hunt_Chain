from pathlib import Path

from hunt_chain_core import AssessmentManager


def register_project_2(
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

    return manager.add_project(
        assessment_name,
        project_id="project_2",
        project_name="Recon",
        source_file=source,
        result_filename="attack_surface.json",
    )
