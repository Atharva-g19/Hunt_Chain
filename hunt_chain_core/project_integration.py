from pathlib import Path

from hunt_chain_core import AssessmentManager


PROJECTS = {
    "project_1": {
        "name": "ScopeGuard",
        "result_filename": "authorization_result.json",
    },
}


def register_project_1(
    assessment_name: str,
    source_file: str | Path,
    runs_directory: str | Path = "Hunt_Chain_Runs",
) -> Path:
    manager = AssessmentManager(runs_directory)

    return manager.add_project(
        assessment_name,
        project_id="project_1",
        project_name=PROJECTS["project_1"]["name"],
        source_file=source_file,
        result_filename=PROJECTS["project_1"]["result_filename"],
    )
