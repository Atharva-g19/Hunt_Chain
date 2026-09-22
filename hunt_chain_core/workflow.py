from __future__ import annotations

from pathlib import Path

from .assessment_manager import AssessmentManager
from hunt_chain_core.project_integration import register_project_1
from hunt_chain_core.project_2_runner import register_project_2
from hunt_chain_core.project_3_runner import register_project_3


PROJECT_RESULTS = {
    "project_1": "authorization_result.json",
    "project_2": "attack_surface.json",
    "project_3": "vulnerability_result.json",
}


class AssessmentWorkflow:
    """Coordinate generic Hunt_Chain assessment history."""

    def __init__(
        self,
        runs_directory: str | Path = "Hunt_Chain_Runs",
    ) -> None:
        self.runs_directory = Path(runs_directory)
        self.manager = AssessmentManager(
            self.runs_directory
        )

    def create(
        self,
        assessment_name: str,
    ) -> Path:
        return self.manager.create(
            assessment_name
        )

    def assessment_path(
        self,
        assessment_name: str,
    ) -> Path:
        return self.manager.get(
            assessment_name
        )

    def result_path(
        self,
        assessment_name: str,
        project_id: str,
    ) -> Path:
        if project_id not in PROJECT_RESULTS:
            raise ValueError(
                f"Unknown project: {project_id}"
            )

        path = (
            self.assessment_path(assessment_name)
            / PROJECT_RESULTS[project_id]
        )

        if not path.is_file():
            raise FileNotFoundError(
                f"Required {project_id} result does not exist: "
                f"{path}"
            )

        return path

    def has_result(
        self,
        assessment_name: str,
        project_id: str,
    ) -> bool:
        try:
            self.result_path(
                assessment_name,
                project_id,
            )
            return True
        except (
            ValueError,
            FileNotFoundError,
        ):
            return False

    def register_project_1(
        self,
        assessment_name: str,
        result: str | Path,
    ) -> Path:
        return register_project_1(
            assessment_name,
            result,
            self.runs_directory,
        )

    def register_project_2(
        self,
        assessment_name: str,
        result: str | Path,
    ) -> Path:
        return register_project_2(
            assessment_name,
            result,
            self.runs_directory,
        )

    def register_project_3(
        self,
        assessment_name: str,
        result: str | Path,
    ) -> Path:
        return register_project_3(
            assessment_name,
            result,
            self.runs_directory,
        )

    def complete(
        self,
        assessment_name: str,
    ) -> Path:
        return self.manager.complete(
            assessment_name
        )

    def manifest(
        self,
        assessment_name: str,
    ) -> dict:
        return self.manager.manifest(
            assessment_name
        )
