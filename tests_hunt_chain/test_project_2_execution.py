from pathlib import Path

import pytest

from hunt_chain_core import AssessmentWorkflow
from hunt_chain_core.project_2_execution import run_project_2


def test_project_2_requires_project_1_result(
    tmp_path: Path,
):
    runs = tmp_path / "runs"

    workflow = AssessmentWorkflow(runs)
    workflow.create("Missing_P1")

    with pytest.raises(FileNotFoundError):
        run_project_2(
            "Missing_P1",
            runs_directory=runs,
        )
