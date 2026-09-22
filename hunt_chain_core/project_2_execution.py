from __future__ import annotations

import subprocess
from pathlib import Path

from hunt_chain_core.workflow import AssessmentWorkflow


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_2_ROOT = PROJECT_ROOT / "Project 2"
PROJECT_2_OUTPUT = PROJECT_2_ROOT / "output"


def run_project_2(
    assessment_name: str,
    runs_directory: str | Path = "Hunt_Chain_Runs",
) -> Path:
    runs_path = Path(runs_directory)

    if not runs_path.is_absolute():
        runs_path = PROJECT_ROOT / runs_path

    runs_path = runs_path.resolve()

    workflow = AssessmentWorkflow(
        runs_directory=runs_path,
    )

    authorization_artifact = (
        workflow.result_path(
            assessment_name,
            "project_1",
        ).resolve()
    )

    if not authorization_artifact.is_file():
        raise FileNotFoundError(
            "Authorization artifact does not exist: "
            f"{authorization_artifact}"
        )

    output_directory = (
        PROJECT_2_OUTPUT
        / assessment_name
    ).resolve()

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    command = [
        "hunt-chain-recon",
        str(authorization_artifact),
        "--output",
        str(output_directory),
    ]

    completed = subprocess.run(
        command,
        cwd=PROJECT_2_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    if completed.stdout:
        print(
            completed.stdout,
            end="",
        )

    if completed.stderr:
        print(
            completed.stderr,
            end="",
        )

    if completed.returncode != 0:
        raise RuntimeError(
            "Project 2 execution failed with exit code "
            f"{completed.returncode}."
        )

    result = (
        output_directory
        / "attack_surface.json"
    )

    if not result.is_file():
        raise FileNotFoundError(
            "Project 2 did not produce "
            "attack_surface.json."
        )

    return workflow.register_project_2(
        assessment_name,
        result,
    )
