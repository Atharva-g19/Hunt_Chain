import os
import subprocess
import sys
from pathlib import Path

from hunt_chain_core.workflow import AssessmentWorkflow


PROJECT_ROOT = Path(__file__).resolve().parents[1]

PROJECT_3_ROOT = (
    PROJECT_ROOT / "Project_3_Vulnerability"
)

PROJECT_3_SRC = (
    PROJECT_3_ROOT / "src"
)

PROJECT_3_OUTPUT = (
    PROJECT_3_ROOT / "output"
)


def run_project_3(
    assessment_name: str,
    runs_directory: str | Path = "Hunt_Chain_Runs",
    test_ids: list[str] | tuple[str, ...] | None = None,
    endpoint_ids: list[str] | tuple[str, ...] | None = None,
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

    attack_surface_artifact = (
        workflow.result_path(
            assessment_name,
            "project_2",
        ).resolve()
    )

    if not authorization_artifact.is_file():
        raise FileNotFoundError(
            "Project 1 authorization artifact was not found."
        )

    if not attack_surface_artifact.is_file():
        raise FileNotFoundError(
            "Project 2 attack-surface artifact was not found."
        )

    output_directory = (
        PROJECT_3_OUTPUT / assessment_name
    ).resolve()

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_file = (
        output_directory
        / "vulnerability_result.json"
    )

    command = [
        sys.executable,
        "-m",
        "hunt_chain_vulnerability",
        "--config",
        str(
            PROJECT_3_ROOT
            / "config"
            / "default.yaml"
        ),
        "--authorization-artifact",
        str(authorization_artifact),
        "--attack-surface",
        str(attack_surface_artifact),
        "--output",
        str(output_file),
        "--run-id",
        f"{assessment_name}-project3",
    ]

    if test_ids:
        command.extend(["--test-ids", *test_ids])

    if endpoint_ids:
        for ep in endpoint_ids:
            command.extend(["--endpoint-id", ep])

    print()
    print("Starting Project 3: Vulnerability Testing")
    print("-" * 55)

    environment = os.environ.copy()
    existing_pythonpath = environment.get(
        "PYTHONPATH",
        "",
    )
    python_paths = [str(PROJECT_3_SRC)]
    if existing_pythonpath:
        python_paths.append(existing_pythonpath)
    environment["PYTHONPATH"] = os.pathsep.join(python_paths)

    completed = subprocess.run(
        command,
        cwd=PROJECT_3_ROOT,
        env=environment,
        text=True,
        check=False,
    )

    print("-" * 55)

    if completed.returncode != 0:
        raise RuntimeError(
            "Project 3 execution failed with exit code "
            f"{completed.returncode}."
        )

    if not output_file.is_file():
        raise FileNotFoundError(
            "Project 3 did not produce "
            "vulnerability_result.json."
        )

    return workflow.register_project_3(
        assessment_name,
        output_file,
    )
