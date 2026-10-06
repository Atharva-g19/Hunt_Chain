from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from hunt_chain_core.workflow import AssessmentWorkflow


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_4_ROOT = (
    PROJECT_ROOT / "Project_4_Validation_Exploitation"
)
PROJECT_4_SRC = PROJECT_4_ROOT / "src"
PROJECT_3_ROOT = (
    PROJECT_ROOT / "Project_3_Vulnerability"
)
PROJECT_3_INVENTORY = (
    PROJECT_3_ROOT
    / "config"
    / "project3_tester_inventory.csv"
)
PROJECT_4_CONFIG = (
    PROJECT_4_ROOT
    / "config"
    / "live.yaml"
)
PROJECT_4_RESULT = "project4_validation.json"


def _project3_output(
    workflow: AssessmentWorkflow,
    assessment_name: str,
) -> Path:
    return workflow.result_path(
        assessment_name,
        "project_3",
    ).resolve()


def _authorization_output(
    workflow: AssessmentWorkflow,
    assessment_name: str,
) -> Path:
    return workflow.result_path(
        assessment_name,
        "project_1",
    ).resolve()


def list_project4_candidates(
    assessment_name: str,
    runs_directory: str | Path = "Hunt_Chain_Runs",
) -> tuple[dict[str, Any], ...]:
    """Return Project 3 POTENTIAL findings requiring Project 4 validation."""

    workflow = AssessmentWorkflow(
        runs_directory
    )

    source = _project3_output(
        workflow,
        assessment_name,
    )

    with source.open(
        "r",
        encoding="utf-8-sig",
    ) as handle:
        document = json.load(handle)

    target = document.get(
        "target",
        {},
    )

    endpoints = {
        endpoint.get("endpoint_id"): endpoint
        for endpoint in target.get(
            "endpoints",
            [],
        )
        if endpoint.get("endpoint_id")
    }

    evidence = {
        item.get("evidence_id"): item
        for item in document.get(
            "evidence",
            [],
        )
        if item.get("evidence_id")
    }

    candidates: list[dict[str, Any]] = []

    for result in document.get(
        "results",
        [],
    ):
        if str(
            result.get("status", "")
        ).upper() != "POTENTIAL":
            continue

        if not result.get(
            "manual_validation_required"
        ):
            continue

        endpoint_id = result.get(
            "endpoint_id"
        )

        endpoint = endpoints.get(
            endpoint_id
        )

        if endpoint is None:
            continue

        candidates.append(
            {
                "result_id": result.get(
                    "result_id"
                ),
                "test_id": result.get(
                    "test_id"
                ),
                "target_id": result.get(
                    "target_id"
                ),
                "endpoint_id": endpoint_id,
                "title": result.get(
                    "title",
                    "",
                ),
                "observation": result.get(
                    "observation",
                    "",
                ),
                "confidence": result.get(
                    "confidence"
                ),
                "evidence_ids": list(
                    result.get(
                        "evidence_ids",
                        [],
                    )
                ),
                "endpoint": endpoint,
                "source_evidence": [
                    evidence[evidence_id]
                    for evidence_id in result.get(
                        "evidence_ids",
                        [],
                    )
                    if evidence_id in evidence
                ],
            }
        )

    return tuple(candidates)


def run_project_4_validation(
    assessment_name: str,
    *,
    test_id: str,
    target_id: str | None = None,
    endpoint_id: str | None = None,
    result_id: str | None = None,
    runs_directory: str | Path = "Hunt_Chain_Runs",
) -> Path:
    """Run bounded Project 4 validation for one selected Project 3 finding."""

    workflow = AssessmentWorkflow(
        runs_directory
    )

    project3_output = _project3_output(
        workflow,
        assessment_name,
    )

    authorization_artifact = _authorization_output(
        workflow,
        assessment_name,
    )

    if not PROJECT_4_CONFIG.is_file():
        raise FileNotFoundError(
            "Project 4 config does not exist: "
            f"{PROJECT_4_CONFIG}"
        )

    if not PROJECT_3_INVENTORY.is_file():
        raise FileNotFoundError(
            "Project 3 tester inventory does not exist: "
            f"{PROJECT_3_INVENTORY}"
        )

    if not project3_output.is_file():
        raise FileNotFoundError(
            "Project 3 vulnerability result does not exist: "
            f"{project3_output}"
        )

    if not authorization_artifact.is_file():
        raise FileNotFoundError(
            "Project 1 authorization artifact does not exist: "
            f"{authorization_artifact}"
        )

    output_directory = (
        workflow.assessment_path(
            assessment_name
        ).resolve()
    )

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    environment = os.environ.copy()

    existing_pythonpath = environment.get(
        "PYTHONPATH",
        "",
    )

    python_paths = [
        str(PROJECT_4_SRC),
        str(PROJECT_3_ROOT / "src"),
    ]

    if existing_pythonpath:
        python_paths.append(
            existing_pythonpath
        )

    environment["PYTHONPATH"] = (
        os.pathsep.join(python_paths)
    )

    with tempfile.TemporaryDirectory(
        prefix="hunt_chain_project4_",
    ) as temporary_directory:
        temporary_output = (
            Path(temporary_directory)
            / PROJECT_4_RESULT
        )

        existing_result = (
            output_directory / PROJECT_4_RESULT
        )
        if existing_result.is_file():
            shutil.copy2(
                existing_result,
                temporary_output,
            )

        command = [
            sys.executable,
            "-m",
            "hunt_chain_project4.cli",
            "validate",
            "--config",
            str(PROJECT_4_CONFIG),
            "--authorization-artifact",
            str(authorization_artifact),
            "--project3-inventory",
            str(PROJECT_3_INVENTORY),
            "--project3-output",
            str(project3_output),
            "--test-id",
            test_id,
            "--output",
            str(temporary_output),
        ]

        optional_arguments = (
            (
                "--target-id",
                target_id,
            ),
            (
                "--endpoint-id",
                endpoint_id,
            ),
            (
                "--result-id",
                result_id,
            ),
        )

        for flag, value in optional_arguments:
            if value:
                command.extend(
                    [
                        flag,
                        value,
                    ]
                )

        completed = subprocess.run(
            command,
            cwd=PROJECT_4_ROOT,
            text=True,
            capture_output=True,
            check=False,
            env=environment,
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
                "Project 4 validation failed "
                f"with exit code {completed.returncode}."
            )

        if not temporary_output.is_file():
            raise FileNotFoundError(
                "Project 4 did not produce "
                "project4_validation.json."
            )

        return workflow.register_project_4(
            assessment_name,
            temporary_output,
        )


def run_project_4_batch_validation(
    assessment_name: str,
    *,
    result_ids: list[str] | tuple[str, ...] | None = None,
    host: str | None = None,
    test_id: str | None = None,
    validate_all: bool = False,
    runs_directory: str | Path = "Hunt_Chain_Runs",
) -> Path:
    """Run bounded Project 4 validation for multiple Project 3 findings in a single pass."""

    workflow = AssessmentWorkflow(
        runs_directory
    )

    project3_output = _project3_output(
        workflow,
        assessment_name,
    )

    authorization_artifact = _authorization_output(
        workflow,
        assessment_name,
    )

    if not PROJECT_4_CONFIG.is_file():
        raise FileNotFoundError(
            "Project 4 config does not exist: "
            f"{PROJECT_4_CONFIG}"
        )

    if not PROJECT_3_INVENTORY.is_file():
        raise FileNotFoundError(
            "Project 3 tester inventory does not exist: "
            f"{PROJECT_3_INVENTORY}"
        )

    if not project3_output.is_file():
        raise FileNotFoundError(
            "Project 3 vulnerability result does not exist: "
            f"{project3_output}"
        )

    if not authorization_artifact.is_file():
        raise FileNotFoundError(
            "Project 1 authorization artifact does not exist: "
            f"{authorization_artifact}"
        )

    output_directory = (
        workflow.assessment_path(
            assessment_name
        ).resolve()
    )

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    environment = os.environ.copy()

    existing_pythonpath = environment.get(
        "PYTHONPATH",
        "",
    )

    python_paths = [
        str(PROJECT_4_SRC),
        str(PROJECT_3_ROOT / "src"),
    ]

    if existing_pythonpath:
        python_paths.append(
            existing_pythonpath
        )

    environment["PYTHONPATH"] = (
        os.pathsep.join(python_paths)
    )

    with tempfile.TemporaryDirectory(
        prefix="hunt_chain_project4_batch_",
    ) as temporary_directory:
        temporary_output = (
            Path(temporary_directory)
            / PROJECT_4_RESULT
        )

        existing_result = (
            output_directory / PROJECT_4_RESULT
        )
        if existing_result.is_file():
            shutil.copy2(
                existing_result,
                temporary_output,
            )

        command = [
            sys.executable,
            "-m",
            "hunt_chain_project4.cli",
            "validate-batch",
            "--config",
            str(PROJECT_4_CONFIG),
            "--authorization-artifact",
            str(authorization_artifact),
            "--project3-inventory",
            str(PROJECT_3_INVENTORY),
            "--project3-output",
            str(project3_output),
            "--output",
            str(temporary_output),
        ]

        if validate_all:
            command.append("--all")
        elif result_ids:
            cand_file = (
                Path(temporary_directory)
                / "candidates.json"
            )
            cand_file.write_text(
                json.dumps(list(result_ids)),
                encoding="utf-8",
            )
            command.extend(
                [
                    "--candidate-file",
                    str(cand_file),
                ]
            )

        if host:
            command.extend(
                [
                    "--host",
                    host,
                ]
            )

        if test_id:
            command.extend(
                [
                    "--test-id",
                    test_id,
                ]
            )

        completed = subprocess.run(
            command,
            cwd=PROJECT_4_ROOT,
            text=True,
            capture_output=False,
            check=False,
            env=environment,
        )

        if completed.returncode != 0:
            raise RuntimeError(
                "Project 4 batch validation failed "
                f"with exit code {completed.returncode}."
            )

        if not temporary_output.is_file():
            raise FileNotFoundError(
                "Project 4 did not produce "
                "project4_validation.json."
            )

        return workflow.register_project_4(
            assessment_name,
            temporary_output,
        )

