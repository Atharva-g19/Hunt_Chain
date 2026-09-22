from __future__ import annotations

import json
import subprocess
from pathlib import Path

from .project_integration import register_project_1


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_1_ROOT = PROJECT_ROOT / "Project 1" / "ScopeGuard"
PROJECT_1_OUTPUT = PROJECT_1_ROOT / "output"


def run_project_1(
    assessment_name: str,
    scope_path: str | Path,
    target: str,
    runs_directory: str | Path = "Hunt_Chain_Runs",
) -> Path:
    scope = Path(scope_path)

    if not scope.is_absolute():
        scope = PROJECT_ROOT / scope

    scope = scope.resolve()

    if not scope.is_file():
        raise FileNotFoundError(
            f"Scope YAML does not exist: {scope}"
        )

    if not target.strip():
        raise ValueError("Target must not be empty.")

    runs_path = Path(runs_directory)

    if not runs_path.is_absolute():
        runs_path = PROJECT_ROOT / runs_path

    runs_path = runs_path.resolve()

    PROJECT_1_OUTPUT.mkdir(
        parents=True,
        exist_ok=True,
    )

    result = (
        PROJECT_1_OUTPUT
        / "authorization_result.json"
    )

    command = [
        "scopeguard",
        "check",
        "--scope",
        str(scope),
        "--target",
        target,
        "--json",
        "--output",
        str(result),
    ]

    completed = subprocess.run(
        command,
        cwd=PROJECT_1_ROOT,
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
            "Project 1 execution failed with exit code "
            f"{completed.returncode}."
        )

    if not result.is_file():
        raise FileNotFoundError(
            "Project 1 did not produce "
            "authorization_result.json."
        )

    with result.open(
        "r",
        encoding="utf-8-sig",
    ) as handle:
        authorization = json.load(handle)

    state = authorization.get("state")

    if state != "IN_SCOPE":
        print()
        print(f"Authorization result: {state}")
        print(
            "Project 1 did not authorize this target."
        )
        print(
            "Project 2 and later projects cannot "
            "run for this assessment."
        )
        raise PermissionError(
            f"Target authorization state: {state}"
        )

    history = register_project_1(
        assessment_name,
        result,
        runs_path,
    )

    if not history.is_file():
        raise FileNotFoundError(
            "Project 1 history artifact was not created."
        )

    return history


def run_project_1_result_to_history(
    assessment_name: str,
    authorization_result: str | Path,
    runs_directory: str | Path = "Hunt_Chain_Runs",
) -> Path:
    source = Path(authorization_result)

    if not source.is_file():
        raise FileNotFoundError(
            f"Project 1 result does not exist: {source}"
        )

    runs_path = Path(runs_directory)

    if not runs_path.is_absolute():
        runs_path = PROJECT_ROOT / runs_path

    runs_path = runs_path.resolve()

    return register_project_1(
        assessment_name,
        source,
        runs_path,
    )
