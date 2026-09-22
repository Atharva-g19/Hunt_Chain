from __future__ import annotations

import subprocess
from pathlib import Path

from hunt_chain_core import AssessmentManager


PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_1_ROOT = PROJECT_ROOT / "Project 1" / "ScopeGuard"
PROJECT_1_OUTPUT = (
    PROJECT_1_ROOT / "output" / "authorization_result.json"
)


def run_project_1(
    assessment_name: str,
    scope_path: str | Path,
    target: str,
) -> Path:
    scope_path = Path(scope_path)

    if not scope_path.is_absolute():
        scope_path = PROJECT_ROOT / scope_path

    scope_path = scope_path.resolve()

    if not scope_path.is_file():
        raise FileNotFoundError(
            f"Scope YAML does not exist: {scope_path}"
        )

    target = target.strip()

    if not target:
        raise ValueError("Target must not be empty.")

    command = [
        "scopeguard",
        "check",
        "--scope",
        str(scope_path),
        "--target",
        target,
        "--json",
        "--output",
        str(PROJECT_1_OUTPUT),
    ]

    completed = subprocess.run(
        command,
        cwd=PROJECT_1_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    if completed.stdout:
        print(completed.stdout, end="")

    if completed.stderr:
        print(completed.stderr, end="")

    if completed.returncode not in (0, 1):
        raise RuntimeError(
            "Project 1 execution failed with exit code "
            f"{completed.returncode}."
        )

    if not PROJECT_1_OUTPUT.is_file():
        raise FileNotFoundError(
            "Project 1 did not produce authorization_result.json."
        )

    manager = AssessmentManager()

    manager.add_project(
        assessment_name,
        project_id="project_1",
        project_name="ScopeGuard",
        source_file=PROJECT_1_OUTPUT,
        result_filename="authorization_result.json",
    )

    return PROJECT_1_OUTPUT
