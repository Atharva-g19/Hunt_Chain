from pathlib import Path

import pytest

from hunt_chain_core import AssessmentManager
from hunt_chain_core.project_3_launcher import (
    run_project_3_result_to_history,
)


def test_project_3_launcher_copies_result(tmp_path: Path):
    runs = tmp_path / "runs"
    manager = AssessmentManager(runs)
    manager.create("Generic_Project_3")

    source = tmp_path / "vulnerability_result.json"
    source.write_text(
        '{"schema_version":"v1","results":[]}\n',
        encoding="utf-8",
    )

    result = run_project_3_result_to_history(
        "Generic_Project_3",
        source,
        runs,
    )

    expected = (
        runs
        / "Generic_Project_3"
        / "vulnerability_result.json"
    )

    assert result == expected
    assert result.read_bytes() == source.read_bytes()


def test_project_3_launcher_rejects_missing_result(tmp_path: Path):
    runs = tmp_path / "runs"
    manager = AssessmentManager(runs)
    manager.create("Missing_Project_3_Launcher")

    with pytest.raises(FileNotFoundError):
        run_project_3_result_to_history(
            "Missing_Project_3_Launcher",
            tmp_path / "missing.json",
            runs,
        )
