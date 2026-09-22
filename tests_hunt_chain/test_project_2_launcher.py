from pathlib import Path

import pytest

from hunt_chain_core import AssessmentManager
from hunt_chain_core.project_2_launcher import (
    run_project_2_result_to_history,
)


def test_project_2_launcher_copies_result(tmp_path: Path):
    runs = tmp_path / "runs"
    manager = AssessmentManager(runs)
    manager.create("Generic_Project_2")

    source = tmp_path / "attack_surface.json"
    source.write_text(
        '{"schema_version":"v1","assets":[]}\n',
        encoding="utf-8",
    )

    result = run_project_2_result_to_history(
        "Generic_Project_2",
        source,
        runs,
    )

    expected = (
        runs
        / "Generic_Project_2"
        / "attack_surface.json"
    )

    assert result == expected
    assert result.read_bytes() == source.read_bytes()


def test_project_2_launcher_rejects_missing_result(tmp_path: Path):
    runs = tmp_path / "runs"
    manager = AssessmentManager(runs)
    manager.create("Missing_Project_2_Launcher")

    with pytest.raises(FileNotFoundError):
        run_project_2_result_to_history(
            "Missing_Project_2_Launcher",
            tmp_path / "missing.json",
            runs,
        )
