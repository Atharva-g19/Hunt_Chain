from pathlib import Path

import pytest

from hunt_chain_core import AssessmentManager
from hunt_chain_core.project_1_runner import (
    run_project_1_result_to_history,
)


def test_project_1_runner_copies_real_result(tmp_path: Path):
    runs = tmp_path / "runs"
    manager = AssessmentManager(runs)
    manager.create("Generic_Assessment")

    source = tmp_path / "authorization_result.json"
    source.write_text(
        '{"state":"IN_SCOPE","target":{"value":"example.com"}}\n',
        encoding="utf-8",
    )

    result = run_project_1_result_to_history(
        "Generic_Assessment",
        source,
        runs,
    )

    expected = (
        runs
        / "Generic_Assessment"
        / "authorization_result.json"
    )

    assert result == expected
    assert expected.read_bytes() == source.read_bytes()


def test_project_1_runner_rejects_missing_result(tmp_path: Path):
    runs = tmp_path / "runs"
    manager = AssessmentManager(runs)
    manager.create("Missing_Result_Test")

    missing = tmp_path / "missing.json"

    with pytest.raises(FileNotFoundError):
        run_project_1_result_to_history(
            "Missing_Result_Test",
            missing,
            runs,
        )
