from pathlib import Path

import pytest

from hunt_chain_core import AssessmentManager
from hunt_chain_core.project_3_runner import register_project_3


def test_project_3_result_is_copied_to_assessment(tmp_path: Path):
    runs = tmp_path / "runs"
    manager = AssessmentManager(runs)
    manager.create("Assessment_Project_3")

    source = tmp_path / "vulnerability_result.json"
    source.write_text(
        '{"schema_version":"v1","results":[]}\n',
        encoding="utf-8",
    )

    result = register_project_3(
        "Assessment_Project_3",
        source,
        runs,
    )

    expected = (
        runs
        / "Assessment_Project_3"
        / "vulnerability_result.json"
    )

    assert result == expected
    assert expected.read_bytes() == source.read_bytes()

    manifest = manager.manifest("Assessment_Project_3")

    assert manifest["projects"]["project_3"]["name"] == (
        "Vulnerability Testing"
    )
    assert manifest["projects"]["project_3"]["status"] == "COMPLETED"
    assert manifest["projects"]["project_3"]["result"] == (
        "vulnerability_result.json"
    )


def test_project_3_rejects_missing_result(tmp_path: Path):
    runs = tmp_path / "runs"
    manager = AssessmentManager(runs)
    manager.create("Missing_Project_3")

    with pytest.raises(FileNotFoundError):
        register_project_3(
            "Missing_Project_3",
            tmp_path / "missing.json",
            runs,
        )
