from pathlib import Path

import pytest

from hunt_chain_core import AssessmentManager
from hunt_chain_core.project_2_runner import register_project_2


def test_project_2_result_is_copied_to_assessment(tmp_path: Path):
    runs = tmp_path / "runs"
    manager = AssessmentManager(runs)
    manager.create("Assessment_Project_2")

    source = tmp_path / "attack_surface.json"
    source.write_text(
        '{"schema_version":"v1","assets":[]}\n',
        encoding="utf-8",
    )

    result = register_project_2(
        "Assessment_Project_2",
        source,
        runs,
    )

    expected = (
        runs
        / "Assessment_Project_2"
        / "attack_surface.json"
    )

    assert result == expected
    assert expected.read_bytes() == source.read_bytes()

    manifest = manager.manifest("Assessment_Project_2")

    assert manifest["projects"]["project_2"]["name"] == "Recon"
    assert manifest["projects"]["project_2"]["status"] == "COMPLETED"
    assert manifest["projects"]["project_2"]["result"] == (
        "attack_surface.json"
    )


def test_project_2_rejects_missing_result(tmp_path: Path):
    runs = tmp_path / "runs"
    manager = AssessmentManager(runs)
    manager.create("Missing_Project_2")

    with pytest.raises(FileNotFoundError):
        register_project_2(
            "Missing_Project_2",
            tmp_path / "missing.json",
            runs,
        )
