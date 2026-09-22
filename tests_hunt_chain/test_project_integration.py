from pathlib import Path

import pytest

from hunt_chain_core import AssessmentManager
from hunt_chain_core.project_integration import register_project_1


def test_project_1_result_is_copied_to_assessment(tmp_path: Path):
    runs = tmp_path / "runs"
    manager = AssessmentManager(runs)
    manager.create("Assessment_Project_1")

    source = tmp_path / "authorization_result.json"
    source.write_text(
        '{"state": "IN_SCOPE"}\n',
        encoding="utf-8",
    )

    result = register_project_1(
        "Assessment_Project_1",
        source,
        runs,
    )

    expected = (
        runs
        / "Assessment_Project_1"
        / "authorization_result.json"
    )

    assert result == expected
    assert expected.read_text(encoding="utf-8") == (
        '{"state": "IN_SCOPE"}\n'
    )

    manifest = manager.manifest("Assessment_Project_1")

    assert manifest["projects"]["project_1"]["name"] == "ScopeGuard"
    assert manifest["projects"]["project_1"]["status"] == "COMPLETED"
    assert manifest["projects"]["project_1"]["result"] == (
        "authorization_result.json"
    )


def test_project_1_integration_is_generic(tmp_path: Path):
    runs = tmp_path / "runs"
    manager = AssessmentManager(runs)
    manager.create("Bumba_Assessment")

    source = tmp_path / "source.json"
    source.write_text(
        '{"state": "IN_SCOPE", "target": "example.com"}\n',
        encoding="utf-8",
    )

    register_project_1(
        "Bumba_Assessment",
        source,
        runs,
    )

    assert (
        runs
        / "Bumba_Assessment"
        / "authorization_result.json"
    ).is_file()
