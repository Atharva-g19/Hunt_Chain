import json
from pathlib import Path

import pytest

from hunt_chain_core import AssessmentManager


def test_create_generic_assessment(tmp_path: Path):
    manager = AssessmentManager(tmp_path / "runs")

    path = manager.create("Assessment_A")

    assert path.is_dir()

    manifest = json.loads(
        (path / "run.json").read_text(encoding="utf-8")
    )

    assert manifest["run_name"] == "Assessment_A"
    assert manifest["status"] == "NEW"
    assert manifest["projects"] == {}


def test_assessment_name_rejects_path_traversal(tmp_path: Path):
    manager = AssessmentManager(tmp_path / "runs")

    with pytest.raises(ValueError):
        manager.create("../outside")


def test_add_generic_project_result(tmp_path: Path):
    manager = AssessmentManager(tmp_path / "runs")

    manager.create("Assessment_B")

    source = tmp_path / "source.json"
    source.write_text('{"example": true}\n', encoding="utf-8")

    result = manager.add_project(
        "Assessment_B",
        project_id="project_alpha",
        project_name="Generic Project Alpha",
        source_file=source,
        result_filename="alpha_result.json",
    )

    assert result.is_file()
    assert result.read_text(encoding="utf-8") == '{"example": true}\n'

    manifest = manager.manifest("Assessment_B")

    assert manifest["status"] == "IN_PROGRESS"
    assert manifest["projects"]["project_alpha"]["name"] == (
        "Generic Project Alpha"
    )
    assert manifest["projects"]["project_alpha"]["result"] == (
        "alpha_result.json"
    )


def test_complete_assessment(tmp_path: Path):
    manager = AssessmentManager(tmp_path / "runs")

    manager.create("Assessment_C")

    source = tmp_path / "result.json"
    source.write_text('{"ok": true}\n', encoding="utf-8")

    manager.add_project(
        "Assessment_C",
        project_id="project_test",
        project_name="Test Project",
        source_file=source,
        result_filename="result.json",
    )

    manager.complete("Assessment_C")

    assert manager.manifest("Assessment_C")["status"] == "COMPLETED"


def test_duplicate_assessment_is_rejected(tmp_path: Path):
    manager = AssessmentManager(tmp_path / "runs")

    manager.create("Assessment_D")

    with pytest.raises(FileExistsError):
        manager.create("Assessment_D")
