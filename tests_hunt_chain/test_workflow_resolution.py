from pathlib import Path

import pytest

from hunt_chain_core import AssessmentWorkflow


def test_workflow_resolves_project_result(
    tmp_path: Path,
):
    runs = tmp_path / "runs"
    workflow = AssessmentWorkflow(runs)

    workflow.create("Generic_Assessment")

    result = (
        runs
        / "Generic_Assessment"
        / "attack_surface.json"
    )

    result.write_text(
        '{"schema_version":"v1"}\n',
        encoding="utf-8",
    )

    assert (
        workflow.result_path(
            "Generic_Assessment",
            "project_2",
        )
        == result
    )


def test_workflow_reports_missing_result(
    tmp_path: Path,
):
    workflow = AssessmentWorkflow(
        tmp_path / "runs"
    )

    workflow.create("Missing_Result")

    with pytest.raises(FileNotFoundError):
        workflow.result_path(
            "Missing_Result",
            "project_2",
        )


def test_workflow_has_result(
    tmp_path: Path,
):
    runs = tmp_path / "runs"
    workflow = AssessmentWorkflow(runs)

    workflow.create("Result_Check")

    assert not workflow.has_result(
        "Result_Check",
        "project_1",
    )

    (
        runs
        / "Result_Check"
        / "authorization_result.json"
    ).write_text(
        '{"state":"IN_SCOPE"}\n',
        encoding="utf-8",
    )

    assert workflow.has_result(
        "Result_Check",
        "project_1",
    )


def test_workflow_rejects_unknown_project(
    tmp_path: Path,
):
    workflow = AssessmentWorkflow(
        tmp_path / "runs"
    )

    workflow.create("Unknown_Project")

    with pytest.raises(ValueError):
        workflow.result_path(
            "Unknown_Project",
            "project_99",
        )
