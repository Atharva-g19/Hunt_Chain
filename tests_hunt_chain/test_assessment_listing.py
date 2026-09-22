from pathlib import Path

from hunt_chain_core import AssessmentManager


def test_list_assessments_returns_sorted_names(
    tmp_path: Path,
):
    manager = AssessmentManager(tmp_path / "runs")

    manager.create("Zebra_Test")
    manager.create("alpha_test")
    manager.create("Middle_Test")

    assert manager.list_assessments() == (
        "alpha_test",
        "Middle_Test",
        "Zebra_Test",
    )


def test_exists_identifies_assessment(
    tmp_path: Path,
):
    manager = AssessmentManager(tmp_path / "runs")

    manager.create("Existing_Test")

    assert manager.exists("Existing_Test")
    assert not manager.exists("Missing_Test")


def test_list_assessments_ignores_non_assessment_directories(
    tmp_path: Path,
):
    runs = tmp_path / "runs"
    manager = AssessmentManager(runs)

    manager.create("Real_Assessment")

    (runs / "Not_An_Assessment").mkdir(
        parents=True
    )

    assert manager.list_assessments() == (
        "Real_Assessment",
    )
