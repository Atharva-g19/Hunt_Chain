import json
from pathlib import Path

from hunt_chain_core import AssessmentWorkflow


def test_complete_generic_three_project_workflow(tmp_path: Path):
    runs = tmp_path / "runs"
    workflow = AssessmentWorkflow(runs)

    workflow.create("Generic_Web_Assessment")

    p1 = tmp_path / "authorization_result.json"
    p2 = tmp_path / "attack_surface.json"
    p3 = tmp_path / "vulnerability_result.json"

    p1.write_text(
        '{"state":"IN_SCOPE"}\n',
        encoding="utf-8",
    )

    p2.write_text(
        '{"schema_version":"v1","assets":[]}\n',
        encoding="utf-8",
    )

    p3.write_text(
        '{"schema_version":"v1","results":[]}\n',
        encoding="utf-8",
    )

    workflow.register_project_1(
        "Generic_Web_Assessment",
        p1,
    )

    workflow.register_project_2(
        "Generic_Web_Assessment",
        p2,
    )

    workflow.register_project_3(
        "Generic_Web_Assessment",
        p3,
    )

    workflow.complete("Generic_Web_Assessment")

    assessment = runs / "Generic_Web_Assessment"

    assert (assessment / "authorization_result.json").is_file()
    assert (assessment / "attack_surface.json").is_file()
    assert (assessment / "vulnerability_result.json").is_file()

    manifest = json.loads(
        (assessment / "run.json").read_text(
            encoding="utf-8"
        )
    )

    assert manifest["run_name"] == "Generic_Web_Assessment"
    assert manifest["status"] == "COMPLETED"
    assert set(manifest["projects"]) == {
        "project_1",
        "project_2",
        "project_3",
    }
