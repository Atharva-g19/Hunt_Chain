from pathlib import Path

from hunt_chain_core.project_1_launcher import PROJECT_1_OUTPUT


def test_project_1_output_path_is_inside_scopeguard():
    assert PROJECT_1_OUTPUT.name == "authorization_result.json"
    assert PROJECT_1_OUTPUT.parent.name == "output"
    assert PROJECT_1_OUTPUT.parent.parent.name == "ScopeGuard"


def test_project_1_output_path_exists_or_can_be_generated():
    assert PROJECT_1_OUTPUT.parent.is_dir()
