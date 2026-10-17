"""Unit test for requirement (g): ScopeGuard fail-closed authorization gate."""

from pathlib import Path
import pytest

from hunt_chain_reporting.generator import AuthorizationGateError, generate_report
from hunt_chain_reporting.writer import write_report_artifacts


def test_fixture_g_missing_authorization_data_fails():
    """Missing authorization data must fail with AuthorizationGateError."""
    with pytest.raises(AuthorizationGateError, match="ScopeGuard authorization artifact is missing"):
        generate_report(authorization_data={})


def test_fixture_g_not_in_scope_state_fails():
    """State other than IN_SCOPE (e.g. OUT_OF_SCOPE, UNKNOWN, REQUIRE_CONFIRMATION) must fail."""
    out_of_scope_data = {
        "state": "OUT_OF_SCOPE",
        "rule_id": "RULE-EXCLUDE-01",
        "target": "forbidden.internal.corp",
    }
    with pytest.raises(AuthorizationGateError, match="authorized IN_SCOPE"):
        generate_report(authorization_data=out_of_scope_data)


def test_fixture_g_writer_refuses_when_unauthorized(tmp_path: Path):
    """File writer must refuse to produce any files when ScopeGuard authorization is missing."""
    with pytest.raises(AuthorizationGateError):
        write_report_artifacts(
            output_directory=tmp_path,
            authorization_data={"state": "PENDING_APPROVAL"},
        )
    assert not (tmp_path / "report.md").exists()
    assert not (tmp_path / "report.json").exists()
