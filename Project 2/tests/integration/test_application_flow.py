"""Application-level integration tests for Hunt_Chain Project 2."""

from __future__ import annotations

from pathlib import Path

from hunt_chain_recon.application.runner import ApplicationRunner
from hunt_chain_recon.authorization.models import (
    AuthorizationDecision,
    AuthorizationResult,
)
from hunt_chain_recon.config.loader import load_config
from hunt_chain_recon.models.attack_surface import AttackSurface


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "default.yaml"


def make_authorization(target: str) -> AuthorizationResult:
    """Create an authorized result for deterministic integration testing."""
    return AuthorizationResult(
        target=target,
        decision=AuthorizationDecision.IN_SCOPE,
        provider="test",
        reference="integration-test-authorization",
    )


def test_application_runner_builds_attack_surface_without_output(
    monkeypatch,
) -> None:
    """ApplicationRunner should execute the default pipeline successfully."""

    config = load_config(DEFAULT_CONFIG_PATH)

    authorization = make_authorization(
        config.target.value.strip().lower().rstrip(".")
    )

    runner = ApplicationRunner()

    result = runner.run(
        config,
        authorization,
        output_directory=None,
    )

    assert result.pipeline_completed is True
    assert result.pipeline_blocked is False
    assert isinstance(
        result.attack_surface,
        AttackSurface,
    )
    assert result.output is None


def test_application_runner_writes_both_outputs(
    tmp_path: Path,
) -> None:
    """ApplicationRunner should produce JSON and report outputs."""

    config = load_config(DEFAULT_CONFIG_PATH)

    authorization = make_authorization(
        config.target.value.strip().lower().rstrip(".")
    )

    runner = ApplicationRunner()

    result = runner.run(
        config,
        authorization,
        output_directory=tmp_path,
        json_enabled=True,
        report_enabled=True,
    )

    assert result.pipeline_completed is True
    assert result.pipeline_blocked is False
    assert isinstance(
        result.attack_surface,
        AttackSurface,
    )

    assert result.output is not None
    assert result.output.json_path is not None
    assert result.output.report_path is not None

    assert result.output.json_path.exists()
    assert result.output.report_path.exists()

    assert result.output.json_path.name == "attack_surface.json"
    assert result.output.report_path.name == "recon_report.txt"


def test_application_runner_writes_json_only(
    tmp_path: Path,
) -> None:
    """ApplicationRunner should support JSON-only output."""

    config = load_config(DEFAULT_CONFIG_PATH)

    authorization = make_authorization(
        config.target.value.strip().lower().rstrip(".")
    )

    runner = ApplicationRunner()

    result = runner.run(
        config,
        authorization,
        output_directory=tmp_path,
        json_enabled=True,
        report_enabled=False,
    )

    assert result.pipeline_completed is True
    assert result.output is not None
    assert result.output.json_path is not None
    assert result.output.report_path is None

    assert result.output.json_path.exists()


def test_application_runner_writes_report_only(
    tmp_path: Path,
) -> None:
    """ApplicationRunner should support report-only output."""

    config = load_config(DEFAULT_CONFIG_PATH)

    authorization = make_authorization(
        config.target.value.strip().lower().rstrip(".")
    )

    runner = ApplicationRunner()

    result = runner.run(
        config,
        authorization,
        output_directory=tmp_path,
        json_enabled=False,
        report_enabled=True,
    )

    assert result.pipeline_completed is True
    assert result.output is not None
    assert result.output.json_path is None
    assert result.output.report_path is not None

    assert result.output.report_path.exists()