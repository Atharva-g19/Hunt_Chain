"""Unit tests for the Project 2 application runner."""

from pathlib import Path

import pytest

from hunt_chain_recon.application.runner import (
    ApplicationResult,
    ApplicationRunner,
    ApplicationRunnerError,
)
from hunt_chain_recon.authorization.models import (
    AuthorizationDecision,
    AuthorizationResult,
)
from hunt_chain_recon.config.loader import load_config


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "default.yaml"


def build_config():
    """Load the repository's default configuration."""

    return load_config(DEFAULT_CONFIG_PATH)


def normalized_target(config) -> str:
    """Return the normalized configured target."""

    return config.target.value.strip().lower().rstrip(".")


def build_authorization(
    target: str = "example.com",
    decision: AuthorizationDecision = AuthorizationDecision.IN_SCOPE,
) -> AuthorizationResult:
    """Build a test authorization result."""

    return AuthorizationResult(
        target=target,
        decision=decision,
        provider="scopeguard",
        reference="test-reference",
    )


def test_runner_rejects_non_config() -> None:
    """The runner requires a validated ReconConfig."""

    runner = ApplicationRunner()

    with pytest.raises(TypeError, match="ReconConfig"):
        runner.run(
            object(),
            build_authorization(),
        )


def test_runner_rejects_non_authorization() -> None:
    """The runner requires an AuthorizationResult."""

    runner = ApplicationRunner()
    config = build_config()

    with pytest.raises(
        TypeError,
        match="AuthorizationResult",
    ):
        runner.run(
            config,
            object(),
        )


def test_runner_rejects_mismatched_authorization_target() -> None:
    """Authorization must correspond to the configured target."""

    runner = ApplicationRunner()
    config = build_config()

    authorization = build_authorization(
        target="different.example.com",
    )

    with pytest.raises(
        ApplicationRunnerError,
        match="does not match configured target",
    ):
        runner.run(
            config,
            authorization,
        )


def test_runner_blocks_out_of_scope_target() -> None:
    """Out-of-scope authorization must block the pipeline."""

    runner = ApplicationRunner()
    config = build_config()

    authorization = build_authorization(
        target=normalized_target(config),
        decision=AuthorizationDecision.OUT_OF_SCOPE,
    )

    result = runner.run(
        config,
        authorization,
    )

    assert isinstance(result, ApplicationResult)
    assert result.pipeline_completed is False
    assert result.pipeline_blocked is True
    assert result.attack_surface is None
    assert result.output is None


def test_runner_blocks_unknown_authorization() -> None:
    """Unknown authorization must block the pipeline."""

    runner = ApplicationRunner()
    config = build_config()

    authorization = build_authorization(
        target=normalized_target(config),
        decision=AuthorizationDecision.UNKNOWN,
    )

    result = runner.run(
        config,
        authorization,
    )

    assert result.pipeline_completed is False
    assert result.pipeline_blocked is True
    assert result.attack_surface is None
    assert result.output is None


def test_runner_blocks_conflicting_authorization() -> None:
    """Conflicting authorization must block the pipeline."""

    runner = ApplicationRunner()
    config = build_config()

    authorization = build_authorization(
        target=normalized_target(config),
        decision=AuthorizationDecision.CONFLICT,
    )

    result = runner.run(
        config,
        authorization,
    )

    assert result.pipeline_completed is False
    assert result.pipeline_blocked is True
    assert result.attack_surface is None
    assert result.output is None


def test_runner_requires_output_directory_for_output_generation() -> None:
    """Pipeline execution can complete without writing output."""

    runner = ApplicationRunner()
    config = build_config()

    authorization = build_authorization(
        target=normalized_target(config),
    )

    result = runner.run(
        config,
        authorization,
        output_directory=None,
    )

    assert result.pipeline_completed is True
    assert result.pipeline_blocked is False
    assert result.attack_surface is not None
    assert result.output is None


def test_runner_generates_outputs_when_requested(
    tmp_path: Path,
) -> None:
    """Authorized pipeline execution can generate both outputs."""

    runner = ApplicationRunner()
    config = build_config()

    authorization = build_authorization(
        target=normalized_target(config),
    )

    result = runner.run(
        config,
        authorization,
        output_directory=tmp_path,
    )

    assert result.pipeline_completed is True
    assert result.pipeline_blocked is False
    assert result.attack_surface is not None
    assert result.output is not None

    assert result.output.json_path is not None
    assert result.output.report_path is not None

    assert result.output.json_path.exists()
    assert result.output.report_path.exists()


def test_runner_can_generate_json_only(
    tmp_path: Path,
) -> None:
    """The runner supports JSON-only output."""

    runner = ApplicationRunner()
    config = build_config()

    authorization = build_authorization(
        target=normalized_target(config),
    )

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
    assert not (tmp_path / "recon_report.txt").exists()


def test_runner_can_generate_report_only(
    tmp_path: Path,
) -> None:
    """The runner supports report-only output."""

    runner = ApplicationRunner()
    config = build_config()

    authorization = build_authorization(
        target=normalized_target(config),
    )

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
    assert not (tmp_path / "attack_surface.json").exists()