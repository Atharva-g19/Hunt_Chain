"""Unit tests for the Hunt_Chain Project 2 CLI."""

from __future__ import annotations

from argparse import Namespace
from pathlib import Path

import pytest

from hunt_chain_recon.application.runner import (
    ApplicationRunnerError,
)
from hunt_chain_recon.authorization.adapter import (
    AuthorizationError,
)
from hunt_chain_recon.authorization.models import (
    AuthorizationDecision,
    AuthorizationResult,
)
from hunt_chain_recon.cli.commands import (
    build_parser,
    run_cli,
)
from hunt_chain_recon.config.loader import (
    ConfigurationError,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "default.yaml"


def build_args(
    *,
    config: str | Path = DEFAULT_CONFIG_PATH,
    output: str | Path | None = None,
    no_json: bool = False,
    no_report: bool = False,
) -> Namespace:
    """Build CLI arguments for tests."""
    return Namespace(
        config=str(config),
        output=None if output is None else str(output),
        no_json=no_json,
        no_report=no_report,
    )


def build_authorization(
    target: str,
    decision: AuthorizationDecision,
) -> AuthorizationResult:
    """Build an authorization result for tests."""
    return AuthorizationResult(
        target=target,
        decision=decision,
        provider="scopeguard",
        reference="test-reference",
    )


def test_parser_requires_config() -> None:
    """The CLI must require a configuration path."""
    parser = build_parser()

    with pytest.raises(SystemExit):
        parser.parse_args([])


def test_parser_accepts_output_override() -> None:
    """The CLI should accept an output directory override."""
    parser = build_parser()

    args = parser.parse_args(
        [
            "--config",
            "config.yaml",
            "--output",
            "custom-output",
        ]
    )

    assert args.config == "config.yaml"
    assert args.output == "custom-output"
    assert args.no_json is False
    assert args.no_report is False


def test_parser_accepts_output_disable_flags() -> None:
    """The CLI should accept JSON and report disable flags."""
    parser = build_parser()

    args = parser.parse_args(
        [
            "--config",
            "config.yaml",
            "--no-json",
            "--no-report",
        ]
    )

    assert args.no_json is True
    assert args.no_report is True


def test_run_cli_returns_configuration_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Configuration errors should return a dedicated CLI status."""
    def fail_load_config(path: str | Path) -> None:
        raise ConfigurationError("invalid configuration")

    monkeypatch.setattr(
        "hunt_chain_recon.cli.commands.load_config",
        fail_load_config,
    )

    result = run_cli(build_args())

    assert result == 2


def test_run_cli_does_not_swallow_unexpected_scopeguard_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Unexpected provider errors must not be silently treated as authorization denial."""

    class FakeScopeGuard:
        def evaluate(self, target, authorization):
            raise RuntimeError("unexpected provider failure")

    monkeypatch.setattr(
        "hunt_chain_recon.cli.commands.ScopeGuardAdapter",
        FakeScopeGuard,
    )

    with pytest.raises(RuntimeError, match="unexpected provider failure"):
        run_cli(build_args())


def test_run_cli_blocks_authorization_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ScopeGuard authorization failures must return exit code 3."""

    class FakeScopeGuard:
        def evaluate(self, target, authorization):
            raise AuthorizationError(
                "authorization unavailable"
            )

    monkeypatch.setattr(
        "hunt_chain_recon.cli.commands.ScopeGuardAdapter",
        FakeScopeGuard,
    )

    result = run_cli(build_args())

    assert result == 3


def test_run_cli_blocks_non_authorized_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-IN_SCOPE decision must never reach ApplicationRunner."""

    class FakeScopeGuard:
        def evaluate(self, target, authorization):
            return build_authorization(
                target,
                AuthorizationDecision.OUT_OF_SCOPE,
            )

    class FailRunner:
        def run(self, *args, **kwargs):
            raise AssertionError(
                "ApplicationRunner must not execute."
            )

    monkeypatch.setattr(
        "hunt_chain_recon.cli.commands.ScopeGuardAdapter",
        FakeScopeGuard,
    )
    monkeypatch.setattr(
        "hunt_chain_recon.cli.commands.ApplicationRunner",
        FailRunner,
    )

    result = run_cli(build_args())

    assert result == 3


def test_run_cli_success(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """An authorized target should be passed to ApplicationRunner."""

    class FakeScopeGuard:
        def evaluate(self, target, authorization):
            return build_authorization(
                target,
                AuthorizationDecision.IN_SCOPE,
            )

    class FakeOutput:
        json_path = tmp_path / "attack_surface.json"
        report_path = tmp_path / "recon_report.txt"

    class FakeResult:
        pipeline_completed = True
        pipeline_blocked = False
        output = FakeOutput()

    captured = {}

    class FakeRunner:
        def run(self, config, authorization, **kwargs):
            captured["config"] = config
            captured["authorization"] = authorization
            captured["kwargs"] = kwargs
            return FakeResult()

    monkeypatch.setattr(
        "hunt_chain_recon.cli.commands.ScopeGuardAdapter",
        FakeScopeGuard,
    )
    monkeypatch.setattr(
        "hunt_chain_recon.cli.commands.ApplicationRunner",
        FakeRunner,
    )

    result = run_cli(
        build_args(
            output=tmp_path,
        )
    )

    assert result == 0
    assert captured["authorization"].is_authorized is True
    assert captured["kwargs"]["output_directory"] == str(tmp_path)
    assert captured["kwargs"]["json_enabled"] is True
    assert captured["kwargs"]["report_enabled"] is True


def test_run_cli_passes_output_flags(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CLI output flags must reach ApplicationRunner."""

    class FakeScopeGuard:
        def evaluate(self, target, authorization):
            return build_authorization(
                target,
                AuthorizationDecision.IN_SCOPE,
            )

    class FakeResult:
        pipeline_completed = True
        pipeline_blocked = False
        output = None

    captured = {}

    class FakeRunner:
        def run(self, config, authorization, **kwargs):
            captured.update(kwargs)
            return FakeResult()

    monkeypatch.setattr(
        "hunt_chain_recon.cli.commands.ScopeGuardAdapter",
        FakeScopeGuard,
    )
    monkeypatch.setattr(
        "hunt_chain_recon.cli.commands.ApplicationRunner",
        FakeRunner,
    )

    result = run_cli(
        build_args(
            no_json=True,
            no_report=True,
        )
    )

    assert result == 0
    assert captured["json_enabled"] is False
    assert captured["report_enabled"] is False


def test_run_cli_handles_application_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ApplicationRunner failures should return exit code 4."""

    class FakeScopeGuard:
        def evaluate(self, target, authorization):
            return build_authorization(
                target,
                AuthorizationDecision.IN_SCOPE,
            )

    class FakeRunner:
        def run(self, *args, **kwargs):
            raise ApplicationRunnerError(
                "pipeline failure"
            )

    monkeypatch.setattr(
        "hunt_chain_recon.cli.commands.ScopeGuardAdapter",
        FakeScopeGuard,
    )
    monkeypatch.setattr(
        "hunt_chain_recon.cli.commands.ApplicationRunner",
        FakeRunner,
    )

    result = run_cli(build_args())

    assert result == 4


def test_run_cli_handles_blocked_pipeline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A blocked pipeline should return exit code 3."""

    class FakeScopeGuard:
        def evaluate(self, target, authorization):
            return build_authorization(
                target,
                AuthorizationDecision.IN_SCOPE,
            )

    class FakeResult:
        pipeline_completed = False
        pipeline_blocked = True
        output = None

    class FakeRunner:
        def run(self, *args, **kwargs):
            return FakeResult()

    monkeypatch.setattr(
        "hunt_chain_recon.cli.commands.ScopeGuardAdapter",
        FakeScopeGuard,
    )
    monkeypatch.setattr(
        "hunt_chain_recon.cli.commands.ApplicationRunner",
        FakeRunner,
    )

    result = run_cli(build_args())

    assert result == 3