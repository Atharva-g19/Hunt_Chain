"""Unit tests for the Project 2 output manager."""

from pathlib import Path

import pytest

from hunt_chain_recon.authorization.models import (
    AuthorizationDecision,
    AuthorizationResult,
)
from hunt_chain_recon.config.loader import load_config
from hunt_chain_recon.models.attack_surface import AttackSurface
from hunt_chain_recon.models.run import ReconRun
from hunt_chain_recon.output.manager import (
    OutputManager,
    OutputManagerError,
    OutputResult,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "default.yaml"


def build_attack_surface() -> AttackSurface:
    """Build a minimal valid AttackSurface fixture."""

    config = load_config(DEFAULT_CONFIG_PATH)

    authorization = AuthorizationResult(
        target="example.com",
        decision=AuthorizationDecision.IN_SCOPE,
        provider="scopeguard",
        reference="test-reference",
    )

    run = ReconRun.create(
        target="example.com",
        execution_mode=config.execution.mode,
    )

    return AttackSurface(
        schema_version="v1",
        run=run,
        target=config.target,
        authorization=config.authorization,
        execution=config.execution,
        assets=[],
        dns_observations=[],
        services=[],
        endpoints=[],
        http_observations=[],
        technologies=[],
        technology_evidence=[],
        indicators=[],
        relationships=[],
        metadata={},
    )


def test_write_generates_json_and_report(tmp_path: Path) -> None:
    """Both enabled output formats are generated."""

    attack_surface = build_attack_surface()
    manager = OutputManager()

    result = manager.write(
        attack_surface,
        tmp_path,
    )

    assert isinstance(result, OutputResult)
    assert result.json_path is not None
    assert result.report_path is not None

    assert result.json_path.exists()
    assert result.report_path.exists()


def test_write_generates_only_json_when_report_disabled(
    tmp_path: Path,
) -> None:
    """JSON-only output works."""

    attack_surface = build_attack_surface()
    manager = OutputManager()

    result = manager.write(
        attack_surface,
        tmp_path,
        json_enabled=True,
        report_enabled=False,
    )

    assert result.json_path is not None
    assert result.json_path.exists()

    assert result.report_path is None
    assert not (tmp_path / "recon_report.txt").exists()


def test_write_generates_only_report_when_json_disabled(
    tmp_path: Path,
) -> None:
    """Report-only output works."""

    attack_surface = build_attack_surface()
    manager = OutputManager()

    result = manager.write(
        attack_surface,
        tmp_path,
        json_enabled=False,
        report_enabled=True,
    )

    assert result.json_path is None
    assert not (tmp_path / "attack_surface.json").exists()

    assert result.report_path is not None
    assert result.report_path.exists()


def test_write_rejects_when_all_formats_disabled(
    tmp_path: Path,
) -> None:
    """At least one output format must be enabled."""

    attack_surface = build_attack_surface()
    manager = OutputManager()

    with pytest.raises(ValueError, match="At least one output format"):
        manager.write(
            attack_surface,
            tmp_path,
            json_enabled=False,
            report_enabled=False,
        )


def test_write_rejects_invalid_attack_surface(
    tmp_path: Path,
) -> None:
    """The manager accepts only AttackSurface instances."""

    manager = OutputManager()

    with pytest.raises(TypeError, match="AttackSurface"):
        manager.write(
            object(),
            tmp_path,
        )


def test_write_creates_output_directory(
    tmp_path: Path,
) -> None:
    """Missing output directories are created automatically."""

    attack_surface = build_attack_surface()
    manager = OutputManager()

    output_directory = tmp_path / "nested" / "recon" / "results"

    result = manager.write(
        attack_surface,
        output_directory,
        json_enabled=True,
        report_enabled=False,
    )

    assert output_directory.exists()
    assert result.json_path is not None
    assert result.json_path.exists()


def test_json_output_has_expected_filename(
    tmp_path: Path,
) -> None:
    """The machine-readable output uses the expected filename."""

    attack_surface = build_attack_surface()
    manager = OutputManager()

    result = manager.write(
        attack_surface,
        tmp_path,
        json_enabled=True,
        report_enabled=False,
    )

    assert result.json_path == (
        tmp_path / "attack_surface.json"
    )


def test_report_output_has_expected_filename(
    tmp_path: Path,
) -> None:
    """The human-readable output uses the expected filename."""

    attack_surface = build_attack_surface()
    manager = OutputManager()

    result = manager.write(
        attack_surface,
        tmp_path,
        json_enabled=False,
        report_enabled=True,
    )

    assert result.report_path == (
        tmp_path / "recon_report.txt"
    )


def test_output_manager_can_use_injected_components(
    tmp_path: Path,
) -> None:
    """Custom writer and report generator dependencies are supported."""

    attack_surface = build_attack_surface()

    class FakeJSONWriter:
        def write(self, attack_surface, output_path):
            output_path.write_text(
                '{"test": true}\n',
                encoding="utf-8",
            )
            return output_path

    class FakeReportGenerator:
        def write(self, attack_surface, output_path):
            Path(output_path).write_text(
                "test report\n",
                encoding="utf-8",
            )
            return output_path

    manager = OutputManager(
        json_writer=FakeJSONWriter(),
        report_generator=FakeReportGenerator(),
    )

    result = manager.write(
        attack_surface,
        tmp_path,
    )

    assert result.json_path is not None
    assert result.report_path is not None

    assert result.json_path.read_text(
        encoding="utf-8"
    ) == '{"test": true}\n'

    assert result.report_path.read_text(
        encoding="utf-8"
    ) == "test report\n"


def test_json_generation_failure_is_wrapped(
    tmp_path: Path,
) -> None:
    """JSON writer failures are exposed as OutputManagerError."""

    attack_surface = build_attack_surface()

    class FailingJSONWriter:
        def write(self, attack_surface, output_path):
            raise RuntimeError("simulated JSON failure")

    manager = OutputManager(
        json_writer=FailingJSONWriter(),
    )

    with pytest.raises(
        OutputManagerError,
        match="Failed to generate JSON output",
    ):
        manager.write(
            attack_surface,
            tmp_path,
            json_enabled=True,
            report_enabled=False,
        )


def test_report_generation_failure_is_wrapped(
    tmp_path: Path,
) -> None:
    """Report generator failures are exposed as OutputManagerError."""

    attack_surface = build_attack_surface()

    class FailingReportGenerator:
        def write(self, attack_surface, output_path):
            raise RuntimeError("simulated report failure")

    manager = OutputManager(
        report_generator=FailingReportGenerator(),
    )

    with pytest.raises(
        OutputManagerError,
        match="Failed to generate human-readable report",
    ):
        manager.write(
            attack_surface,
            tmp_path,
            json_enabled=False,
            report_enabled=True,
        )