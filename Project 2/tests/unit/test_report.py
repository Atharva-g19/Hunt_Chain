"""Tests for the Hunt_Chain Project 2 human-readable report generator."""

from __future__ import annotations

from pathlib import Path

import pytest

from hunt_chain_recon.models.attack_surface import AttackSurface
from hunt_chain_recon.output.report import (
    ReconReportGenerator,
    ReportGenerationError,
)


def build_attack_surface() -> AttackSurface:
    """Build a minimal valid AttackSurface for report tests."""
    from hunt_chain_recon.models.run import ReconRun

    target = "example.com"

    run = ReconRun.create(
        target=target,
    )

    return AttackSurface(
        schema_version="v1",
        run=run,
        target={
            "value": target,
            "type": "DOMAIN",
        },
        authorization={
            "provider": "scopeguard",
            "reference": "test-reference",
        },
        execution={
            "mode": "active",
        },
        assets=[],
        dns_observations=[],
        services=[],
        endpoints=[],
        http_observations=[],
        technologies=[],
        technology_evidence=[],
        indicators=[],
        relationships=[],
        metadata={
            "test": True,
        },
    )


def test_generate_returns_string() -> None:
    """Report generation must return text."""
    generator = ReconReportGenerator()
    attack_surface = build_attack_surface()

    report = generator.generate(
        attack_surface
    )

    assert isinstance(
        report,
        str,
    )
    assert report.strip()


def test_report_contains_project_identity() -> None:
    """The report must identify Hunt_Chain Project 2."""
    generator = ReconReportGenerator()
    attack_surface = build_attack_surface()

    report = generator.generate(
        attack_surface
    )

    assert "HUNT_CHAIN PROJECT 2" in report
    assert "RECONNAISSANCE & ATTACK SURFACE REPORT" in report


def test_report_contains_target_information() -> None:
    """The report must contain target information."""
    generator = ReconReportGenerator()
    attack_surface = build_attack_surface()

    report = generator.generate(
        attack_surface
    )

    assert "example.com" in report
    assert "DOMAIN" in report
    assert "Schema Version : v1" in report


def test_report_contains_authorization_information() -> None:
    """The report must expose authorization metadata."""
    generator = ReconReportGenerator()
    attack_surface = build_attack_surface()

    report = generator.generate(
        attack_surface
    )

    assert "scopeguard" in report
    assert "test-reference" in report


def test_report_contains_execution_information() -> None:
    """The report must expose execution metadata."""
    generator = ReconReportGenerator()
    attack_surface = build_attack_surface()

    report = generator.generate(
        attack_surface
    )

    assert "Execution Mode         : active" in report
    assert "Run Status             : INITIALIZED" in report


def test_empty_attack_surface_is_reported_cleanly() -> None:
    """Empty collections must produce explicit empty-state messages."""
    generator = ReconReportGenerator()
    attack_surface = build_attack_surface()

    report = generator.generate(
        attack_surface
    )

    assert "No assets observed." in report
    assert "No DNS observations recorded." in report
    assert "No service observations recorded." in report
    assert "No endpoints recorded." in report
    assert "No HTTP observations recorded." in report
    assert "No technologies identified." in report
    assert "No reconnaissance indicators recorded." in report
    assert "No relationships recorded." in report


def test_report_contains_summary_counts() -> None:
    """The report must include collection counts."""
    generator = ReconReportGenerator()
    attack_surface = build_attack_surface()

    report = generator.generate(
        attack_surface
    )

    assert "Assets                 : 0" in report
    assert "DNS Observations       : 0" in report
    assert "Services               : 0" in report
    assert "Endpoints              : 0" in report
    assert "Technologies           : 0" in report
    assert "Indicators             : 0" in report
    assert "Relationships          : 0" in report


def test_report_contains_non_vulnerability_disclaimer() -> None:
    """The report must clearly distinguish reconnaissance from findings."""
    generator = ReconReportGenerator()
    attack_surface = build_attack_surface()

    report = generator.generate(
        attack_surface
    )

    assert "reconnaissance observations" in report
    assert "does not constitute a vulnerability confirmation" in report


def test_report_generation_is_deterministic() -> None:
    """Generating a report twice from the same model must be stable."""
    generator = ReconReportGenerator()
    attack_surface = build_attack_surface()

    first = generator.generate(
        attack_surface
    )
    second = generator.generate(
        attack_surface
    )

    assert first == second


def test_non_attack_surface_input_is_rejected() -> None:
    """The report generator must require an AttackSurface."""
    generator = ReconReportGenerator()

    with pytest.raises(
        TypeError,
        match="AttackSurface",
    ):
        generator.generate(
            {"schema_version": "v1"}  # type: ignore[arg-type]
        )


def test_write_creates_report_file(
    tmp_path: Path,
) -> None:
    """The report writer must create the requested file."""
    generator = ReconReportGenerator()
    attack_surface = build_attack_surface()

    output_path = (
        tmp_path
        / "reports"
        / "recon_report.txt"
    )

    result = generator.write(
        attack_surface,
        str(output_path),
    )

    assert result == str(output_path)
    assert output_path.is_file()


def test_written_report_contains_expected_content(
    tmp_path: Path,
) -> None:
    """The written report must contain the generated report."""
    generator = ReconReportGenerator()
    attack_surface = build_attack_surface()

    output_path = (
        tmp_path
        / "recon_report.txt"
    )

    generator.write(
        attack_surface,
        str(output_path),
    )

    content = output_path.read_text(
        encoding="utf-8",
    )

    assert "HUNT_CHAIN PROJECT 2" in content
    assert "example.com" in content
    assert "Schema Version : v1" in content


def test_write_creates_parent_directories(
    tmp_path: Path,
) -> None:
    """Report writing must create missing parent directories."""
    generator = ReconReportGenerator()
    attack_surface = build_attack_surface()

    output_path = (
        tmp_path
        / "nested"
        / "reports"
        / "recon_report.txt"
    )

    generator.write(
        attack_surface,
        str(output_path),
    )

    assert output_path.is_file()


def test_report_generation_error_is_exported() -> None:
    """The report module must expose its public exception."""
    assert issubclass(
        ReportGenerationError,
        Exception,
    )