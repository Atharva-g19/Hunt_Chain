"""Tests for potential dangling CNAME analysis in Hunt_Chain Project 2."""

from __future__ import annotations

from uuid import uuid4

import pytest

from hunt_chain_recon.models.dns import (
    DNSObservation,
    DNSRecord,
    DNSRecordType,
    DNSResolutionStatus,
)
from hunt_chain_recon.models.indicators import (
    IndicatorConfidence,
    IndicatorStatus,
    IndicatorType,
)
from hunt_chain_recon.processing.dangling_cname import (
    DanglingCNAMEAnalysisError,
    DanglingCNAMEAnalyzer,
)


def make_cname_observation(
    hostname: str = "app.example.com",
    target: str = "unclaimed.example.net",
    *,
    status: DNSResolutionStatus = DNSResolutionStatus.RESOLVED,
) -> DNSObservation:
    """Create a deterministic CNAME observation."""
    return DNSObservation(
        id=uuid4(),
        hostname=hostname,
        status=status,
        records=[
            DNSRecord(
                record_type=DNSRecordType.CNAME,
                value=target,
            )
        ],
    )


def test_analyzer_creates_potential_dangling_cname_indicator() -> None:
    """An unresolved CNAME target produces a potential indicator."""
    cname = make_cname_observation()

    result = DanglingCNAMEAnalyzer().analyze(
        cname_observation=cname,
        target_resolution_status=DNSResolutionStatus.UNRESOLVED,
        asset_id=uuid4(),
    )

    assert result is not None
    assert result.type is IndicatorType.POTENTIAL_DANGLING_CNAME
    assert result.status is IndicatorStatus.NEEDS_REVIEW
    assert result.confidence is IndicatorConfidence.MEDIUM


def test_indicator_references_cname_observation() -> None:
    """The generated indicator references its supporting DNS observation."""
    cname = make_cname_observation()
    asset_id = uuid4()

    result = DanglingCNAMEAnalyzer().analyze(
        cname_observation=cname,
        target_resolution_status=DNSResolutionStatus.UNRESOLVED,
        asset_id=asset_id,
    )

    assert result.asset_id == asset_id
    assert cname.id in result.source_ids


def test_indicator_contains_observable_evidence() -> None:
    """The indicator explains the observed CNAME and unresolved target."""
    cname = make_cname_observation(
        hostname="app.example.com",
        target="unclaimed.example.net",
    )

    result = DanglingCNAMEAnalyzer().analyze(
        cname_observation=cname,
        target_resolution_status=DNSResolutionStatus.UNRESOLVED,
        asset_id=uuid4(),
    )

    evidence = " ".join(result.evidence)

    assert "app.example.com" in evidence
    assert "unclaimed.example.net" in evidence
    assert "UNRESOLVED" in evidence


def test_resolved_cname_target_does_not_create_indicator() -> None:
    """A resolvable CNAME target is not considered dangling."""
    cname = make_cname_observation()

    result = DanglingCNAMEAnalyzer().analyze(
        cname_observation=cname,
        target_resolution_status=DNSResolutionStatus.RESOLVED,
        asset_id=uuid4(),
    )

    assert result is None


def test_timeout_target_does_not_create_confirmed_indicator() -> None:
    """A timeout is insufficient evidence for dangling-CNAME analysis."""
    cname = make_cname_observation()

    result = DanglingCNAMEAnalyzer().analyze(
        cname_observation=cname,
        target_resolution_status=DNSResolutionStatus.TIMEOUT,
        asset_id=uuid4(),
    )

    assert result is None


def test_error_target_does_not_create_confirmed_indicator() -> None:
    """A DNS error is insufficient evidence for a dangling indicator."""
    cname = make_cname_observation()

    result = DanglingCNAMEAnalyzer().analyze(
        cname_observation=cname,
        target_resolution_status=DNSResolutionStatus.ERROR,
        asset_id=uuid4(),
    )

    assert result is None


def test_unresolved_cname_without_cname_record_is_rejected() -> None:
    """The analyzer requires an actual CNAME observation."""
    observation = DNSObservation(
        hostname="app.example.com",
        status=DNSResolutionStatus.UNRESOLVED,
        records=[],
    )

    with pytest.raises(
        DanglingCNAMEAnalysisError,
        match="CNAME",
    ):
        DanglingCNAMEAnalyzer().analyze(
            cname_observation=observation,
            target_resolution_status=DNSResolutionStatus.UNRESOLVED,
            asset_id=uuid4(),
        )


def test_multiple_cname_records_are_rejected() -> None:
    """Ambiguous CNAME observations are rejected conservatively."""
    observation = DNSObservation(
        hostname="app.example.com",
        status=DNSResolutionStatus.RESOLVED,
        records=[
            DNSRecord(
                record_type=DNSRecordType.CNAME,
                value="one.example.net",
            ),
            DNSRecord(
                record_type=DNSRecordType.CNAME,
                value="two.example.net",
            ),
        ],
    )

    with pytest.raises(
        DanglingCNAMEAnalysisError,
        match="exactly one CNAME",
    ):
        DanglingCNAMEAnalyzer().analyze(
            cname_observation=observation,
            target_resolution_status=DNSResolutionStatus.UNRESOLVED,
            asset_id=uuid4(),
        )


def test_empty_asset_id_is_rejected() -> None:
    """The indicator must be associated with an asset."""
    cname = make_cname_observation()

    with pytest.raises(
        DanglingCNAMEAnalysisError,
        match="asset_id",
    ):
        DanglingCNAMEAnalyzer().analyze(
            cname_observation=cname,
            target_resolution_status=DNSResolutionStatus.UNRESOLVED,
            asset_id=None,
        )


def test_non_dns_observation_is_rejected() -> None:
    """The analyzer validates its DNS observation input."""
    with pytest.raises(
        DanglingCNAMEAnalysisError,
        match="DNSObservation",
    ):
        DanglingCNAMEAnalyzer().analyze(
            cname_observation="not-a-dns-observation",
            target_resolution_status=DNSResolutionStatus.UNRESOLVED,
            asset_id=uuid4(),
        )


def test_dangling_analysis_does_not_confirm_takeover() -> None:
    """Potential dangling CNAME remains an observation, not a takeover."""
    cname = make_cname_observation()

    result = DanglingCNAMEAnalyzer().analyze(
        cname_observation=cname,
        target_resolution_status=DNSResolutionStatus.UNRESOLVED,
        asset_id=uuid4(),
    )

    assert result.type is IndicatorType.POTENTIAL_DANGLING_CNAME
    assert result.status is IndicatorStatus.NEEDS_REVIEW

    assert "takeover_confirmed" not in result.metadata
    assert "vulnerability" not in result.metadata
    assert "exploited" not in result.metadata


def test_dangling_analysis_performs_no_network_activity() -> None:
    """Analysis consumes observations and performs no DNS requests."""
    cname = make_cname_observation()

    result = DanglingCNAMEAnalyzer().analyze(
        cname_observation=cname,
        target_resolution_status=DNSResolutionStatus.UNRESOLVED,
        asset_id=uuid4(),
    )

    assert result is not None


def test_cname_target_is_normalized_in_evidence() -> None:
    """Trailing DNS dots do not alter the normalized target."""
    cname = make_cname_observation(
        target="unclaimed.example.net.",
    )

    result = DanglingCNAMEAnalyzer().analyze(
        cname_observation=cname,
        target_resolution_status=DNSResolutionStatus.UNRESOLVED,
        asset_id=uuid4(),
    )

    assert result is not None
    assert result.metadata["cname_target"] == (
        "unclaimed.example.net"
    )

    evidence = " ".join(result.evidence)

    assert "unclaimed.example.net" in evidence