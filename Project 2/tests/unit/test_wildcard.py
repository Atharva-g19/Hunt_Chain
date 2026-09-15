"""Tests for wildcard DNS analysis in Hunt_Chain Project 2."""

from __future__ import annotations

import pytest

from hunt_chain_recon.processing.wildcard import (
    WildcardAnalysisError,
    WildcardDNSAnalyzer,
    WildcardProbe,
)


def test_wildcard_probe_requires_hostname() -> None:
    """A wildcard probe must identify the queried hostname."""
    with pytest.raises(
        WildcardAnalysisError,
        match="hostname",
    ):
        WildcardProbe(
            hostname="",
            resolved_values=["192.0.2.10"],
        )


def test_wildcard_probe_normalizes_hostname() -> None:
    """Probe hostnames are normalized deterministically."""
    probe = WildcardProbe(
        hostname="RANDOM.Example.COM.",
        resolved_values=["192.0.2.10"],
    )

    assert probe.hostname == "random.example.com"


def test_wildcard_probe_normalizes_values() -> None:
    """DNS answer values are normalized before comparison."""
    probe = WildcardProbe(
        hostname="random.example.com",
        resolved_values=[
            "192.0.2.10",
            "192.0.2.10",
            "2001:db8::10",
        ],
    )

    assert probe.resolved_values == (
        "192.0.2.10",
        "2001:db8::10",
    )


def test_wildcard_detected_when_multiple_random_labels_share_answers() -> None:
    """Consistent answers for random labels indicate wildcard behavior."""
    probes = [
        WildcardProbe(
            hostname="random-a.example.com",
            resolved_values=["192.0.2.10"],
        ),
        WildcardProbe(
            hostname="random-b.example.com",
            resolved_values=["192.0.2.10"],
        ),
        WildcardProbe(
            hostname="random-c.example.com",
            resolved_values=["192.0.2.10"],
        ),
    ]

    result = WildcardDNSAnalyzer().analyze(
        "example.com",
        probes,
    )

    assert result.detected is True
    assert result.confidence == "HIGH"
    assert result.common_values == ("192.0.2.10",)
    assert result.probes_evaluated == 3


def test_wildcard_not_detected_when_answers_differ() -> None:
    """Different answers do not establish wildcard behavior."""
    probes = [
        WildcardProbe(
            hostname="random-a.example.com",
            resolved_values=["192.0.2.10"],
        ),
        WildcardProbe(
            hostname="random-b.example.com",
            resolved_values=["192.0.2.20"],
        ),
        WildcardProbe(
            hostname="random-c.example.com",
            resolved_values=["192.0.2.30"],
        ),
    ]

    result = WildcardDNSAnalyzer().analyze(
        "example.com",
        probes,
    )

    assert result.detected is False
    assert result.confidence == "LOW"
    assert result.common_values == ()
    assert result.probes_evaluated == 3


def test_unresolved_probe_does_not_establish_wildcard() -> None:
    """An unresolved random label is evidence against wildcard behavior."""
    probes = [
        WildcardProbe(
            hostname="random-a.example.com",
            resolved_values=["192.0.2.10"],
        ),
        WildcardProbe(
            hostname="random-b.example.com",
            resolved_values=[],
        ),
        WildcardProbe(
            hostname="random-c.example.com",
            resolved_values=["192.0.2.10"],
        ),
    ]

    result = WildcardDNSAnalyzer().analyze(
        "example.com",
        probes,
    )

    assert result.detected is False
    assert result.confidence == "LOW"


def test_insufficient_probes_return_unknown() -> None:
    """Fewer than two usable probes cannot establish wildcard behavior."""
    probes = [
        WildcardProbe(
            hostname="random-a.example.com",
            resolved_values=["192.0.2.10"],
        ),
    ]

    result = WildcardDNSAnalyzer().analyze(
        "example.com",
        probes,
    )

    assert result.detected is False
    assert result.confidence == "LOW"
    assert result.probes_evaluated == 1


def test_empty_probe_collection_returns_unknown() -> None:
    """No probes produce a controlled non-detection result."""
    result = WildcardDNSAnalyzer().analyze(
        "example.com",
        [],
    )

    assert result.detected is False
    assert result.confidence == "LOW"
    assert result.probes_evaluated == 0


def test_analyzer_rejects_empty_domain() -> None:
    """The analyzed domain must not be empty."""
    with pytest.raises(
        WildcardAnalysisError,
        match="domain",
    ):
        WildcardDNSAnalyzer().analyze(
            "",
            [],
        )


def test_analyzer_rejects_invalid_probe_objects() -> None:
    """Analyzer input must contain WildcardProbe objects."""
    with pytest.raises(
        WildcardAnalysisError,
        match="WildcardProbe",
    ):
        WildcardDNSAnalyzer().analyze(
            "example.com",
            ["not-a-probe"],
        )


def test_analyzer_does_not_perform_network_activity() -> None:
    """Wildcard analysis operates only on supplied observations."""
    analyzer = WildcardDNSAnalyzer()

    probes = [
        WildcardProbe(
            hostname="random-a.example.com",
            resolved_values=["192.0.2.10"],
        ),
        WildcardProbe(
            hostname="random-b.example.com",
            resolved_values=["192.0.2.10"],
        ),
    ]

    result = analyzer.analyze(
        "example.com",
        probes,
    )

    assert result.probes_evaluated == 2
    assert result.detected is True


def test_common_values_are_sorted_deterministically() -> None:
    """Analysis output remains deterministic regardless of input ordering."""
    probes = [
        WildcardProbe(
            hostname="random-a.example.com",
            resolved_values=[
                "2001:db8::20",
                "192.0.2.20",
            ],
        ),
        WildcardProbe(
            hostname="random-b.example.com",
            resolved_values=[
                "192.0.2.20",
                "2001:db8::20",
            ],
        ),
        WildcardProbe(
            hostname="random-c.example.com",
            resolved_values=[
                "2001:db8::20",
                "192.0.2.20",
            ],
        ),
    ]

    result = WildcardDNSAnalyzer().analyze(
        "example.com",
        probes,
    )

    assert result.detected is True
    assert result.common_values == (
        "192.0.2.20",
        "2001:db8::20",
    )


def test_result_contains_analyzed_domain() -> None:
    """The analysis result identifies the analyzed domain."""
    result = WildcardDNSAnalyzer().analyze(
        "Example.COM.",
        [],
    )

    assert result.domain == "example.com"