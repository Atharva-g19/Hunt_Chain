"""Tests for shared-IP infrastructure intelligence."""

from __future__ import annotations

from uuid import uuid4

from hunt_chain_recon.models.assets import Asset, AssetType
from hunt_chain_recon.models.dns import (
    DNSObservation,
    DNSRecord,
    DNSRecordType,
    DNSResolutionStatus,
)
from hunt_chain_recon.models.infrastructure import (
    InfrastructureConfidence,
    InfrastructureObservationType,
)
from hunt_chain_recon.processing.infrastructure import (
    InfrastructureAnalyzer,
)


def make_hostname(value: str) -> Asset:
    """Create a hostname asset."""
    return Asset(
        value=value,
        normalized_value=value.lower().rstrip("."),
        type=AssetType.HOSTNAME,
        sources=["test"],
    )


def make_ip(value: str) -> Asset:
    """Create an IP asset."""
    return Asset(
        value=value,
        normalized_value=value,
        type=AssetType.IP_ADDRESS,
        sources=["test"],
    )


def make_dns_observation(
    hostname: str,
    ip_address: str,
) -> DNSObservation:
    """Create a resolved A-record observation."""
    return DNSObservation(
        hostname=hostname,
        status=DNSResolutionStatus.RESOLVED,
        records=[
            DNSRecord(
                record_type=DNSRecordType.A,
                value=ip_address,
            )
        ],
    )


def test_detects_shared_ip() -> None:
    """Multiple hostnames resolving to one IP are identified."""
    first = make_hostname("www.example.com")
    second = make_hostname("api.example.com")

    observations = [
        make_dns_observation(
            "www.example.com",
            "192.0.2.10",
        ),
        make_dns_observation(
            "api.example.com",
            "192.0.2.10",
        ),
    ]

    result = InfrastructureAnalyzer().analyze(
        assets=[first, second],
        dns_observations=observations,
    )

    assert len(result.observations) == 1

    observation = result.observations[0]

    assert observation.observation_type == (
        InfrastructureObservationType.SHARED_IP
    )
    assert observation.ip_address == "192.0.2.10"
    assert observation.confidence == InfrastructureConfidence.HIGH


def test_different_ips_are_not_shared() -> None:
    """Hostnames resolving to different IPs produce no shared-IP result."""
    first = make_hostname("www.example.com")
    second = make_hostname("api.example.com")

    observations = [
        make_dns_observation(
            "www.example.com",
            "192.0.2.10",
        ),
        make_dns_observation(
            "api.example.com",
            "192.0.2.20",
        ),
    ]

    result = InfrastructureAnalyzer().analyze(
        assets=[first, second],
        dns_observations=observations,
    )

    assert result.observations == []


def test_three_hostnames_sharing_ip_are_preserved() -> None:
    """All hostnames sharing an IP are represented in metadata."""
    assets = [
        make_hostname("www.example.com"),
        make_hostname("api.example.com"),
        make_hostname("mail.example.com"),
    ]

    observations = [
        make_dns_observation(
            "www.example.com",
            "192.0.2.10",
        ),
        make_dns_observation(
            "api.example.com",
            "192.0.2.10",
        ),
        make_dns_observation(
            "mail.example.com",
            "192.0.2.10",
        ),
    ]

    result = InfrastructureAnalyzer().analyze(
        assets=assets,
        dns_observations=observations,
    )

    assert len(result.observations) == 1

    observation = result.observations[0]

    assert observation.metadata["hostname_count"] == "3"

    hostnames = set(
        observation.metadata["hostnames"].split(",")
    )

    assert hostnames == {
        "www.example.com",
        "api.example.com",
        "mail.example.com",
    }


def test_same_hostname_multiple_records_does_not_count_as_shared() -> None:
    """Sharing an IP with itself is not shared-IP intelligence."""
    asset = make_hostname("www.example.com")

    observation = DNSObservation(
        hostname="www.example.com",
        status=DNSResolutionStatus.RESOLVED,
        records=[
            DNSRecord(
                record_type=DNSRecordType.A,
                value="192.0.2.10",
            ),
            DNSRecord(
                record_type=DNSRecordType.A,
                value="192.0.2.20",
            ),
        ],
    )

    result = InfrastructureAnalyzer().analyze(
        assets=[asset],
        dns_observations=[observation],
    )

    assert result.observations == []


def test_unresolved_hostname_is_ignored() -> None:
    """Unresolved DNS observations cannot produce shared-IP intelligence."""
    asset = make_hostname("missing.example.com")

    observation = DNSObservation(
        hostname="missing.example.com",
        status=DNSResolutionStatus.UNRESOLVED,
        records=[],
    )

    result = InfrastructureAnalyzer().analyze(
        assets=[asset],
        dns_observations=[observation],
    )

    assert result.observations == []


def test_timeout_is_ignored() -> None:
    """DNS timeouts are not treated as shared-IP evidence."""
    asset = make_hostname("timeout.example.com")

    observation = DNSObservation(
        hostname="timeout.example.com",
        status=DNSResolutionStatus.TIMEOUT,
        records=[],
    )

    result = InfrastructureAnalyzer().analyze(
        assets=[asset],
        dns_observations=[observation],
    )

    assert result.observations == []


def test_unknown_assets_are_ignored() -> None:
    """DNS observations without matching canonical hostname assets are ignored."""
    observation = make_dns_observation(
        "unknown.example.com",
        "192.0.2.10",
    )

    result = InfrastructureAnalyzer().analyze(
        assets=[],
        dns_observations=[observation],
    )

    assert result.observations == []


def test_ip_assets_are_not_used_as_hostname_sources() -> None:
    """Only canonical hostname assets contribute to shared-IP detection."""
    ip_asset = make_ip("192.0.2.10")

    observations = [
        make_dns_observation(
            "www.example.com",
            "192.0.2.10",
        ),
    ]

    result = InfrastructureAnalyzer().analyze(
        assets=[ip_asset],
        dns_observations=observations,
    )

    assert result.observations == []


def test_duplicate_dns_observations_are_deduplicated() -> None:
    """Repeated observations do not inflate the hostname count."""
    assets = [
        make_hostname("www.example.com"),
        make_hostname("api.example.com"),
    ]

    observations = [
        make_dns_observation(
            "www.example.com",
            "192.0.2.10",
        ),
        make_dns_observation(
            "www.example.com",
            "192.0.2.10",
        ),
        make_dns_observation(
            "api.example.com",
            "192.0.2.10",
        ),
    ]

    result = InfrastructureAnalyzer().analyze(
        assets=assets,
        dns_observations=observations,
    )

    assert len(result.observations) == 1
    assert result.observations[0].metadata["hostname_count"] == "2"


def test_ipv6_shared_ip_is_supported() -> None:
    """AAAA records can also produce shared-IP observations."""
    assets = [
        make_hostname("www.example.com"),
        make_hostname("api.example.com"),
    ]

    observations = [
        DNSObservation(
            hostname="www.example.com",
            status=DNSResolutionStatus.RESOLVED,
            records=[
                DNSRecord(
                    record_type=DNSRecordType.AAAA,
                    value="2001:db8::10",
                )
            ],
        ),
        DNSObservation(
            hostname="api.example.com",
            status=DNSResolutionStatus.RESOLVED,
            records=[
                DNSRecord(
                    record_type=DNSRecordType.AAAA,
                    value="2001:db8::10",
                )
            ],
        ),
    ]

    result = InfrastructureAnalyzer().analyze(
        assets=assets,
        dns_observations=observations,
    )

    assert len(result.observations) == 1
    assert result.observations[0].ip_address == "2001:db8::10"


def test_multiple_shared_ips_are_returned() -> None:
    """Independent shared IP groups are all returned."""
    assets = [
        make_hostname("www.example.com"),
        make_hostname("api.example.com"),
        make_hostname("mail.example.com"),
        make_hostname("dev.example.com"),
    ]

    observations = [
        make_dns_observation(
            "www.example.com",
            "192.0.2.10",
        ),
        make_dns_observation(
            "api.example.com",
            "192.0.2.10",
        ),
        make_dns_observation(
            "mail.example.com",
            "192.0.2.20",
        ),
        make_dns_observation(
            "dev.example.com",
            "192.0.2.20",
        ),
    ]

    result = InfrastructureAnalyzer().analyze(
        assets=assets,
        dns_observations=observations,
    )

    assert len(result.observations) == 2

    ips = {
        observation.ip_address
        for observation in result.observations
    }

    assert ips == {
        "192.0.2.10",
        "192.0.2.20",
    }


def test_analysis_is_deterministic() -> None:
    """Repeated analysis produces equivalent infrastructure intelligence."""
    assets = [
        make_hostname("www.example.com"),
        make_hostname("api.example.com"),
    ]

    observations = [
        make_dns_observation(
            "www.example.com",
            "192.0.2.10",
        ),
        make_dns_observation(
            "api.example.com",
            "192.0.2.10",
        ),
    ]

    analyzer = InfrastructureAnalyzer()

    first = analyzer.analyze(
        assets=assets,
        dns_observations=observations,
    )

    second = analyzer.analyze(
        assets=assets,
        dns_observations=observations,
    )

    assert [
        (
            item.observation_type,
            item.ip_address,
            item.value,
            item.evidence,
            item.confidence,
            item.metadata,
        )
        for item in first.observations
    ] == [
        (
            item.observation_type,
            item.ip_address,
            item.value,
            item.evidence,
            item.confidence,
            item.metadata,
        )
        for item in second.observations
    ]