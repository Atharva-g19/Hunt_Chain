"""Tests for the infrastructure provider contract and local provider."""

from __future__ import annotations

from hunt_chain_recon.models.infrastructure import (
    InfrastructureConfidence,
    InfrastructureObservationType,
)
from hunt_chain_recon.providers.base import ProviderStatus
from hunt_chain_recon.providers.infrastructure.local import (
    LocalInfrastructureProvider,
)


def test_provider_has_stable_name() -> None:
    """The local provider exposes a stable provider name."""
    provider = LocalInfrastructureProvider()

    assert provider.name == "local"


def test_provider_has_stable_version() -> None:
    """The local provider exposes a stable version."""
    provider = LocalInfrastructureProvider()

    assert provider.version == "1.0"


def test_provider_exposes_capabilities() -> None:
    """The provider advertises its supported capabilities."""
    provider = LocalInfrastructureProvider()

    assert "shared_ip" in provider.capabilities
    assert "provider_identification" in provider.capabilities


def test_empty_metadata_returns_success() -> None:
    """An empty metadata set produces a successful empty result."""
    provider = LocalInfrastructureProvider()

    result = provider.categorize(
        ["192.0.2.10"],
        metadata={},
    )

    assert result.status == ProviderStatus.SUCCESS
    assert result.observations == []


def test_provider_metadata_creates_provider_observation() -> None:
    """Known provider metadata becomes an infrastructure observation."""
    provider = LocalInfrastructureProvider()

    result = provider.categorize(
        ["192.0.2.10"],
        metadata={
            "192.0.2.10": {
                "provider": "Example Cloud",
            }
        },
    )

    assert result.status == ProviderStatus.SUCCESS
    assert len(result.observations) == 1

    observation = result.observations[0]

    assert observation.observation_type == (
        InfrastructureObservationType.PROVIDER
    )
    assert observation.ip_address == "192.0.2.10"
    assert observation.value == "Example Cloud"
    assert observation.confidence == (
        InfrastructureConfidence.MEDIUM
    )


def test_cdn_metadata_creates_cdn_observation() -> None:
    """Known CDN metadata creates a CDN observation."""
    provider = LocalInfrastructureProvider()

    result = provider.categorize(
        ["192.0.2.20"],
        metadata={
            "192.0.2.20": {
                "cdn": "Example CDN",
            }
        },
    )

    assert result.status == ProviderStatus.SUCCESS
    assert len(result.observations) == 1

    observation = result.observations[0]

    assert observation.observation_type == (
        InfrastructureObservationType.CDN
    )
    assert observation.value == "Example CDN"


def test_cloud_platform_metadata_creates_observation() -> None:
    """Known cloud metadata creates a cloud-platform observation."""
    provider = LocalInfrastructureProvider()

    result = provider.categorize(
        ["192.0.2.30"],
        metadata={
            "192.0.2.30": {
                "cloud_platform": "Example Cloud",
            }
        },
    )

    assert result.status == ProviderStatus.SUCCESS

    observation = result.observations[0]

    assert observation.observation_type == (
        InfrastructureObservationType.CLOUD_PLATFORM
    )
    assert observation.value == "Example Cloud"


def test_unknown_ip_is_ignored() -> None:
    """Metadata for an IP outside the requested set is ignored."""
    provider = LocalInfrastructureProvider()

    result = provider.categorize(
        ["192.0.2.10"],
        metadata={
            "192.0.2.20": {
                "provider": "Other Provider",
            }
        },
    )

    assert result.observations == []


def test_multiple_metadata_types_are_preserved() -> None:
    """Multiple infrastructure observations for one IP are preserved."""
    provider = LocalInfrastructureProvider()

    result = provider.categorize(
        ["192.0.2.10"],
        metadata={
            "192.0.2.10": {
                "provider": "Example Cloud",
                "cdn": "Example CDN",
            }
        },
    )

    assert len(result.observations) == 2

    types = {
        observation.observation_type
        for observation in result.observations
    }

    assert types == {
        InfrastructureObservationType.PROVIDER,
        InfrastructureObservationType.CDN,
    }


def test_metadata_is_observation_only() -> None:
    """Provider metadata cannot create vulnerability conclusions."""
    provider = LocalInfrastructureProvider()

    result = provider.categorize(
        ["192.0.2.10"],
        metadata={
            "192.0.2.10": {
                "provider": "Example Cloud",
                "vulnerability": "critical",
            }
        },
    )

    assert len(result.observations) == 1

    observation = result.observations[0]

    assert "vulnerability" not in observation.metadata
    assert "critical" not in observation.evidence.lower()


def test_provider_is_deterministic() -> None:
    """The same metadata produces equivalent observations."""
    provider = LocalInfrastructureProvider()

    metadata = {
        "192.0.2.10": {
            "provider": "Example Cloud",
            "cdn": "Example CDN",
        }
    }

    first = provider.categorize(
        ["192.0.2.10"],
        metadata=metadata,
    )

    second = provider.categorize(
        ["192.0.2.10"],
        metadata=metadata,
    )

    first_values = [
        (
            item.observation_type,
            item.ip_address,
            item.value,
            item.evidence,
            item.confidence,
        )
        for item in first.observations
    ]

    second_values = [
        (
            item.observation_type,
            item.ip_address,
            item.value,
            item.evidence,
            item.confidence,
        )
        for item in second.observations
    ]

    assert first_values == second_values