"""Contract tests for Hunt_Chain Project 2 providers.

These tests use fake providers and perform no network activity.
They verify the provider abstraction and result contracts before
real reconnaissance providers are implemented.
"""

from typing import Any

from hunt_chain_recon.models.dns import DNSObservation
from hunt_chain_recon.providers.base import (
    ProviderError,
    ProviderResult,
)
from hunt_chain_recon.providers.discovery import DiscoveryProvider
from hunt_chain_recon.providers.dns import DNSProvider
from hunt_chain_recon.providers.http import HTTPProvider
from hunt_chain_recon.providers.infrastructure import (
    InfrastructureProvider,
)


class FakeDiscoveryProvider(DiscoveryProvider):
    """Fake discovery provider used only for contract testing."""

    name = "fake-discovery"
    version = "1.0.0"

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Return capabilities exposed by the fake provider."""
        return (
            "asset_discovery",
            "hostname_discovery",
        )

    def discover(self, target: Any) -> ProviderResult[Any]:
        """Return a deterministic fake discovery result."""
        return ProviderResult(
            status="SUCCESS",
            observations=[
                {
                    "value": f"www.{target}",
                    "type": "HOSTNAME",
                }
            ],
            provider=self.name,
            version=self.version,
        )


class FakeDNSProvider(DNSProvider):
    """Fake DNS provider used only for contract testing."""

    name = "fake-dns"
    version = "1.0.0"

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Return capabilities exposed by the fake provider."""
        return (
            "dns_resolution",
            "a_records",
            "aaaa_records",
            "cname_records",
        )

    def resolve(
        self,
        hostnames: list[str],
    ) -> ProviderResult[DNSObservation]:
        """Return deterministic DNS observations."""
        observations: list[DNSObservation] = []

        for hostname in hostnames:
            observations.append(
                DNSObservation(
                    hostname=hostname,
                    state="UNRESOLVED",
                )
            )

        return ProviderResult(
            status="SUCCESS",
            observations=observations,
            provider=self.name,
            version=self.version,
        )


class FakeHTTPProvider(HTTPProvider):
    """Fake HTTP provider used only for contract testing."""

    name = "fake-http"
    version = "1.0.0"

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Return capabilities exposed by the fake provider."""
        return (
            "http_probe",
            "https_probe",
            "response_headers",
        )

    def probe(
        self,
        endpoints: list[Any],
    ) -> ProviderResult[Any]:
        """Return a deterministic fake HTTP result."""
        return ProviderResult(
            status="SUCCESS",
            observations=[
                {
                    "endpoint": str(endpoint.url),
                    "status_code": 200,
                }
                for endpoint in endpoints
            ],
            provider=self.name,
            version=self.version,
        )


class FakeInfrastructureProvider(InfrastructureProvider):
    """Fake infrastructure provider used only for contract testing."""

    name = "fake-infrastructure"
    version = "1.0.0"

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Return capabilities exposed by the fake provider."""
        return (
            "shared_ip_detection",
            "provider_identification",
        )

    def categorize(
        self,
        ip_addresses: list[str],
    ) -> ProviderResult[Any]:
        """Return deterministic infrastructure observations."""
        return ProviderResult(
            status="SUCCESS",
            observations=[
                {
                    "ip_address": ip_address,
                    "provider": "test-provider",
                }
                for ip_address in ip_addresses
            ],
            provider=self.name,
            version=self.version,
        )


def test_discovery_provider_contract() -> None:
    """Verify the discovery provider contract."""
    provider = FakeDiscoveryProvider()

    result = provider.execute("example.com")

    assert provider.name == "fake-discovery"
    assert provider.version == "1.0.0"
    assert "asset_discovery" in provider.capabilities

    assert result.status == "SUCCESS"
    assert result.provider == provider.name
    assert result.version == provider.version
    assert len(result.observations) == 1
    assert result.observations[0]["value"] == "www.example.com"


def test_dns_provider_contract() -> None:
    """Verify the DNS provider contract."""
    provider = FakeDNSProvider()

    result = provider.execute(
        [
            "www.example.com",
            "api.example.com",
        ]
    )

    assert provider.name == "fake-dns"
    assert "dns_resolution" in provider.capabilities

    assert result.status == "SUCCESS"
    assert result.provider == provider.name
    assert len(result.observations) == 2

    assert result.observations[0].hostname == "www.example.com"
    assert result.observations[0].state.value == "UNRESOLVED"


def test_http_provider_contract() -> None:
    """Verify the HTTP provider contract."""
    provider = FakeHTTPProvider()

    class FakeEndpoint:
        """Minimal endpoint object for the fake test."""

        def __init__(self, url: str) -> None:
            self.url = url

    endpoints = [
        FakeEndpoint("https://www.example.com/"),
        FakeEndpoint("https://api.example.com/"),
    ]

    result = provider.execute(endpoints)

    assert provider.name == "fake-http"
    assert "http_probe" in provider.capabilities

    assert result.status == "SUCCESS"
    assert result.provider == provider.name
    assert len(result.observations) == 2
    assert result.observations[0]["status_code"] == 200


def test_infrastructure_provider_contract() -> None:
    """Verify the infrastructure provider contract."""
    provider = FakeInfrastructureProvider()

    result = provider.execute(
        [
            "203.0.113.10",
            "203.0.113.20",
        ]
    )

    assert provider.name == "fake-infrastructure"
    assert "shared_ip_detection" in provider.capabilities

    assert result.status == "SUCCESS"
    assert result.provider == provider.name
    assert len(result.observations) == 2
    assert result.observations[0]["ip_address"] == "203.0.113.10"


def test_provider_result_can_represent_partial_execution() -> None:
    """Verify that providers can return observations plus execution errors."""
    result = ProviderResult(
        status="PARTIAL",
        observations=[
            {
                "value": "www.example.com",
                "type": "HOSTNAME",
            }
        ],
        errors=[
            ProviderError(
                type="TIMEOUT",
                message="One discovery source timed out.",
                retryable=True,
            )
        ],
        provider="fake-discovery",
        version="1.0.0",
    )

    assert result.status.value == "PARTIAL"
    assert len(result.observations) == 1
    assert len(result.errors) == 1
    assert result.errors[0].type.value == "TIMEOUT"
    assert result.errors[0].retryable is True


def test_provider_result_can_represent_skipped_execution() -> None:
    """Verify that a provider can explicitly report being skipped."""
    result = ProviderResult(
        status="SKIPPED",
        provider="fake-provider",
        version="1.0.0",
        metadata={
            "reason": "passive_only_mode",
        },
    )

    assert result.status.value == "SKIPPED"
    assert result.observations == []
    assert result.errors == []
    assert result.metadata["reason"] == "passive_only_mode"