"""Unit tests for the Certificate Transparency discovery provider.

All tests use deterministic local data and perform no network activity.
"""

from __future__ import annotations

from typing import Any

from hunt_chain_recon.providers.discovery import (
    CertificateTransparencyProvider,
)


class FakeCertificateTransparencyProvider(
    CertificateTransparencyProvider
):
    """CT provider with an injectable local data source."""

    def __init__(
        self,
        records: list[dict[str, Any]],
    ) -> None:
        """Initialize the fake provider with fixture records."""
        self.records = records

    def _query_source(
        self,
        domain: str,
    ) -> list[dict[str, Any]]:
        """Return deterministic fixture records."""
        return self.records


def test_ct_provider_metadata() -> None:
    """Verify provider identity and capabilities."""
    provider = CertificateTransparencyProvider()

    assert provider.name == "certificate-transparency"
    assert provider.version == "1.0.0"
    assert "passive_discovery" in provider.capabilities
    assert "certificate_transparency" in provider.capabilities
    assert "hostname_discovery" in provider.capabilities


def test_ct_extracts_hostnames_from_records() -> None:
    """Verify hostname extraction from CT name_value records."""
    provider = FakeCertificateTransparencyProvider(
        [
            {
                "name_value": (
                    "www.example.com\n"
                    "api.example.com\n"
                    "admin.example.com"
                )
            }
        ]
    )

    result = provider.discover("example.com")

    assert result.status.value == "SUCCESS"
    assert len(result.observations) == 3

    values = [
        observation["value"]
        for observation in result.observations
    ]

    assert values == [
        "www.example.com",
        "api.example.com",
        "admin.example.com",
    ]


def test_ct_removes_wildcard_prefix() -> None:
    """Verify wildcard certificate names become normal hostnames."""
    provider = FakeCertificateTransparencyProvider(
        [
            {
                "name_value": (
                    "*.example.com\n"
                    "*.api.example.com"
                )
            }
        ]
    )

    result = provider.discover("example.com")

    values = [
        observation["value"]
        for observation in result.observations
    ]

    assert values == [
        "example.com",
        "api.example.com",
    ]


def test_ct_keeps_target_domain() -> None:
    """Verify that the target domain itself is accepted."""
    provider = FakeCertificateTransparencyProvider(
        [
            {
                "name_value": "example.com"
            }
        ]
    )

    result = provider.discover("example.com")

    assert len(result.observations) == 1
    assert result.observations[0]["value"] == "example.com"
    assert result.observations[0]["type"] == "HOSTNAME"


def test_ct_filters_unrelated_domains() -> None:
    """Verify that unrelated certificate names are excluded."""
    provider = FakeCertificateTransparencyProvider(
        [
            {
                "name_value": (
                    "www.example.com\n"
                    "attacker.example.net\n"
                    "example.org\n"
                    "api.example.com"
                )
            }
        ]
    )

    result = provider.discover("example.com")

    values = [
        observation["value"]
        for observation in result.observations
    ]

    assert values == [
        "www.example.com",
        "api.example.com",
    ]


def test_ct_handles_invalid_records_without_failing() -> None:
    """Verify malformed CT records are ignored safely."""
    provider = FakeCertificateTransparencyProvider(
        [
            {},
            {
                "name_value": None,
            },
            {
                "name_value": 12345,
            },
            {
                "name_value": "www.example.com",
            },
        ]
    )

    result = provider.discover("example.com")

    assert result.status.value == "SUCCESS"
    assert len(result.observations) == 1
    assert result.observations[0]["value"] == "www.example.com"


def test_ct_invalid_target_returns_configuration_error() -> None:
    """Verify invalid targets produce a configuration error."""
    provider = FakeCertificateTransparencyProvider([])

    result = provider.discover("   ")

    assert result.status.value == "FAILED"
    assert len(result.errors) == 1
    assert result.errors[0].type.value == "CONFIGURATION_ERROR"


def test_ct_non_string_target_returns_configuration_error() -> None:
    """Verify non-string targets are rejected."""
    provider = FakeCertificateTransparencyProvider([])

    result = provider.discover(12345)

    assert result.status.value == "FAILED"
    assert result.errors[0].type.value == "CONFIGURATION_ERROR"


def test_ct_source_timeout_is_reported() -> None:
    """Verify CT source timeout errors are represented correctly."""

    class TimeoutProvider(CertificateTransparencyProvider):
        """Provider that simulates a source timeout."""

        def _query_source(
            self,
            domain: str,
        ) -> list[dict[str, Any]]:
            raise TimeoutError("CT source timed out.")

    provider = TimeoutProvider()

    result = provider.discover("example.com")

    assert result.status.value == "FAILED"
    assert result.errors[0].type.value == "TIMEOUT"
    assert result.errors[0].retryable is True


def test_ct_source_network_error_is_reported() -> None:
    """Verify CT network errors are represented correctly."""

    class NetworkErrorProvider(CertificateTransparencyProvider):
        """Provider that simulates a source network failure."""

        def _query_source(
            self,
            domain: str,
        ) -> list[dict[str, Any]]:
            raise OSError("CT source unavailable.")

    provider = NetworkErrorProvider()

    result = provider.discover("example.com")

    assert result.status.value == "FAILED"
    assert result.errors[0].type.value == "NETWORK_ERROR"
    assert result.errors[0].retryable is True


def test_ct_source_transport_is_not_silently_fabricated() -> None:
    """Verify the real provider does not invent CT observations."""
    provider = CertificateTransparencyProvider()

    result = provider.discover("example.com")

    assert result.status.value == "FAILED"
    assert result.errors[0].type.value == "EXECUTION_ERROR"