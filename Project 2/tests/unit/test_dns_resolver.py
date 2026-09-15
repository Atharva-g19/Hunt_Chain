"""Tests for the Hunt_Chain Project 2 DNS resolver provider."""

from __future__ import annotations

from dataclasses import dataclass

import dns.exception
import dns.resolver
import pytest

from hunt_chain_recon.models.dns import (
    DNSRecordType,
    DNSResolutionStatus,
)
from hunt_chain_recon.providers.base import ProviderResult
from hunt_chain_recon.providers.dns.resolver import (
    DNSResolverProvider,
)


@dataclass
class FakeDNSRecord:
    """Minimal fake DNS record used by the test resolver."""

    value: str

    @property
    def address(self) -> str:
        return self.value

    @property
    def target(self) -> str:
        return self.value


class FakeRRSet:
    """Minimal fake RRset containing a TTL."""

    def __init__(self, ttl: int) -> None:
        self.ttl = ttl


class FakeAnswer:
    """Minimal dnspython-compatible answer object."""

    def __init__(
        self,
        values: list[str],
        ttl: int = 300,
    ) -> None:
        self._records = [
            FakeDNSRecord(value)
            for value in values
        ]
        self.rrset = FakeRRSet(ttl)

    def __iter__(self):
        return iter(self._records)


class FakeResolver:
    """Deterministic resolver with configurable DNS responses."""

    def __init__(
        self,
        responses: dict[tuple[str, str], object],
    ) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, float]] = []

    def resolve(
        self,
        hostname: str,
        record_type: str,
        *,
        lifetime: float,
    ) -> object:
        self.calls.append(
            (
                hostname,
                record_type,
                lifetime,
            )
        )

        response = self.responses.get(
            (hostname, record_type)
        )

        if isinstance(
            response,
            BaseException,
        ):
            raise response

        if response is None:
            raise dns.resolver.NoAnswer()

        return response


def test_dns_resolver_provider_identity():
    """The resolver exposes stable provider identity."""
    resolver = FakeResolver({})

    provider = DNSResolverProvider(
        timeout_seconds=3,
        resolver=resolver,
    )

    assert provider.name == "dns-resolver"
    assert provider.version == "1.0.0"


def test_dns_resolver_provider_capabilities():
    """The resolver exposes its supported DNS capabilities."""
    provider = DNSResolverProvider(
        resolver=FakeResolver({})
    )

    assert provider.capabilities == (
        "dns_resolution",
        "a_records",
        "aaaa_records",
        "cname_records",
    )


def test_dns_resolver_rejects_non_positive_timeout():
    """DNS timeout must be greater than zero."""
    with pytest.raises(
        ValueError,
        match="timeout_seconds must be greater than zero",
    ):
        DNSResolverProvider(
            timeout_seconds=0,
            resolver=FakeResolver({}),
        )


def test_dns_resolver_records_configured_timeout():
    """Every resolver request receives the configured timeout."""
    fake_resolver = FakeResolver(
        {
            (
                "example.com",
                "A",
            ): FakeAnswer(
                ["192.168.1.10"],
                ttl=300,
            )
        }
    )

    provider = DNSResolverProvider(
        timeout_seconds=7,
        resolver=fake_resolver,
    )

    provider.resolve(
        ["example.com"]
    )

    assert fake_resolver.calls

    assert all(
        call[2] == 7
        for call in fake_resolver.calls
    )


def test_dns_resolver_collects_a_record():
    """A records are converted into DNSRecord objects."""
    fake_resolver = FakeResolver(
        {
            (
                "example.com",
                "A",
            ): FakeAnswer(
                ["192.168.1.10"],
                ttl=300,
            )
        }
    )

    provider = DNSResolverProvider(
        resolver=fake_resolver
    )

    result = provider.resolve(
        ["example.com"]
    )

    assert isinstance(
        result,
        ProviderResult,
    )

    observation = result.observations[0]

    assert observation.status is DNSResolutionStatus.RESOLVED
    assert len(observation.address_records()) == 1

    record = observation.address_records()[0]

    assert record.record_type is DNSRecordType.A
    assert record.value == "192.168.1.10"
    assert record.ttl == 300


def test_dns_resolver_collects_aaaa_record():
    """AAAA records are converted correctly."""
    fake_resolver = FakeResolver(
        {
            (
                "example.com",
                "AAAA",
            ): FakeAnswer(
                ["2001:db8::1"],
                ttl=600,
            )
        }
    )

    provider = DNSResolverProvider(
        resolver=fake_resolver
    )

    result = provider.resolve(
        ["example.com"]
    )

    observation = result.observations[0]

    assert observation.status is DNSResolutionStatus.RESOLVED

    records = observation.address_records()

    assert len(records) == 1
    assert records[0].record_type is DNSRecordType.AAAA
    assert records[0].value == "2001:db8::1"
    assert records[0].ttl == 600


def test_dns_resolver_collects_cname_record():
    """CNAME records are converted correctly."""
    fake_resolver = FakeResolver(
        {
            (
                "app.example.com",
                "CNAME",
            ): FakeAnswer(
                ["external.example.net."],
                ttl=120,
            )
        }
    )

    provider = DNSResolverProvider(
        resolver=fake_resolver
    )

    result = provider.resolve(
        ["app.example.com"]
    )

    observation = result.observations[0]

    assert observation.status is DNSResolutionStatus.RESOLVED

    records = observation.cname_records()

    assert len(records) == 1
    assert records[0].record_type is DNSRecordType.CNAME
    assert records[0].value == "external.example.net"
    assert records[0].ttl == 120


def test_dns_resolver_collects_multiple_record_types():
    """A, AAAA, and CNAME records can coexist."""
    fake_resolver = FakeResolver(
        {
            (
                "example.com",
                "A",
            ): FakeAnswer(
                ["192.168.1.10"],
                ttl=300,
            ),
            (
                "example.com",
                "AAAA",
            ): FakeAnswer(
                ["2001:db8::1"],
                ttl=300,
            ),
            (
                "example.com",
                "CNAME",
            ): FakeAnswer(
                ["target.example.net."],
                ttl=300,
            ),
        }
    )

    provider = DNSResolverProvider(
        resolver=fake_resolver
    )

    result = provider.resolve(
        ["example.com"]
    )

    observation = result.observations[0]

    assert observation.status is DNSResolutionStatus.RESOLVED

    assert len(observation.records) == 3

    assert {
        record.record_type
        for record in observation.records
    } == {
        DNSRecordType.A,
        DNSRecordType.AAAA,
        DNSRecordType.CNAME,
    }


def test_dns_resolver_preserves_unresolved_hostname():
    """NXDOMAIN/NoAnswer results become UNRESOLVED."""
    fake_resolver = FakeResolver({})

    provider = DNSResolverProvider(
        resolver=fake_resolver
    )

    result = provider.resolve(
        ["missing.example.com"]
    )

    observation = result.observations[0]

    assert observation.status is DNSResolutionStatus.UNRESOLVED
    assert observation.records == []
    assert observation.error is None

    assert result.status.value == "SUCCESS"


def test_dns_resolver_preserves_timeout():
    """Resolver timeout becomes an explicit TIMEOUT observation."""
    fake_resolver = FakeResolver(
        {
            (
                "slow.example.com",
                "A",
            ): dns.resolver.LifetimeTimeout(
                timeout=5,
                errors=[],
            )
        }
    )

    provider = DNSResolverProvider(
        resolver=fake_resolver
    )

    result = provider.resolve(
        ["slow.example.com"]
    )

    observation = result.observations[0]

    assert observation.status is DNSResolutionStatus.TIMEOUT
    assert observation.records == []
    assert observation.error is not None

    assert result.status.value == "PARTIAL"


def test_dns_resolver_preserves_unexpected_error():
    """Unexpected resolver errors become ERROR observations."""
    fake_resolver = FakeResolver(
        {
            (
                "broken.example.com",
                "A",
            ): RuntimeError(
                "simulated resolver failure"
            )
        }
    )

    provider = DNSResolverProvider(
        resolver=fake_resolver
    )

    result = provider.resolve(
        ["broken.example.com"]
    )

    observation = result.observations[0]

    assert observation.status is DNSResolutionStatus.ERROR
    assert observation.records == []
    assert "simulated resolver failure" in observation.error

    assert result.status.value == "PARTIAL"


def test_dns_resolver_supports_multiple_hostnames():
    """Multiple hostnames produce separate observations."""
    fake_resolver = FakeResolver(
        {
            (
                "one.example.com",
                "A",
            ): FakeAnswer(
                ["192.168.1.10"]
            ),
            (
                "two.example.com",
                "A",
            ): FakeAnswer(
                ["192.168.1.20"]
            ),
        }
    )

    provider = DNSResolverProvider(
        resolver=fake_resolver
    )

    result = provider.resolve(
        [
            "one.example.com",
            "two.example.com",
        ]
    )

    assert len(result.observations) == 2

    assert [
        observation.hostname
        for observation in result.observations
    ] == [
        "one.example.com",
        "two.example.com",
    ]


def test_dns_resolver_preserves_partial_success():
    """Successful and unresolved hostnames coexist."""
    fake_resolver = FakeResolver(
        {
            (
                "good.example.com",
                "A",
            ): FakeAnswer(
                ["192.168.1.10"]
            )
        }
    )

    provider = DNSResolverProvider(
        resolver=fake_resolver
    )

    result = provider.resolve(
        [
            "good.example.com",
            "missing.example.com",
        ]
    )

    assert len(result.observations) == 2

    good = result.observations[0]
    missing = result.observations[1]

    assert good.status is DNSResolutionStatus.RESOLVED
    assert missing.status is DNSResolutionStatus.UNRESOLVED

    assert result.status.value == "SUCCESS"


def test_dns_resolver_skips_invalid_hostname():
    """Invalid hostname entries become provider errors."""
    fake_resolver = FakeResolver({})

    provider = DNSResolverProvider(
        resolver=fake_resolver
    )

    result = provider.resolve(
        [
            "example.com",
            "",
            123,
        ]
    )

    assert len(result.observations) == 1
    assert result.observations[0].hostname == "example.com"

    assert len(result.errors) == 2
    assert result.status.value == "PARTIAL"


def test_dns_resolver_rejects_empty_only_input_as_failed():
    """No valid hostnames produces a controlled provider failure."""
    fake_resolver = FakeResolver({})

    provider = DNSResolverProvider(
        resolver=fake_resolver
    )

    result = provider.resolve(
        [
            "",
            "   ",
            123,
        ]
    )

    assert result.observations == []
    assert result.errors
    assert result.status.value == "FAILED"


def test_dns_resolver_handles_empty_hostname_sequence():
    """An empty hostname sequence produces a controlled failure."""
    provider = DNSResolverProvider(
        resolver=FakeResolver({})
    )

    result = provider.resolve([])

    assert result.observations == []
    assert result.status.value == "FAILED"


def test_dns_resolver_metadata_contains_configuration():
    """Provider metadata exposes the resolver configuration."""
    provider = DNSResolverProvider(
        timeout_seconds=9,
        resolver=FakeResolver({}),
    )

    result = provider.resolve(
        []
    )

    assert result.metadata["timeout_seconds"] == 9
    assert result.metadata["record_types"] == [
        "A",
        "AAAA",
        "CNAME",
    ]


def test_dns_resolver_does_not_confirm_takeover():
    """DNS observations must not contain takeover conclusions."""
    fake_resolver = FakeResolver(
        {
            (
                "app.example.com",
                "CNAME",
            ): FakeAnswer(
                ["unclaimed.example.net."]
            )
        }
    )

    provider = DNSResolverProvider(
        resolver=fake_resolver
    )

    result = provider.resolve(
        ["app.example.com"]
    )

    observation = result.observations[0]

    assert observation.status is DNSResolutionStatus.RESOLVED

    assert not hasattr(
        observation,
        "takeover_confirmed",
    )

    assert not hasattr(
        observation,
        "vulnerability",
    )