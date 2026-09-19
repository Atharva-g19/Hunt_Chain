"""Tests for the Hunt_Chain Project 2 DNS pipeline stage."""

from __future__ import annotations

from datetime import datetime, timezone

from hunt_chain_recon.authorization.models import AuthorizationResult
from hunt_chain_recon.config.models import ReconConfig
from hunt_chain_recon.models.assets import Asset
from hunt_chain_recon.models.dns import (
    DNSObservation,
    DNSRecord,
    DNSRecordType,
    DNSResolutionStatus,
)
from hunt_chain_recon.models.run import ReconRun
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.pipeline.dns import (
    DNS_RESULTS_STATE_KEY,
    DNSStage,
    DNSStageError,
)
from hunt_chain_recon.policy.execution import ExecutionPolicy
from hunt_chain_recon.policy.politeness import PolitenessController
from hunt_chain_recon.providers.base import ProviderResult
from hunt_chain_recon.providers.dns.base import DNSProvider


class FakeDNSProvider(DNSProvider):
    """Deterministic DNS provider for DNS-stage tests."""

    def __init__(
        self,
        observations: list[DNSObservation] | None = None,
    ) -> None:
        self._observations = observations or []
        self.calls: list[list[str]] = []

    @property
    def name(self) -> str:
        return "fake-dns"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ("dns_resolution",)

    def resolve(
        self,
        hostnames: list[str],
    ) -> ProviderResult[DNSObservation]:
        self.calls.append(list(hostnames))

        return ProviderResult(
            status="SUCCESS",
            observations=list(self._observations),
            errors=[],
            provider=self.name,
            version=self.version,
            metadata={
                "fixture": True,
            },
        )


class InvalidDNSProvider(DNSProvider):
    """Provider returning an invalid observation for validation tests."""

    @property
    def name(self) -> str:
        return "invalid-dns"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ("dns_resolution",)

    def resolve(
        self,
        hostnames: list[str],
    ) -> ProviderResult[DNSObservation]:
        return ProviderResult(
            status="SUCCESS",
            observations=["not-a-dns-observation"],
            errors=[],
            provider=self.name,
            version=self.version,
            metadata={},
        )


def make_context(
    *,
    mode: str = "active",
    dns_enabled: bool = True,
    assets: list[Asset] | None = None,
) -> PipelineContext:
    """Create a deterministic authorized pipeline context."""
    config = ReconConfig(
        target={
            "value": "example.com",
            "type": "DOMAIN",
        },
        authorization={
            "provider": "scopeguard",
            "reference": "fixture-authorized",
        },
        execution={
            "mode": mode,
        },
        dns={
            "enabled": dns_enabled,
            "timeout_seconds": 5,
        },
        politeness={
            "concurrency": 1,
            "requests_per_second": 1000,
        },
    )

    authorization = AuthorizationResult(
        authorized=True,
        status="IN_SCOPE",
        target="example.com",
        provider="scopeguard",
        reference="fixture-authorized",
        reason="Fixture authorization.",
    )

    run = ReconRun(
        target="example.com",
        started_at=datetime.now(timezone.utc),
    )

    context = PipelineContext(
        config=config,
        authorization=authorization,
        execution_policy=ExecutionPolicy(
            config.execution
        ),
        politeness=PolitenessController(
            config.politeness
        ),
        run=run,
    )

    context.set_state(
        "assets",
        assets
        if assets is not None
        else [
            Asset(
                value="example.com",
                type="DOMAIN",
                normalized_value="example.com",
                sources=["fixture"],
            ),
            Asset(
                value="www.example.com",
                type="HOSTNAME",
                normalized_value="www.example.com",
                sources=["fixture"],
            ),
            Asset(
                value="api.example.com",
                type="HOSTNAME",
                normalized_value="api.example.com",
                sources=["fixture"],
            ),
            Asset(
                value="192.168.1.10",
                type="IP_ADDRESS",
                normalized_value="192.168.1.10",
                sources=["fixture"],
            ),
        ],
    )

    return context


def test_dns_stage_collects_domain_and_hostname_assets():
    """DNS stage resolves domain/hostname assets but never IP assets."""
    provider = FakeDNSProvider(
        [
            DNSObservation(
                hostname="www.example.com",
                status=DNSResolutionStatus.RESOLVED,
                records=[
                    DNSRecord(
                        record_type=DNSRecordType.A,
                        value="192.168.1.10",
                    )
                ],
            ),
            DNSObservation(
                hostname="api.example.com",
                status=DNSResolutionStatus.RESOLVED,
                records=[
                    DNSRecord(
                        record_type=DNSRecordType.A,
                        value="192.168.1.20",
                    )
                ],
            ),
        ]
    )

    context = make_context()

    result = DNSStage(
        provider=provider
    ).execute(context)

    assert result.hostnames_processed == 3
    assert provider.calls == [
        [
            "example.com",
            "www.example.com",
            "api.example.com",
        ]
    ]


def test_dns_stage_stores_result_in_pipeline_state():
    """DNS stage result is available to later pipeline stages."""
    provider = FakeDNSProvider(
        [
            DNSObservation(
                hostname="www.example.com",
                status=DNSResolutionStatus.RESOLVED,
            )
        ]
    )

    context = make_context()

    result = DNSStage(
        provider=provider
    ).execute(context)

    stored = context.get_state(
        DNS_RESULTS_STATE_KEY
    )

    assert stored is result
    assert result.observations[0].hostname == "www.example.com"


def test_dns_stage_uses_configured_provider():
    """Injected providers are used instead of constructing a live resolver."""
    provider = FakeDNSProvider()

    context = make_context()

    DNSStage(
        provider=provider
    ).execute(context)

    assert len(provider.calls) == 1


def test_dns_stage_preserves_unresolved_observations():
    """Unresolved DNS observations remain available."""
    provider = FakeDNSProvider(
        [
            DNSObservation(
                hostname="missing.example.com",
                status=DNSResolutionStatus.UNRESOLVED,
            )
        ]
    )

    context = make_context(
        assets=[
            Asset(
                value="missing.example.com",
                type="HOSTNAME",
                normalized_value="missing.example.com",
                sources=["fixture"],
            )
        ]
    )

    result = DNSStage(
        provider=provider
    ).execute(context)

    assert result.observations[0].status is (
        DNSResolutionStatus.UNRESOLVED
    )


def test_dns_stage_preserves_timeout_observations():
    """DNS timeout observations remain available."""
    provider = FakeDNSProvider(
        [
            DNSObservation(
                hostname="slow.example.com",
                status=DNSResolutionStatus.TIMEOUT,
                error="DNS resolution timed out.",
            )
        ]
    )

    context = make_context(
        assets=[
            Asset(
                value="slow.example.com",
                type="HOSTNAME",
                normalized_value="slow.example.com",
                sources=["fixture"],
            )
        ]
    )

    result = DNSStage(
        provider=provider
    ).execute(context)

    assert result.observations[0].status is (
        DNSResolutionStatus.TIMEOUT
    )
    assert result.observations[0].error == (
        "DNS resolution timed out."
    )


def test_dns_stage_preserves_cname_observations():
    """CNAME observations are passed through without interpretation."""
    provider = FakeDNSProvider(
        [
            DNSObservation(
                hostname="app.example.com",
                status=DNSResolutionStatus.RESOLVED,
                records=[
                    DNSRecord(
                        record_type=DNSRecordType.CNAME,
                        value="external.example.net",
                    )
                ],
            )
        ]
    )

    context = make_context(
        assets=[
            Asset(
                value="app.example.com",
                type="HOSTNAME",
                normalized_value="app.example.com",
                sources=["fixture"],
            )
        ]
    )

    result = DNSStage(
        provider=provider
    ).execute(context)

    observation = result.observations[0]

    assert observation.cname_records()[0].value == (
        "external.example.net"
    )


def test_dns_stage_skips_when_dns_is_disabled():
    """Disabled DNS configuration produces a SKIPPED result."""
    provider = FakeDNSProvider()

    context = make_context(
        dns_enabled=False
    )

    result = DNSStage(
        provider=provider
    ).execute(context)

    assert result.provider_result.status.value == "SKIPPED"
    assert result.hostnames_processed == 0
    assert result.observations == []
    assert provider.calls == []


def test_dns_stage_requires_authorization():
    """Unauthorized targets cannot reach the DNS provider."""
    provider = FakeDNSProvider()

    context = make_context()

    context.authorization = context.authorization.model_copy(
        update={
            "authorized": False,
            "status": "OUT_OF_SCOPE",
        }
    )

    try:
        DNSStage(
            provider=provider
        ).execute(context)
    except PermissionError:
        pass
    else:
        raise AssertionError(
            "DNS stage executed without authorization."
        )

    assert provider.calls == []


def test_dns_stage_requires_active_mode():
    """DNS resolution is blocked in passive-only mode."""
    provider = FakeDNSProvider()

    context = make_context(
        mode="passive_only"
    )

    try:
        DNSStage(
            provider=provider
        ).execute(context)
    except Exception as exc:
        assert "DNS_RESOLUTION" in str(exc)
    else:
        raise AssertionError(
            "DNS stage executed in passive_only mode."
        )

    assert provider.calls == []


def test_dns_stage_rejects_missing_assets():
    """DNS stage requires canonical assets from an earlier stage."""
    provider = FakeDNSProvider()

    context = make_context()
    context.state.clear()

    try:
        DNSStage(
            provider=provider
        ).execute(context)
    except DNSStageError as exc:
        assert "Canonical assets" in str(exc)
    else:
        raise AssertionError(
            "DNS stage accepted missing assets."
        )


def test_dns_stage_rejects_invalid_asset_state():
    """DNS stage rejects malformed asset pipeline state."""
    provider = FakeDNSProvider()

    context = make_context()
    context.set_state(
        "assets",
        {"invalid": "state"},
    )

    try:
        DNSStage(
            provider=provider
        ).execute(context)
    except DNSStageError as exc:
        assert "must contain a list" in str(exc)
    else:
        raise AssertionError(
            "DNS stage accepted invalid asset state."
        )


def test_dns_stage_rejects_invalid_asset_object():
    """DNS stage rejects non-Asset values."""
    provider = FakeDNSProvider()

    context = make_context(
        assets=["not-an-asset"]
    )

    try:
        DNSStage(
            provider=provider
        ).execute(context)
    except DNSStageError as exc:
        assert "invalid Asset" in str(exc)
    else:
        raise AssertionError(
            "DNS stage accepted an invalid Asset."
        )


def test_dns_stage_rejects_invalid_provider_observation():
    """DNS stage validates provider observations."""
    provider = InvalidDNSProvider()

    context = make_context()

    try:
        DNSStage(
            provider=provider
        ).execute(context)
    except DNSStageError as exc:
        assert "non-DNSObservation" in str(exc)
    else:
        raise AssertionError(
            "DNS stage accepted an invalid DNS observation."
        )


def test_dns_stage_reports_number_of_processed_hostnames():
    """Stage result records how many hostnames were submitted."""
    provider = FakeDNSProvider()

    context = make_context(
        assets=[
            Asset(
                value="one.example.com",
                type="HOSTNAME",
                normalized_value="one.example.com",
                sources=["fixture"],
            ),
            Asset(
                value="two.example.com",
                type="HOSTNAME",
                normalized_value="two.example.com",
                sources=["fixture"],
            ),
            Asset(
                value="10.0.0.1",
                type="IP_ADDRESS",
                normalized_value="10.0.0.1",
                sources=["fixture"],
            ),
        ]
    )

    result = DNSStage(
        provider=provider
    ).execute(context)

    assert result.hostnames_processed == 2
    assert provider.calls == [
        [
            "one.example.com",
            "two.example.com",
        ]
    ]


def test_dns_stage_handles_no_domain_or_hostname_assets():
    """IP-only assets produce an empty DNS request."""
    provider = FakeDNSProvider()

    context = make_context(
        assets=[
                Asset(
                value="192.168.1.10",
                type="IP_ADDRESS",
                normalized_value="192.168.1.10",
                sources=["fixture"],
            ),
        ]
    )

    result = DNSStage(
        provider=provider
    ).execute(context)

    assert result.hostnames_processed == 0
    assert provider.calls == [[]]
