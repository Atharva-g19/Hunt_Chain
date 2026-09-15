"""Tests for DNS analysis pipeline stage in Hunt_Chain Project 2."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from hunt_chain_recon.authorization.models import AuthorizationResult
from hunt_chain_recon.config.models import ReconConfig
from hunt_chain_recon.models.assets import Asset
from hunt_chain_recon.models.dns import (
    DNSObservation,
    DNSRecord,
    DNSRecordType,
    DNSResolutionStatus,
)
from hunt_chain_recon.models.indicators import (
    IndicatorType,
)
from hunt_chain_recon.models.run import ReconRun
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.pipeline.dns import (
    DNS_RESULTS_STATE_KEY,
    DNSStageResult,
)
from hunt_chain_recon.policy.execution import ExecutionPolicy
from hunt_chain_recon.policy.politeness import PolitenessController
from hunt_chain_recon.providers.base import ProviderResult
from hunt_chain_recon.providers.dns.base import DNSProvider
from hunt_chain_recon.processing.dangling_cname import (
    DanglingCNAMEAnalyzer,
)
from hunt_chain_recon.pipeline.dns_analysis import (
    DNS_ANALYSIS_RESULTS_STATE_KEY,
    DNSAnalysisStage,
    DNSAnalysisStageError,
)


class FakeDNSProvider(DNSProvider):
    """Deterministic DNS provider for DNS-analysis tests."""

    def __init__(
        self,
        results: dict[str, DNSObservation],
    ) -> None:
        self._results = results
        self.calls: list[list[str]] = []

    @property
    def name(self) -> str:
        """Return the fixture provider name."""
        return "fake-dns-analysis"

    @property
    def version(self) -> str:
        """Return the fixture provider version."""
        return "1.0.0"

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Return supported fixture capabilities."""
        return ("dns_resolution",)

    def resolve(
        self,
        hostnames: list[str],
    ) -> ProviderResult[DNSObservation]:
        """Return deterministic observations for requested hostnames."""
        requested = list(hostnames)
        self.calls.append(requested)

        observations = [
            self._results[hostname]
            for hostname in requested
            if hostname in self._results
        ]

        return ProviderResult(
            status="SUCCESS",
            observations=observations,
            errors=[],
            provider=self.name,
            version=self.version,
            metadata={
                "fixture": True,
            },
        )


class InvalidDNSProvider(DNSProvider):
    """Provider returning an invalid DNS observation."""

    @property
    def name(self) -> str:
        """Return the fixture provider name."""
        return "invalid-dns-analysis"

    @property
    def version(self) -> str:
        """Return the fixture provider version."""
        return "1.0.0"

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Return supported fixture capabilities."""
        return ("dns_resolution",)

    def resolve(
        self,
        hostnames: list[str],
    ) -> ProviderResult[DNSObservation]:
        """Return an invalid observation for validation testing."""
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
    dangling_enabled: bool = True,
    wildcard_enabled: bool = True,
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
            "wildcard_detection": {
                "enabled": wildcard_enabled,
            },
            "dangling_cname_detection": {
                "enabled": dangling_enabled,
            },
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
        [
            Asset(
                value="app.example.com",
                type="HOSTNAME",
                normalized_value="app.example.com",
                sources=["fixture"],
            ),
            Asset(
                value="www.example.com",
                type="HOSTNAME",
                normalized_value="www.example.com",
                sources=["fixture"],
            ),
        ],
    )

    return context


def make_dns_stage_result(
    observations: list[DNSObservation],
) -> DNSStageResult:
    """Create a deterministic completed DNS-stage result."""
    provider_result = ProviderResult(
        status="SUCCESS",
        observations=observations,
        errors=[],
        provider="fixture-dns",
        version="1.0.0",
        metadata={
            "fixture": True,
        },
    )

    return DNSStageResult(
        provider_result=provider_result,
        hostnames_processed=len(observations),
    )


def make_cname_observation(
    *,
    hostname: str = "app.example.com",
    target: str = "unclaimed.example.net",
) -> DNSObservation:
    """Create a resolved CNAME observation."""
    return DNSObservation(
        id=uuid4(),
        hostname=hostname,
        status=DNSResolutionStatus.RESOLVED,
        records=[
            DNSRecord(
                record_type=DNSRecordType.CNAME,
                value=target,
            )
        ],
    )


def make_unresolved_observation(
    hostname: str,
) -> DNSObservation:
    """Create an unresolved DNS observation."""
    return DNSObservation(
        id=uuid4(),
        hostname=hostname,
        status=DNSResolutionStatus.UNRESOLVED,
        records=[],
    )


def test_dns_analysis_requires_dns_results() -> None:
    """DNS analysis requires the preceding DNS stage result."""
    context = make_context()

    try:
        DNSAnalysisStage().execute(context)
    except DNSAnalysisStageError as exc:
        assert "dns_results" in str(exc)
    else:
        raise AssertionError(
            "DNS analysis accepted missing DNS-stage state."
        )


def test_dns_analysis_requires_authorization() -> None:
    """DNS analysis cannot execute for an unauthorized target."""
    context = make_context()

    context.authorization = context.authorization.model_copy(
        update={
            "authorized": False,
            "status": "OUT_OF_SCOPE",
        }
    )

    try:
        DNSAnalysisStage().execute(context)
    except PermissionError:
        pass
    else:
        raise AssertionError(
            "DNS analysis executed without authorization."
        )


def test_dns_analysis_is_blocked_in_passive_only_mode() -> None:
    """CNAME target resolution is not performed in passive-only mode."""
    context = make_context(
        mode="passive_only",
    )

    cname = make_cname_observation()

    context.set_state(
        DNS_RESULTS_STATE_KEY,
        make_dns_stage_result([cname]),
    )

    provider = FakeDNSProvider(
        {
            "unclaimed.example.net": make_unresolved_observation(
                "unclaimed.example.net"
            )
        }
    )

    try:
        DNSAnalysisStage(
            provider=provider,
        ).execute(context)
    except Exception as exc:
        assert "DNS_RESOLUTION" in str(exc)
    else:
        raise AssertionError(
            "DNS analysis performed active DNS resolution "
            "in passive_only mode."
        )

    assert provider.calls == []


def test_dns_analysis_resolves_cname_targets() -> None:
    """CNAME targets are resolved through the injected DNS provider."""
    cname = make_cname_observation()

    context = make_context()

    context.set_state(
        DNS_RESULTS_STATE_KEY,
        make_dns_stage_result([cname]),
    )

    provider = FakeDNSProvider(
        {
            "unclaimed.example.net": make_unresolved_observation(
                "unclaimed.example.net"
            )
        }
    )

    DNSAnalysisStage(
        provider=provider,
    ).execute(context)

    assert provider.calls == [
        ["unclaimed.example.net"]
    ]


def test_dns_analysis_creates_potential_dangling_cname_indicator() -> None:
    """An unresolved CNAME target produces a review indicator."""
    cname = make_cname_observation()

    context = make_context()

    context.set_state(
        DNS_RESULTS_STATE_KEY,
        make_dns_stage_result([cname]),
    )

    provider = FakeDNSProvider(
        {
            "unclaimed.example.net": make_unresolved_observation(
                "unclaimed.example.net"
            )
        }
    )

    result = DNSAnalysisStage(
        provider=provider,
    ).execute(context)

    assert len(result.indicators) == 1
    assert result.indicators[0].type is (
        IndicatorType.POTENTIAL_DANGLING_CNAME
    )


def test_dns_analysis_does_not_create_indicator_for_resolved_target() -> None:
    """A resolved CNAME target does not produce a dangling indicator."""
    cname = make_cname_observation()

    context = make_context()

    context.set_state(
        DNS_RESULTS_STATE_KEY,
        make_dns_stage_result([cname]),
    )

    provider = FakeDNSProvider(
        {
            "unclaimed.example.net": DNSObservation(
                hostname="unclaimed.example.net",
                status=DNSResolutionStatus.RESOLVED,
                records=[
                    DNSRecord(
                        record_type=DNSRecordType.A,
                        value="192.168.1.50",
                    )
                ],
            )
        }
    )

    result = DNSAnalysisStage(
        provider=provider,
    ).execute(context)

    assert result.indicators == []


def test_dns_analysis_does_not_treat_timeout_as_dangling() -> None:
    """A timeout does not become a dangling-CNAME indicator."""
    cname = make_cname_observation()

    context = make_context()

    context.set_state(
        DNS_RESULTS_STATE_KEY,
        make_dns_stage_result([cname]),
    )

    provider = FakeDNSProvider(
        {
            "unclaimed.example.net": DNSObservation(
                hostname="unclaimed.example.net",
                status=DNSResolutionStatus.TIMEOUT,
                records=[],
                error="DNS resolution timed out.",
            )
        }
    )

    result = DNSAnalysisStage(
        provider=provider,
    ).execute(context)

    assert result.indicators == []


def test_dns_analysis_does_not_treat_error_as_dangling() -> None:
    """A DNS error does not become a dangling-CNAME indicator."""
    cname = make_cname_observation()

    context = make_context()

    context.set_state(
        DNS_RESULTS_STATE_KEY,
        make_dns_stage_result([cname]),
    )

    provider = FakeDNSProvider(
        {
            "unclaimed.example.net": DNSObservation(
                hostname="unclaimed.example.net",
                status=DNSResolutionStatus.ERROR,
                records=[],
                error="Resolver failure.",
            )
        }
    )

    result = DNSAnalysisStage(
        provider=provider,
    ).execute(context)

    assert result.indicators == []


def test_dns_analysis_ignores_non_cname_observations() -> None:
    """DNS analysis does not perform unnecessary target lookups."""
    observation = DNSObservation(
        hostname="www.example.com",
        status=DNSResolutionStatus.RESOLVED,
        records=[
            DNSRecord(
                record_type=DNSRecordType.A,
                value="192.168.1.10",
            )
        ],
    )

    context = make_context()

    context.set_state(
        DNS_RESULTS_STATE_KEY,
        make_dns_stage_result([observation]),
    )

    provider = FakeDNSProvider({})

    result = DNSAnalysisStage(
        provider=provider,
    ).execute(context)

    assert provider.calls == []
    assert result.indicators == []


def test_dns_analysis_stores_result_in_pipeline_state() -> None:
    """DNS-analysis result is available to later pipeline stages."""
    context = make_context()

    observation = DNSObservation(
        hostname="www.example.com",
        status=DNSResolutionStatus.RESOLVED,
        records=[
            DNSRecord(
                record_type=DNSRecordType.A,
                value="192.168.1.10",
            )
        ],
    )

    context.set_state(
        DNS_RESULTS_STATE_KEY,
        make_dns_stage_result([observation]),
    )

    result = DNSAnalysisStage().execute(context)

    stored = context.get_state(
        DNS_ANALYSIS_RESULTS_STATE_KEY
    )

    assert stored is result


def test_dns_analysis_can_disable_dangling_cname_detection() -> None:
    """Disabled dangling-CNAME analysis produces no indicators."""
    cname = make_cname_observation()

    context = make_context(
        dangling_enabled=False,
    )

    context.set_state(
        DNS_RESULTS_STATE_KEY,
        make_dns_stage_result([cname]),
    )

    provider = FakeDNSProvider(
        {
            "unclaimed.example.net": make_unresolved_observation(
                "unclaimed.example.net"
            )
        }
    )

    result = DNSAnalysisStage(
        provider=provider,
    ).execute(context)

    assert result.indicators == []
    assert provider.calls == []


def test_dns_analysis_validates_dns_stage_result() -> None:
    """Malformed DNS-stage state is rejected."""
    context = make_context()

    context.set_state(
        DNS_RESULTS_STATE_KEY,
        "invalid-dns-result",
    )

    try:
        DNSAnalysisStage().execute(context)
    except DNSAnalysisStageError as exc:
        assert "DNSStageResult" in str(exc)
    else:
        raise AssertionError(
            "DNS analysis accepted invalid DNS-stage state."
        )


def test_dns_analysis_rejects_invalid_provider_observation() -> None:
    """Provider observations are validated before analysis."""
    cname = make_cname_observation()

    context = make_context()

    context.set_state(
        DNS_RESULTS_STATE_KEY,
        make_dns_stage_result([cname]),
    )

    try:
        DNSAnalysisStage(
            provider=InvalidDNSProvider(),
        ).execute(context)
    except DNSAnalysisStageError as exc:
        assert "DNSObservation" in str(exc)
    else:
        raise AssertionError(
            "DNS analysis accepted an invalid DNS observation."
        )


def test_dns_analysis_does_not_confirm_takeover() -> None:
    """DNS analysis never upgrades an indicator into confirmed takeover."""
    cname = make_cname_observation()

    context = make_context()

    context.set_state(
        DNS_RESULTS_STATE_KEY,
        make_dns_stage_result([cname]),
    )

    provider = FakeDNSProvider(
        {
            "unclaimed.example.net": make_unresolved_observation(
                "unclaimed.example.net"
            )
        }
    )

    result = DNSAnalysisStage(
        provider=provider,
    ).execute(context)

    assert len(result.indicators) == 1

    indicator = result.indicators[0]

    assert "takeover_confirmed" not in indicator.metadata
    assert "vulnerability" not in indicator.metadata
    assert "exploited" not in indicator.metadata


def test_dns_analysis_uses_injected_dangling_analyzer() -> None:
    """The stage accepts the deterministic dangling-CNAME analyzer."""
    cname = make_cname_observation()

    context = make_context()

    context.set_state(
        DNS_RESULTS_STATE_KEY,
        make_dns_stage_result([cname]),
    )

    provider = FakeDNSProvider(
        {
            "unclaimed.example.net": make_unresolved_observation(
                "unclaimed.example.net"
            )
        }
    )

    analyzer = DanglingCNAMEAnalyzer()

    result = DNSAnalysisStage(
        provider=provider,
        dangling_analyzer=analyzer,
    ).execute(context)

    assert len(result.indicators) == 1