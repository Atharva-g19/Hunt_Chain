"""Tests for the infrastructure intelligence pipeline stage."""

from __future__ import annotations

from uuid import uuid4

from hunt_chain_recon.authorization import AuthorizationResult
from hunt_chain_recon.config.loader import load_config
from hunt_chain_recon.models.assets import Asset, AssetType
from hunt_chain_recon.models.dns import (
    DNSObservation,
    DNSRecord,
    DNSRecordType,
    DNSResolutionStatus,
)
from hunt_chain_recon.models.infrastructure import (
    InfrastructureObservation,
    InfrastructureObservationType,
)
from hunt_chain_recon.models.run import ReconRun
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.pipeline.infrastructure import (
    INFRASTRUCTURE_RESULTS_STATE_KEY,
    InfrastructureStage,
)
from hunt_chain_recon.policy import (
    ExecutionPolicy,
    PolitenessController,
)
from hunt_chain_recon.providers.base import (
    ProviderResult,
    ProviderStatus,
)
from hunt_chain_recon.providers.infrastructure import (
    InfrastructureProvider,
)


class FakeInfrastructureProvider(InfrastructureProvider):
    """Deterministic provider for stage tests."""

    name = "fake"
    version = "1.0"

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Return fake provider capabilities."""
        return ("provider_identification",)

    def categorize(
        self,
        ip_addresses: list[str],
    ) -> ProviderResult[InfrastructureObservation]:
        """Return deterministic provider observations."""
        observations = [
            InfrastructureObservation(
                observation_type=InfrastructureObservationType.PROVIDER,
                ip_address=ip_address,
                value="Example Cloud",
                evidence="Test provider metadata.",
                confidence="MEDIUM",
            )
            for ip_address in ip_addresses
        ]

        return ProviderResult(
            status=ProviderStatus.SUCCESS,
            observations=observations,
            provider=self.name,
        )


def make_context() -> PipelineContext:
    """Create an authorized active pipeline context."""
    config = load_config("config/default.yaml")

    authorization = AuthorizationResult(
        target=config.target.value,
        decision="IN_SCOPE",
        provider="scopeguard",
        reference="test-reference",
    )

    return PipelineContext(
        config=config,
        authorization=authorization,
        execution_policy=ExecutionPolicy(
            config.execution
        ),
        politeness=PolitenessController(
            config.politeness
        ),
        run=ReconRun.create(
            target=config.target.value
        ),
    )


def make_hostname(value: str) -> Asset:
    """Create a hostname asset."""
    return Asset(
        value=value,
        normalized_value=value,
        type=AssetType.HOSTNAME,
        sources=["test"],
    )


def make_dns(
    hostname: str,
    ip_address: str,
) -> DNSObservation:
    """Create a resolved DNS observation."""
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


def seed_state(
    context: PipelineContext,
) -> tuple[Asset, Asset]:
    """Populate canonical assets and DNS results."""
    first = make_hostname("www.example.com")
    second = make_hostname("api.example.com")

    context.set_state(
        "assets",
        [first, second],
    )

    context.set_state(
        "dns_results",
        type(
            "DNSResult",
            (),
            {
                "observations": [
                    make_dns(
                        "www.example.com",
                        "192.0.2.10",
                    ),
                    make_dns(
                        "api.example.com",
                        "192.0.2.10",
                    ),
                ]
            },
        )(),
    )

    return first, second


def test_stage_detects_shared_ip() -> None:
    """The stage produces shared-IP intelligence."""
    context = make_context()
    seed_state(context)

    result = InfrastructureStage().execute(context)

    assert len(result.shared_ip_observations) == 1
    assert (
        result.shared_ip_observations[0].ip_address
        == "192.0.2.10"
    )


def test_stage_stores_result_in_context() -> None:
    """The stage stores its result in pipeline state."""
    context = make_context()
    seed_state(context)

    result = InfrastructureStage().execute(context)

    stored = context.get_state(
        INFRASTRUCTURE_RESULTS_STATE_KEY
    )

    assert stored is result


def test_stage_uses_injected_provider() -> None:
    """The stage uses an injected infrastructure provider."""
    context = make_context()
    seed_state(context)

    result = InfrastructureStage(
        provider=FakeInfrastructureProvider()
    ).execute(context)

    assert result.provider_observations

    assert all(
        observation.value == "Example Cloud"
        for observation in result.provider_observations
    )


def test_stage_combines_shared_ip_and_provider_results() -> None:
    """Shared-IP and provider observations are preserved together."""
    context = make_context()
    seed_state(context)

    result = InfrastructureStage(
        provider=FakeInfrastructureProvider()
    ).execute(context)

    assert len(result.observations) == 2

    types = {
        observation.observation_type
        for observation in result.observations
    }

    assert types == {
        InfrastructureObservationType.SHARED_IP,
        InfrastructureObservationType.PROVIDER,
    }


def test_stage_requires_dns_results() -> None:
    """Infrastructure analysis cannot run without DNS results."""
    context = make_context()

    try:
        InfrastructureStage().execute(context)
    except Exception as exc:
        assert "DNS results" in str(exc)
    else:
        raise AssertionError(
            "Expected infrastructure stage to reject missing DNS results."
        )


def test_stage_requires_assets() -> None:
    """Infrastructure analysis cannot run without canonical assets."""
    context = make_context()

    context.set_state(
        "dns_results",
        type(
            "DNSResult",
            (),
            {"observations": []},
        )(),
    )

    try:
        InfrastructureStage().execute(context)
    except Exception as exc:
        assert "canonical assets" in str(exc)
    else:
        raise AssertionError(
            "Expected infrastructure stage to reject missing assets."
        )


def test_stage_requires_authorization() -> None:
    """Infrastructure intelligence cannot bypass authorization."""
    context = make_context()

    context.authorization = AuthorizationResult(
        target=context.config.target.value,
        decision="OUT_OF_SCOPE",
        provider="scopeguard",
        reference="test-reference",
    )

    try:
        InfrastructureStage().execute(context)
    except Exception:
        pass
    else:
        raise AssertionError(
            "Expected unauthorized infrastructure execution to fail."
        )


def test_stage_metadata_reports_processed_ips() -> None:
    """Stage metadata records the number of processed IP addresses."""
    context = make_context()
    seed_state(context)

    result = InfrastructureStage().execute(context)

    assert result.metadata["ip_addresses_processed"] == 1


def test_stage_with_no_shared_ip_returns_empty_shared_results() -> None:
    """A unique IP produces no shared-IP observation."""
    context = make_context()

    asset = make_hostname("www.example.com")

    context.set_state(
        "assets",
        [asset],
    )

    context.set_state(
        "dns_results",
        type(
            "DNSResult",
            (),
            {
                "observations": [
                    make_dns(
                        "www.example.com",
                        "192.0.2.10",
                    )
                ]
            },
        )(),
    )

    result = InfrastructureStage().execute(context)

    assert result.shared_ip_observations == []


def test_stage_name_and_activity_are_stable() -> None:
    """The infrastructure stage exposes stable pipeline metadata."""
    stage = InfrastructureStage()

    assert stage.name == "infrastructure"
    assert stage.activity.value == "INFRASTRUCTURE_LOOKUP"