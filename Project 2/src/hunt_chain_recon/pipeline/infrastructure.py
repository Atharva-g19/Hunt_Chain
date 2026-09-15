"""Infrastructure intelligence pipeline stage for Hunt_Chain Project 2."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Sequence

from hunt_chain_recon.models.assets import Asset, AssetType
from hunt_chain_recon.models.dns import (
    DNSObservation,
    DNSRecordType,
    DNSResolutionStatus,
)
from hunt_chain_recon.models.infrastructure import InfrastructureObservation
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.policy.execution import ExecutionActivity
from hunt_chain_recon.processing.infrastructure import InfrastructureAnalyzer
from hunt_chain_recon.providers.base import ProviderResult
from hunt_chain_recon.providers.infrastructure import InfrastructureProvider
from hunt_chain_recon.providers.infrastructure.local import (
    LocalInfrastructureProvider,
)


INFRASTRUCTURE_RESULTS_STATE_KEY = "infrastructure_results"


class InfrastructureStageError(RuntimeError):
    """Raised when infrastructure analysis cannot be completed."""


@dataclass(frozen=True)
class InfrastructureStageResult:
    """Result produced by the infrastructure pipeline stage."""

    observations: list[InfrastructureObservation] = field(
        default_factory=list
    )
    shared_ip_observations: list[InfrastructureObservation] = field(
        default_factory=list
    )
    provider_observations: list[InfrastructureObservation] = field(
        default_factory=list
    )
    metadata: dict[str, Any] = field(default_factory=dict)


class InfrastructureStage:
    """Run infrastructure intelligence over existing recon state.

    The stage itself performs no network activity.

    Shared-IP analysis is deterministic and operates on existing DNS
    observations. Provider-backed infrastructure operations are executed
    through the configured politeness controller.
    """

    name = "infrastructure"

    activity = ExecutionActivity.INFRASTRUCTURE_LOOKUP

    def __init__(
        self,
        *,
        provider: InfrastructureProvider | None = None,
        analyzer: InfrastructureAnalyzer | None = None,
    ) -> None:
        self.provider = provider
        self.analyzer = analyzer or InfrastructureAnalyzer()

    def execute(
        self,
        context: PipelineContext,
    ) -> InfrastructureStageResult:
        """Execute infrastructure intelligence against pipeline state."""

        context.require_authorized()

        context.execution_policy.require_allowed(
            self.activity
        )

        # DNS results are the required upstream input for infrastructure
        # correlation. Validate this before assets so a missing DNS stage
        # produces a deterministic and meaningful error.
        dns_observations = self._get_dns_observations(
            context
        )

        assets = self._get_assets(
            context
        )

        infrastructure_config = context.config.infrastructure

        shared_ip_observations: list[
            InfrastructureObservation
        ] = []

        if infrastructure_config.shared_ip_detection:
            analysis_result = self.analyzer.analyze(
                assets=assets,
                dns_observations=dns_observations,
            )

            shared_ip_observations.extend(
                analysis_result.observations
            )

        provider_observations: list[
            InfrastructureObservation
        ] = []

        provider_config = (
            infrastructure_config.provider_identification
        )

        if provider_config.enabled:
            ip_addresses = self._collect_ip_addresses(
                assets=assets,
                dns_observations=dns_observations,
            )

            if ip_addresses:
                provider_result = self._execute_provider(
                    context=context,
                    ip_addresses=ip_addresses,
                )

                provider_observations.extend(
                    provider_result.observations
                )

        observations = (
            shared_ip_observations
            + provider_observations
        )

        processed_ip_addresses = self._collect_ip_addresses(
            assets=assets,
            dns_observations=dns_observations,
        )

        result = InfrastructureStageResult(
            observations=observations,
            shared_ip_observations=shared_ip_observations,
            provider_observations=provider_observations,
            metadata={
                "ip_addresses_processed": len(
                    processed_ip_addresses
                ),
                "shared_ip_detection_enabled": (
                    infrastructure_config.shared_ip_detection
                ),
                "provider_identification_enabled": (
                    provider_config.enabled
                ),
            },
        )

        context.set_state(
            INFRASTRUCTURE_RESULTS_STATE_KEY,
            result,
        )

        return result

    @staticmethod
    def _get_assets(
        context: PipelineContext,
    ) -> list[Asset]:
        """Retrieve canonical assets from pipeline state."""

        value = context.get_state(
            "assets"
        )

        if value is None:
            raise InfrastructureStageError(
                "Infrastructure analysis requires canonical assets."
            )

        if not isinstance(
            value,
            Sequence,
        ) or isinstance(
            value,
            (str, bytes, bytearray),
        ):
            raise InfrastructureStageError(
                "Pipeline state 'assets' must be a sequence."
            )

        assets = list(value)

        for asset in assets:
            if not isinstance(
                asset,
                Asset,
            ):
                raise InfrastructureStageError(
                    "Pipeline state 'assets' contains an invalid asset."
                )

        return assets

    @staticmethod
    def _get_dns_observations(
        context: PipelineContext,
    ) -> list[DNSObservation]:
        """Retrieve DNS observations from the DNS stage."""

        value = context.get_state(
            "dns_results"
        )

        if value is None:
            raise InfrastructureStageError(
                "Infrastructure analysis requires DNS results."
            )

        observations = getattr(
            value,
            "observations",
            None,
        )

        if observations is None:
            raise InfrastructureStageError(
                "Infrastructure analysis requires DNS results "
                "containing observations."
            )

        if not isinstance(
            observations,
            Sequence,
        ) or isinstance(
            observations,
            (str, bytes, bytearray),
        ):
            raise InfrastructureStageError(
                "DNS results observations must be a sequence."
            )

        dns_observations = list(
            observations
        )

        for observation in dns_observations:
            if not isinstance(
                observation,
                DNSObservation,
            ):
                raise InfrastructureStageError(
                    "DNS results contain an invalid observation."
                )

        return dns_observations

    @staticmethod
    def _collect_ip_addresses(
        *,
        assets: Sequence[Asset],
        dns_observations: Sequence[DNSObservation],
    ) -> list[str]:
        """Collect deterministic unique IP addresses."""

        addresses: set[str] = set()

        for asset in assets:
            if asset.type is AssetType.IP_ADDRESS:
                addresses.add(
                    asset.normalized_value
                    or asset.value
                )

        for observation in dns_observations:
            if observation.status is not DNSResolutionStatus.RESOLVED:
                continue

            for record in observation.records:
                if record.record_type in (
                    DNSRecordType.A,
                    DNSRecordType.AAAA,
                ):
                    addresses.add(
                        record.value
                    )

        return sorted(
            addresses
        )

    def _execute_provider(
        self,
        *,
        context: PipelineContext,
        ip_addresses: Sequence[str],
    ) -> ProviderResult[
        InfrastructureObservation
    ]:
        """Execute the infrastructure provider under politeness control."""

        provider = (
            self.provider
            or LocalInfrastructureProvider()
        )

        if not isinstance(
            provider,
            InfrastructureProvider,
        ):
            raise InfrastructureStageError(
                "Infrastructure provider must implement "
                "InfrastructureProvider."
            )

        try:
            with context.politeness.operation():
                result = provider.categorize(
                    list(ip_addresses)
                )
        except Exception as exc:
            raise InfrastructureStageError(
                f"Infrastructure provider "
                f"'{provider.name}' failed: {exc}"
            ) from exc

        if not isinstance(
            result,
            ProviderResult,
        ):
            raise InfrastructureStageError(
                "Infrastructure provider returned an invalid result."
            )

        for observation in result.observations:
            if not isinstance(
                observation,
                InfrastructureObservation,
            ):
                raise InfrastructureStageError(
                    "Infrastructure provider returned an invalid "
                    "infrastructure observation."
                )

        return result