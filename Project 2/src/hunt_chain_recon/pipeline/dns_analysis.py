"""DNS analysis pipeline stage for Hunt_Chain Project 2.

This module interprets already-collected DNS observations.

Pipeline flow:

    DNSStage
        ->
    DNSAnalysisStage
        ->
    CNAME target resolution
        ->
    DanglingCNAMEAnalyzer
        ->
    Reconnaissance Indicators

The stage is responsible for:
- enforcing authorization,
- enforcing execution policy,
- consuming DNS-stage observations,
- identifying CNAME targets,
- resolving CNAME targets when required,
- invoking deterministic DNS analysis,
- preserving reconnaissance indicators.

The stage does not:
- confirm DNS takeover,
- exploit DNS services,
- perform vulnerability testing,
- perform HTTP probing,
- bypass ScopeGuard,
- treat timeout/error as dangling-CNAME evidence.

CNAME target resolution is a DNS network operation and therefore uses
the existing DNS execution policy and politeness controller.

Wildcard analysis remains a separate deterministic processing concern
until controlled wildcard probes are explicitly available to the stage.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from hunt_chain_recon.models.assets import Asset
from hunt_chain_recon.models.dns import (
    DNSObservation,
    DNSResolutionStatus,
)
from hunt_chain_recon.models.indicators import Indicator
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.pipeline.dns import (
    DNS_RESULTS_STATE_KEY,
    DNSStageResult,
)
from hunt_chain_recon.policy.execution import ExecutionActivity
from hunt_chain_recon.processing.dangling_cname import (
    DanglingCNAMEAnalyzer,
)
from hunt_chain_recon.providers.base import ProviderResult
from hunt_chain_recon.providers.dns.base import DNSProvider
from hunt_chain_recon.providers.dns.resolver import DNSResolverProvider


DNS_ANALYSIS_RESULTS_STATE_KEY = "dns_analysis_results"


class DNSAnalysisStageError(Exception):
    """Raised when the DNS analysis stage cannot execute."""


@dataclass(frozen=True)
class DNSAnalysisStageResult:
    """Result produced by the DNS analysis pipeline stage."""

    indicators: list[Indicator] = field(
        default_factory=list
    )

    cname_targets_processed: int = 0

    target_observations: list[DNSObservation] = field(
        default_factory=list
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )


class DNSAnalysisStage:
    """Analyze DNS observations for reconnaissance indicators."""

    name = "dns_analysis"

    activity = ExecutionActivity.DNS_RESOLUTION

    def __init__(
        self,
        provider: DNSProvider | None = None,
        dangling_analyzer: DanglingCNAMEAnalyzer | None = None,
    ) -> None:
        self._provider = provider
        self._dangling_analyzer = (
            dangling_analyzer or DanglingCNAMEAnalyzer()
        )

    @property
    def provider(self) -> DNSProvider | None:
        """Return the configured DNS provider."""
        return self._provider

    @property
    def dangling_analyzer(self) -> DanglingCNAMEAnalyzer:
        """Return the configured dangling-CNAME analyzer."""
        return self._dangling_analyzer

    def execute(
        self,
        context: PipelineContext,
    ) -> DNSAnalysisStageResult:
        """Analyze DNS observations from the preceding DNS stage."""
        context.require_authorized()

        context.execution_policy.require_allowed(
            self.activity
        )

        dns_stage_result = self._get_dns_stage_result(
            context
        )

        assets = self._get_assets(
            context
        )

        asset_ids_by_hostname = self._build_asset_index(
            assets
        )

        cname_observations = self._collect_cname_observations(
            dns_stage_result.observations
        )

        if not context.config.dns.dangling_cname_detection.enabled:
            result = DNSAnalysisStageResult(
                indicators=[],
                cname_targets_processed=0,
                target_observations=[],
                metadata={
                    "dangling_cname_detection": "DISABLED",
                    "cname_observations": len(cname_observations),
                },
            )

            context.set_state(
                DNS_ANALYSIS_RESULTS_STATE_KEY,
                result,
            )

            return result

        if not cname_observations:
            result = DNSAnalysisStageResult(
                indicators=[],
                cname_targets_processed=0,
                target_observations=[],
                metadata={
                    "dangling_cname_detection": "ENABLED",
                    "cname_observations": 0,
                },
            )

            context.set_state(
                DNS_ANALYSIS_RESULTS_STATE_KEY,
                result,
            )

            return result

        target_hostnames = self._collect_cname_targets(
            cname_observations
        )

        provider = self._provider or DNSResolverProvider(
            timeout_seconds=context.config.dns.timeout_seconds
        )

        target_result = self._resolve_cname_targets(
            context=context,
            provider=provider,
            target_hostnames=target_hostnames,
        )

        self._validate_observations(
            target_result.observations
        )

        target_status_by_hostname = {
            self._normalize_hostname(
                observation.hostname
            ): observation.status
            for observation in target_result.observations
        }

        indicators: list[Indicator] = []

        for observation in cname_observations:
            hostname = self._normalize_hostname(
                observation.hostname
            )

            asset_id = asset_ids_by_hostname.get(
                hostname
            )

            if asset_id is None:
                raise DNSAnalysisStageError(
                    f"No canonical Asset exists for CNAME hostname "
                    f"'{hostname}'."
                )

            cname_records = observation.cname_records()

            if len(cname_records) != 1:
                raise DNSAnalysisStageError(
                    f"CNAME observation for '{hostname}' must contain "
                    "exactly one CNAME record."
                )

            target = self._normalize_hostname(
                cname_records[0].value
            )

            target_status = target_status_by_hostname.get(
                target
            )

            if target_status is None:
                continue

            indicator = self._dangling_analyzer.analyze(
                cname_observation=observation,
                target_resolution_status=target_status,
                asset_id=asset_id,
            )

            if indicator is not None:
                indicators.append(
                    indicator
                )

        result = DNSAnalysisStageResult(
            indicators=indicators,
            cname_targets_processed=len(
                target_hostnames
            ),
            target_observations=list(
                target_result.observations
            ),
            metadata={
                "dangling_cname_detection": "ENABLED",
                "cname_observations": len(
                    cname_observations
                ),
                "target_resolution_status": (
                    target_result.status.value
                ),
            },
        )

        context.set_state(
            DNS_ANALYSIS_RESULTS_STATE_KEY,
            result,
        )

        return result

    @staticmethod
    def _get_dns_stage_result(
        context: PipelineContext,
    ) -> DNSStageResult:
        """Retrieve and validate the preceding DNS-stage result."""
        value = context.get_state(
            DNS_RESULTS_STATE_KEY
        )

        if value is None:
            raise DNSAnalysisStageError(
                "DNS analysis requires 'dns_results' from the "
                "preceding DNS stage."
            )

        if not isinstance(
            value,
            DNSStageResult,
        ):
            raise DNSAnalysisStageError(
                "Pipeline 'dns_results' state must contain a "
                "DNSStageResult."
            )

        DNSAnalysisStage._validate_observations(
            value.observations
        )

        return value

    @staticmethod
    def _get_assets(
        context: PipelineContext,
    ) -> list[Asset]:
        """Retrieve and validate canonical assets."""
        value = context.get_state(
            "assets"
        )

        if value is None:
            raise DNSAnalysisStageError(
                "DNS analysis requires canonical assets."
            )

        if not isinstance(
            value,
            list,
        ):
            raise DNSAnalysisStageError(
                "Pipeline assets state must contain a list."
            )

        for asset in value:
            if not isinstance(
                asset,
                Asset,
            ):
                raise DNSAnalysisStageError(
                    "Pipeline assets state contains an invalid Asset."
                )

        return value

    @staticmethod
    def _build_asset_index(
        assets: list[Asset],
    ) -> dict[str, UUID]:
        """Build a hostname-to-asset-ID lookup."""
        result: dict[str, UUID] = {}

        for asset in assets:
            if asset.type != "HOSTNAME":
                continue

            normalized = (
                asset.normalized_value
                .strip()
                .lower()
                .rstrip(".")
            )

            if not normalized:
                continue

            result.setdefault(
                normalized,
                asset.id,
            )

        return result

    @staticmethod
    def _collect_cname_observations(
        observations: list[DNSObservation],
    ) -> list[DNSObservation]:
        """Return DNS observations containing CNAME records."""
        return [
            observation
            for observation in observations
            if observation.cname_records()
        ]

    @classmethod
    def _collect_cname_targets(
        cls,
        observations: list[DNSObservation],
    ) -> list[str]:
        """Collect unique normalized CNAME targets."""
        targets: list[str] = []
        seen: set[str] = set()

        for observation in observations:
            cname_records = observation.cname_records()

            if len(cname_records) != 1:
                raise DNSAnalysisStageError(
                    f"DNS observation for '{observation.hostname}' "
                    "must contain exactly one CNAME record."
                )

            target = cls._normalize_hostname(
                cname_records[0].value
            )

            if target in seen:
                continue

            seen.add(target)
            targets.append(target)

        return targets

    @staticmethod
    def _resolve_cname_targets(
        context: PipelineContext,
        provider: DNSProvider,
        target_hostnames: list[str],
    ) -> ProviderResult[DNSObservation]:
        """Resolve CNAME targets through the configured DNS provider."""
        try:
            with context.politeness.operation():
                result = provider.resolve(
                    target_hostnames
                )
        except Exception as exc:
            raise DNSAnalysisStageError(
                f"DNS provider '{provider.name}' failed while "
                f"resolving CNAME targets: {exc}"
            ) from exc

        if not isinstance(
            result,
            ProviderResult,
        ):
            raise DNSAnalysisStageError(
                "DNS provider returned an invalid ProviderResult."
            )

        return result

    @staticmethod
    def _validate_observations(
        observations: list[Any],
    ) -> None:
        """Validate provider DNS observations."""
        for observation in observations:
            if not isinstance(
                observation,
                DNSObservation,
            ):
                raise DNSAnalysisStageError(
                    "DNS analysis received a non-DNSObservation value."
                )

    @staticmethod
    def _normalize_hostname(
        value: str,
    ) -> str:
        """Normalize a DNS hostname or CNAME target."""
        if not isinstance(
            value,
            str,
        ):
            raise DNSAnalysisStageError(
                "DNS hostname values must be strings."
            )

        normalized = (
            value
            .strip()
            .lower()
            .rstrip(".")
        )

        if not normalized:
            raise DNSAnalysisStageError(
                "DNS hostname values must not be empty."
            )

        return normalized