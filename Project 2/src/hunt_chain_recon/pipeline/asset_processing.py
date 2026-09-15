"""Asset-processing pipeline stage for Hunt_Chain Project 2.

This module connects discovery observations to the first canonical
processing layer of Project 2.

Processing flow:

    Discovery Provider
        ->
    ProviderResult
        ->
    Raw Discovery Observations
        ->
    AssetNormalizer
        ->
    AssetDeduplicator
        ->
    Canonical Unique Assets

Provider-level status is preserved in DiscoveryStageResult.

Only observations actually returned by providers are processed.
Therefore:

    SUCCESS -> observations processed
    PARTIAL -> observations processed
    FAILED  -> normally zero observations
    SKIPPED -> normally zero observations

A provider failure does not cause asset processing itself to fail.

This stage does not:
- perform network activity,
- resolve DNS,
- probe HTTP/HTTPS,
- fingerprint technologies,
- perform infrastructure lookups,
- determine vulnerabilities,
- confirm dangling DNS records,
- perform exploitation.

Authorization remains enforced by the pipeline context and execution
policy.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunt_chain_recon.models.assets import Asset
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.pipeline.discovery import (
    DISCOVERY_RESULTS_STATE_KEY,
    DiscoveryStageResult,
)
from hunt_chain_recon.policy.execution import ExecutionActivity
from hunt_chain_recon.processing.deduplication import (
    AssetDeduplicator,
    DeduplicationError,
)
from hunt_chain_recon.processing.normalization import (
    AssetNormalizer,
    NormalizationError,
)
from hunt_chain_recon.providers.base import ProviderResult


ASSETS_STATE_KEY = "assets"


class AssetProcessingStageError(Exception):
    """Raised when discovery assets cannot be processed."""


@dataclass(frozen=True)
class AssetProcessingStageResult:
    """Result produced by the asset-processing stage."""

    assets: list[Asset]
    observations_processed: int
    assets_before_deduplication: int
    assets_after_deduplication: int


class AssetProcessingStage:
    """Normalize and deduplicate discovery observations.

    The stage reads the output of DiscoveryStage from pipeline state.

    Provider-level failures are not treated as processing failures.
    Provider results remain available through DiscoveryStageResult.
    """

    name = "asset_processing"

    activity = ExecutionActivity.PASSIVE_DISCOVERY

    def __init__(
        self,
        normalizer: AssetNormalizer | None = None,
        deduplicator: AssetDeduplicator | None = None,
    ) -> None:
        self._normalizer = normalizer or AssetNormalizer()
        self._deduplicator = deduplicator or AssetDeduplicator()

    @property
    def normalizer(self) -> AssetNormalizer:
        """Return the configured asset normalizer."""
        return self._normalizer

    @property
    def deduplicator(self) -> AssetDeduplicator:
        """Return the configured asset deduplicator."""
        return self._deduplicator

    def execute(
        self,
        context: PipelineContext,
    ) -> AssetProcessingStageResult:
        """Process discovery observations into canonical unique assets."""
        context.require_authorized()

        context.execution_policy.require_allowed(
            self.activity
        )

        discovery_result = context.get_state(
            DISCOVERY_RESULTS_STATE_KEY
        )

        if discovery_result is None:
            raise AssetProcessingStageError(
                "Discovery results are not available in pipeline state."
            )

        if not isinstance(
            discovery_result,
            DiscoveryStageResult,
        ):
            raise AssetProcessingStageError(
                "Pipeline state contains an invalid discovery result."
            )

        observations = self._collect_observations(
            discovery_result
        )

        try:
            normalized_assets = self._normalize_observations(
                observations
            )

            unique_assets = self._deduplicator.deduplicate(
                normalized_assets
            )
        except (
            NormalizationError,
            DeduplicationError,
        ) as exc:
            raise AssetProcessingStageError(
                f"Asset processing failed: {exc}"
            ) from exc

        result = AssetProcessingStageResult(
            assets=unique_assets,
            observations_processed=len(observations),
            assets_before_deduplication=len(
                normalized_assets
            ),
            assets_after_deduplication=len(
                unique_assets
            ),
        )

        context.set_state(
            ASSETS_STATE_KEY,
            unique_assets,
        )

        return result

    @staticmethod
    def _collect_observations(
        discovery_result: DiscoveryStageResult,
    ) -> list[dict[str, Any]]:
        """Collect observations from discovery provider results.

        Provider status is intentionally not used as a reason to discard
        observations. A PARTIAL provider may have useful observations,
        and even a provider reporting FAILED may have partial observations
        supplied alongside its error information.

        The stage therefore processes whatever valid observations the
        provider actually returned.
        """
        observations: list[dict[str, Any]] = []

        for provider_name, provider_result in (
            discovery_result.provider_results.items()
        ):
            if not isinstance(
                provider_result,
                ProviderResult,
            ):
                raise AssetProcessingStageError(
                    f"Discovery provider '{provider_name}' returned "
                    "an invalid provider result."
                )

            for observation in provider_result.observations:
                if not isinstance(observation, dict):
                    raise AssetProcessingStageError(
                        f"Discovery provider '{provider_name}' returned "
                        "a non-dictionary observation."
                    )

                observation_copy = dict(observation)

                if not observation_copy.get("source"):
                    observation_copy["source"] = provider_name

                observations.append(
                    observation_copy
                )

        return observations

    def _normalize_observations(
        self,
        observations: list[dict[str, Any]],
    ) -> list[Asset]:
        """Normalize raw discovery observations."""
        assets: list[Asset] = []

        for observation in observations:
            assets.append(
                self._normalizer.normalize(
                    observation
                )
            )

        return assets