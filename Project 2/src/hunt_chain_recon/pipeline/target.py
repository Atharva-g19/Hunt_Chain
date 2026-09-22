"""Target initialization stage for Hunt_Chain Project 2."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from hunt_chain_recon.models.assets import Asset
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.policy.execution import ExecutionActivity
from hunt_chain_recon.processing.normalization import (
    AssetNormalizer,
    NormalizationError,
)


TARGET_ASSET_STATE_KEY = "target_asset"


class TargetStageError(RuntimeError):
    """Raised when target initialization cannot complete."""


@dataclass(frozen=True)
class TargetStageResult:
    """Result produced by target initialization."""

    asset: Asset
    metadata: dict[str, Any] = field(
        default_factory=dict
    )


class TargetStage:
    """Create the configured target as a canonical Asset."""

    name = "target"
    activity = ExecutionActivity.PASSIVE_DISCOVERY

    def __init__(
        self,
        normalizer: AssetNormalizer | None = None,
    ) -> None:
        self._normalizer = normalizer or AssetNormalizer()

    def execute(
        self,
        context: PipelineContext,
    ) -> TargetStageResult:
        """Initialize the configured target."""

        context.require_authorized()

        context.execution_policy.require_allowed(
            self.activity
        )

        target = context.config.target
        asset_value = target.value
        asset_type = target.type

        # Preserve an explicitly authorized URL as the HTTP discovery seed,
        # while representing the canonical asset using the supported hostname
        # asset type. The original URL remains available through config.target
        # for endpoint generation and web discovery.
        if target.type == "URL":
            parsed = urlparse(target.value)

            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
            ):
                raise TargetStageError(
                    "URL targets must include an http or https hostname."
                )

            asset_value = parsed.hostname
            asset_type = "HOSTNAME"

        try:
            asset = self._normalizer.normalize(
                {
                    "value": asset_value,
                    "type": asset_type,
                    "source": "configured_target",
                }
            )
        except NormalizationError as exc:
            raise TargetStageError(
                f"Target normalization failed: {exc}"
            ) from exc

        result = TargetStageResult(
            asset=asset,
            metadata={
                "source": "configured_target",
                "network_activity": False,
                "target_type": target.type,
                "recon_asset_type": asset_type,
            },
        )

        context.set_state(
            TARGET_ASSET_STATE_KEY,
            asset,
        )

        return result
