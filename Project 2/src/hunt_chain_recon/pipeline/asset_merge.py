"""Canonical asset merge stage for Hunt_Chain Project 2.

This stage combines the explicitly configured target asset with assets
discovered by Project 2 discovery providers.

Pipeline flow:

    Configured Target Asset
             +
    Discovered Canonical Assets
             |
             v
    Canonical Unique Asset Set

The stage performs no network activity.

It is responsible for:
- enforcing authorization,
- enforcing execution policy,
- retrieving the target asset,
- retrieving discovery-derived assets,
- deduplicating the combined asset set,
- preserving provenance,
- storing the final canonical asset list.

It does not:
- perform DNS resolution,
- perform HTTP requests,
- perform port scanning,
- fingerprint technologies,
- perform vulnerability testing,
- perform exploitation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunt_chain_recon.models.assets import Asset
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.policy.execution import ExecutionActivity
from hunt_chain_recon.processing.deduplication import (
    AssetDeduplicator,
    DeduplicationError,
)


ASSETS_STATE_KEY = "assets"
TARGET_ASSET_STATE_KEY = "target_asset"


class AssetMergeStageError(RuntimeError):
    """Raised when canonical asset merging cannot complete."""


@dataclass(frozen=True)
class AssetMergeStageResult:
    """Result produced by the canonical asset merge stage."""

    assets: list[Asset]
    target_assets: int
    discovered_assets: int
    assets_before_deduplication: int
    assets_after_deduplication: int
    metadata: dict[str, Any] = field(
        default_factory=dict
    )


class AssetMergeStage:
    """Merge the configured target with discovered canonical assets."""

    name = "asset_merge"

    activity = ExecutionActivity.PASSIVE_DISCOVERY

    def __init__(
        self,
        deduplicator: AssetDeduplicator | None = None,
    ) -> None:
        self._deduplicator = (
            deduplicator or AssetDeduplicator()
        )

    @property
    def deduplicator(self) -> AssetDeduplicator:
        """Return the configured asset deduplicator."""
        return self._deduplicator

    def execute(
        self,
        context: PipelineContext,
    ) -> AssetMergeStageResult:
        """Merge target and discovery-derived canonical assets."""

        context.require_authorized()

        context.execution_policy.require_allowed(
            self.activity
        )

        target_asset = self._get_target_asset(
            context
        )

        discovered_assets = self._get_discovered_assets(
            context
        )

        combined_assets = [
            target_asset,
            *discovered_assets,
        ]

        try:
            unique_assets = self._deduplicator.deduplicate(
                combined_assets
            )
        except DeduplicationError as exc:
            raise AssetMergeStageError(
                f"Asset merge failed: {exc}"
            ) from exc

        result = AssetMergeStageResult(
            assets=unique_assets,
            target_assets=1,
            discovered_assets=len(
                discovered_assets
            ),
            assets_before_deduplication=len(
                combined_assets
            ),
            assets_after_deduplication=len(
                unique_assets
            ),
            metadata={
                "network_activity": False,
                "target_always_included": True,
            },
        )

        context.set_state(
            ASSETS_STATE_KEY,
            unique_assets,
        )

        return result

    @staticmethod
    def _get_target_asset(
        context: PipelineContext,
    ) -> Asset:
        """Retrieve the explicitly configured target asset."""

        value = context.get_state(
            TARGET_ASSET_STATE_KEY
        )

        if not isinstance(
            value,
            Asset,
        ):
            raise AssetMergeStageError(
                "Pipeline state does not contain a valid target asset."
            )

        return value

    @staticmethod
    def _get_discovered_assets(
        context: PipelineContext,
    ) -> list[Asset]:
        """Retrieve canonical assets produced by asset processing."""

        value = context.get_state(
            ASSETS_STATE_KEY
        )

        if value is None:
            return []

        if not isinstance(
            value,
            list,
        ):
            raise AssetMergeStageError(
                "Pipeline state 'assets' must contain a list."
            )

        for asset in value:
            if not isinstance(
                asset,
                Asset,
            ):
                raise AssetMergeStageError(
                    "Pipeline state 'assets' contains an invalid Asset."
                )

        return list(
            value
        )