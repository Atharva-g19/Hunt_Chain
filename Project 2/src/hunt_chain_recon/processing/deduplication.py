"""Asset deduplication for Hunt_Chain Project 2.

This module removes duplicate canonical Asset observations while
preserving provenance.

Deduplication occurs after normalization.

V1 identity is based on:

    asset.type + asset.normalized_value

Therefore, two observations with the same canonical value but different
asset types remain distinct assets.

For example:

    example.com / DOMAIN
    example.com / HOSTNAME

are not considered duplicates.

The deduplicator performs no:
- network activity,
- DNS resolution,
- HTTP probing,
- technology fingerprinting,
- vulnerability assessment,
- exploitation.

It only consolidates equivalent observations.
"""

from __future__ import annotations

from collections.abc import Iterable

from hunt_chain_recon.models.assets import Asset


class DeduplicationError(Exception):
    """Raised when asset deduplication receives invalid input."""


class AssetDeduplicator:
    """Deduplicate canonical Project 2 Asset objects.

    Duplicate assets are merged while their discovery provenance is
    combined.

    The first occurrence determines the retained Asset's original
    ``value`` and position in the output.
    """

    def deduplicate(
        self,
        assets: Iterable[Asset],
    ) -> list[Asset]:
        """Deduplicate assets while preserving deterministic order.

        Args:
            assets: Iterable containing normalized Asset objects.

        Returns:
            A list containing one Asset for each unique
            ``type + normalized_value`` identity.

        Raises:
            DeduplicationError: If an input item is not an Asset or if a
                required canonical identity is unavailable.
        """
        unique_assets: dict[tuple[str, str], Asset] = {}

        for asset in assets:
            if not isinstance(asset, Asset):
                raise DeduplicationError(
                    "Deduplication input must contain Asset objects."
                )

            identity = self._identity(asset)

            existing = unique_assets.get(identity)

            if existing is None:
                unique_assets[identity] = asset
                continue

            unique_assets[identity] = self._merge(
                existing,
                asset,
            )

        return list(unique_assets.values())

    @staticmethod
    def _identity(
        asset: Asset,
    ) -> tuple[str, str]:
        """Return the stable V1 identity for an Asset."""
        asset_type = asset.type

        normalized_value = asset.normalized_value

        if not isinstance(asset_type, str) or not asset_type.strip():
            raise DeduplicationError(
                "Asset type is required for deduplication."
            )

        if not isinstance(normalized_value, str):
            raise DeduplicationError(
                "Asset normalized_value is required for deduplication."
            )

        normalized_type = asset_type.strip().upper()
        normalized_identity = normalized_value.strip().lower()

        if not normalized_identity:
            raise DeduplicationError(
                "Asset normalized_value must not be empty."
            )

        return (
            normalized_type,
            normalized_identity,
        )

    @staticmethod
    def _merge(
        existing: Asset,
        duplicate: Asset,
    ) -> Asset:
        """Merge provenance from a duplicate into the retained Asset.

        The retained Asset keeps:
        - its original UUID,
        - its original observed value,
        - its canonical identity,
        - its position in the output.

        Only provenance is merged.
        """
        merged_sources = list(existing.sources)

        for source in duplicate.sources:
            if source not in merged_sources:
                merged_sources.append(source)

        return existing.model_copy(
            update={
                "sources": merged_sources,
            }
        )