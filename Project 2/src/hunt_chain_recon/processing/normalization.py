"""Asset normalization for Hunt_Chain Project 2.

This module converts raw discovery observations into canonical Project 2
Asset models.

Normalization is deliberately separate from discovery.

It does not:
- perform network requests,
- resolve DNS,
- probe HTTP/HTTPS,
- determine technologies,
- determine vulnerabilities,
- confirm DNS takeover,
- deduplicate assets across unrelated semantic identities.

Its responsibility is to establish a consistent representation of an
observation before later processing stages operate on it.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from hunt_chain_recon.models.assets import Asset


class NormalizationError(Exception):
    """Raised when a discovery observation cannot be normalized."""


class AssetNormalizer:
    """Normalize raw discovery observations into Asset objects.

    V1 supports the Project 2 asset types:

    - DOMAIN
    - HOSTNAME
    - IP_ADDRESS

    The original observed value is preserved in ``Asset.value`` while
    ``normalized_value`` contains the canonical representation.
    """

    SUPPORTED_TYPES = {
        "DOMAIN",
        "HOSTNAME",
        "IP_ADDRESS",
    }

    def normalize(
        self,
        observation: dict[str, Any],
    ) -> Asset:
        """Normalize one raw discovery observation.

        Args:
            observation: Raw provider observation containing at minimum
                ``value`` and ``type``.

        Returns:
            A canonical Project 2 Asset.

        Raises:
            NormalizationError: If the observation is malformed or its
                asset type is unsupported.
        """
        if not isinstance(observation, dict):
            raise NormalizationError(
                "Discovery observation must be a dictionary."
            )

        raw_value = observation.get("value")
        raw_type = observation.get("type")

        if not isinstance(raw_value, str):
            raise NormalizationError(
                "Discovery observation value must be a string."
            )

        if not isinstance(raw_type, str):
            raise NormalizationError(
                "Discovery observation type must be a string."
            )

        value = raw_value.strip()

        if not value:
            raise NormalizationError(
                "Discovery observation value must not be empty."
            )

        asset_type = raw_type.strip().upper()

        if asset_type not in self.SUPPORTED_TYPES:
            raise NormalizationError(
                f"Unsupported asset type: {asset_type}"
            )

        normalized_value = self._normalize_value(
            value,
            asset_type,
        )

        sources = self._normalize_sources(
            observation.get("source")
        )

        return Asset(
            value=value,
            type=asset_type,
            normalized_value=normalized_value,
            sources=sources,
        )

    def normalize_many(
        self,
        observations: list[dict[str, Any]],
    ) -> list[Asset]:
        """Normalize multiple observations in input order.

        This method intentionally does not deduplicate the results.
        Deduplication is a separate processing responsibility.
        """
        return [
            self.normalize(observation)
            for observation in observations
        ]

    @staticmethod
    def _normalize_value(
        value: str,
        asset_type: str,
    ) -> str:
        """Return the canonical value for a supported asset type."""
        if asset_type in {"DOMAIN", "HOSTNAME"}:
            return value.lower().rstrip(".")

        if asset_type == "IP_ADDRESS":
            try:
                return str(
                    ipaddress.ip_address(value)
                )
            except ValueError as exc:
                raise NormalizationError(
                    f"Invalid IP address: {value}"
                ) from exc

        raise NormalizationError(
            f"Unsupported asset type: {asset_type}"
        )

    @staticmethod
    def _normalize_sources(
        source: Any,
    ) -> list[str]:
        """Normalize discovery-source provenance."""
        if source is None:
            return []

        if isinstance(source, str):
            normalized = source.strip()

            return [normalized] if normalized else []

        if isinstance(source, (list, tuple, set)):
            sources: list[str] = []

            for item in source:
                if not isinstance(item, str):
                    continue

                normalized = item.strip()

                if normalized and normalized not in sources:
                    sources.append(normalized)

            return sources

        return []