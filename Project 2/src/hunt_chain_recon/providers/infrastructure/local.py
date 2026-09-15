"""Local infrastructure intelligence provider for Hunt_Chain Project 2.

This provider converts explicitly supplied infrastructure metadata into
normalized InfrastructureObservation objects.

It performs no network activity.

V1 intentionally uses supplied metadata rather than querying external
provider, ASN, CDN, or cloud databases.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from hunt_chain_recon.models.infrastructure import (
    InfrastructureConfidence,
    InfrastructureObservation,
    InfrastructureObservationType,
)
from hunt_chain_recon.providers.base import (
    ProviderResult,
    ProviderStatus,
)
from hunt_chain_recon.providers.infrastructure import (
    InfrastructureProvider,
)


class LocalInfrastructureProvider(InfrastructureProvider):
    """Convert supplied infrastructure metadata into observations."""

    name = "local"
    version = "1.0"

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Return capabilities supported by this provider."""
        return (
            "shared_ip",
            "provider_identification",
        )

    def categorize(
        self,
        ip_addresses: list[str],
        *,
        metadata: Mapping[str, Mapping[str, Any]] | None = None,
    ) -> ProviderResult[InfrastructureObservation]:
        """Categorize explicitly supplied infrastructure metadata."""
        if not isinstance(ip_addresses, list):
            raise TypeError(
                "ip_addresses must be a list."
            )

        metadata = metadata or {}

        requested_ips = {
            ip.strip()
            for ip in ip_addresses
            if isinstance(ip, str) and ip.strip()
        }

        observations: list[InfrastructureObservation] = []

        for ip_address in sorted(requested_ips):
            ip_metadata = metadata.get(ip_address)

            if not isinstance(ip_metadata, Mapping):
                continue

            provider = self._clean_value(
                ip_metadata.get("provider")
            )

            if provider is not None:
                observations.append(
                    InfrastructureObservation(
                        observation_type=(
                            InfrastructureObservationType.PROVIDER
                        ),
                        ip_address=ip_address,
                        value=provider,
                        evidence=(
                            f"Provider metadata identifies "
                            f"{ip_address} as associated with {provider}."
                        ),
                        confidence=(
                            InfrastructureConfidence.MEDIUM
                        ),
                    )
                )

            cdn = self._clean_value(
                ip_metadata.get("cdn")
            )

            if cdn is not None:
                observations.append(
                    InfrastructureObservation(
                        observation_type=(
                            InfrastructureObservationType.CDN
                        ),
                        ip_address=ip_address,
                        value=cdn,
                        evidence=(
                            f"Provider metadata identifies "
                            f"{ip_address} as associated with CDN {cdn}."
                        ),
                        confidence=(
                            InfrastructureConfidence.MEDIUM
                        ),
                    )
                )

            cloud_platform = self._clean_value(
                ip_metadata.get("cloud_platform")
            )

            if cloud_platform is not None:
                observations.append(
                    InfrastructureObservation(
                        observation_type=(
                            InfrastructureObservationType.CLOUD_PLATFORM
                        ),
                        ip_address=ip_address,
                        value=cloud_platform,
                        evidence=(
                            f"Provider metadata identifies "
                            f"{ip_address} as associated with "
                            f"cloud platform {cloud_platform}."
                        ),
                        confidence=(
                            InfrastructureConfidence.MEDIUM
                        ),
                    )
                )

        return ProviderResult(
            status=ProviderStatus.SUCCESS,
            observations=observations,
            provider=self.name,
            metadata={
                "version": self.version,
                "ip_addresses_requested": len(requested_ips),
                "observations_produced": len(observations),
            },
        )

    @staticmethod
    def _clean_value(
        value: Any,
    ) -> str | None:
        """Return a normalized textual metadata value."""
        if not isinstance(value, str):
            return None

        normalized = value.strip()

        return normalized if normalized else None

    def execute(
        self,
        context: Any,
    ) -> ProviderResult[InfrastructureObservation]:
        """Execute using a structured local-provider context."""
        if not isinstance(context, Mapping):
            raise TypeError(
                "Local infrastructure provider context must be a mapping."
            )

        ip_addresses = context.get("ip_addresses", [])
        metadata = context.get("metadata", {})

        return self.categorize(
            ip_addresses,
            metadata=metadata,
        )


__all__ = [
    "LocalInfrastructureProvider",
]