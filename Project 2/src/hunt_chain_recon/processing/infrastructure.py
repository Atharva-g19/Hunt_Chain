"""Infrastructure intelligence processing for Hunt_Chain Project 2.

This module performs deterministic analysis of already-collected assets
and DNS observations.

V1 currently provides shared-IP awareness.

It does not:
- perform DNS queries,
- perform network requests,
- perform port scanning,
- enumerate cloud infrastructure,
- confirm vulnerabilities,
- make security conclusions.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunt_chain_recon.models.assets import Asset, AssetType
from hunt_chain_recon.models.dns import (
    DNSObservation,
    DNSResolutionStatus,
)
from hunt_chain_recon.models.infrastructure import (
    InfrastructureConfidence,
    InfrastructureObservation,
    InfrastructureObservationType,
)


class InfrastructureAnalysisError(ValueError):
    """Raised when infrastructure analysis receives invalid input."""


@dataclass
class InfrastructureAnalysisResult:
    """Result produced by infrastructure analysis."""

    observations: list[InfrastructureObservation] = field(
        default_factory=list
    )


class InfrastructureAnalyzer:
    """Analyze reconnaissance data for infrastructure intelligence."""

    def analyze(
        self,
        *,
        assets: list[Asset],
        dns_observations: list[DNSObservation],
    ) -> InfrastructureAnalysisResult:
        """Identify shared-IP relationships from DNS observations.

        Only canonical HOSTNAME assets and successful DNS observations
        containing A or AAAA records are considered.

        A shared-IP observation requires at least two distinct hostnames
        associated with the same IP address.
        """
        self._validate_assets(assets)
        self._validate_dns_observations(dns_observations)

        hostname_assets = self._build_hostname_index(assets)

        ip_to_hostnames: dict[str, set[str]] = {}

        for observation in dns_observations:
            if observation.status != DNSResolutionStatus.RESOLVED:
                continue

            hostname = self._normalize_hostname(
                observation.hostname
            )

            if hostname not in hostname_assets:
                continue

            for record in observation.address_records():
                ip_address = record.value.strip()

                if not ip_address:
                    continue

                ip_to_hostnames.setdefault(
                    ip_address,
                    set(),
                ).add(hostname)

        observations: list[InfrastructureObservation] = []

        for ip_address in sorted(ip_to_hostnames):
            hostnames = sorted(
                ip_to_hostnames[ip_address]
            )

            if len(hostnames) < 2:
                continue

            observations.append(
                InfrastructureObservation(
                    observation_type=(
                        InfrastructureObservationType.SHARED_IP
                    ),
                    ip_address=ip_address,
                    value=f"{len(hostnames)} hostnames",
                    evidence=(
                        f"{len(hostnames)} canonical hostnames "
                        f"resolve to {ip_address}."
                    ),
                    confidence=InfrastructureConfidence.HIGH,
                    metadata={
                        "hostname_count": str(len(hostnames)),
                        "hostnames": ",".join(hostnames),
                    },
                )
            )

        return InfrastructureAnalysisResult(
            observations=observations
        )

    @staticmethod
    def _validate_assets(
        assets: list[Asset],
    ) -> None:
        if not isinstance(assets, list):
            raise InfrastructureAnalysisError(
                "assets must be a list."
            )

        for asset in assets:
            if not isinstance(asset, Asset):
                raise InfrastructureAnalysisError(
                    "assets contains a non-Asset value."
                )

    @staticmethod
    def _validate_dns_observations(
        observations: list[DNSObservation],
    ) -> None:
        if not isinstance(observations, list):
            raise InfrastructureAnalysisError(
                "dns_observations must be a list."
            )

        for observation in observations:
            if not isinstance(
                observation,
                DNSObservation,
            ):
                raise InfrastructureAnalysisError(
                    "dns_observations contains a non-DNSObservation value."
                )

    @staticmethod
    def _build_hostname_index(
        assets: list[Asset],
    ) -> dict[str, Asset]:
        result: dict[str, Asset] = {}

        for asset in assets:
            if asset.type != AssetType.HOSTNAME:
                continue

            normalized = (
                asset.normalized_value.strip()
                .lower()
                .rstrip(".")
            )

            if not normalized:
                continue

            result.setdefault(
                normalized,
                asset,
            )

        return result

    @staticmethod
    def _normalize_hostname(
        value: str,
    ) -> str:
        normalized = (
            value.strip()
            .lower()
            .rstrip(".")
        )

        if not normalized:
            raise InfrastructureAnalysisError(
                "DNS hostname must not be empty."
            )

        return normalized


__all__ = [
    "InfrastructureAnalysisError",
    "InfrastructureAnalysisResult",
    "InfrastructureAnalyzer",
]