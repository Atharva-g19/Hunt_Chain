"""Deterministic discovery provider fixtures for Hunt_Chain Project 2.

These providers are used only by tests.

They never perform network activity and return fixed observations so
that pipeline tests remain deterministic and independent of external
discovery services.
"""

from __future__ import annotations

from typing import Any

from hunt_chain_recon.providers.discovery.base import DiscoveryProvider
from hunt_chain_recon.providers.base import ProviderResult


class FixtureDiscoveryProvider(DiscoveryProvider):
    """Discovery provider that returns deterministic test observations."""

    def __init__(
        self,
        observations: list[dict[str, Any]] | None = None,
    ) -> None:
        self._observations = observations or []

    @property
    def name(self) -> str:
        """Return the stable provider name."""
        return "fixture-discovery"

    @property
    def version(self) -> str:
        """Return the fixture provider version."""
        return "1.0.0"

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Return the capabilities represented by this fixture."""
        return (
            "passive_discovery",
            "hostname_discovery",
        )

    def discover(
        self,
        target: Any,
    ) -> ProviderResult[Any]:
        """Return the configured observations without network activity."""
        return ProviderResult(
            status="SUCCESS",
            observations=[
                dict(observation)
                for observation in self._observations
            ],
            errors=[],
            provider=self.name,
            metadata={
                "target": target,
                "fixture": True,
            },
        )