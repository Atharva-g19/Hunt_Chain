"""Base discovery-provider contract for Hunt_Chain Project 2.

Discovery providers collect candidate assets from authorized discovery
sources.

Providers are responsible for observation collection only.

They must not:
- perform vulnerability testing,
- perform exploitation,
- make vulnerability conclusions,
- silently normalize or deduplicate observations,
- bypass the Project 2 authorization boundary.

Normalization, deduplication, and correlation are handled by later
processing stages.
"""

from __future__ import annotations

from abc import abstractmethod
from typing import Any

from hunt_chain_recon.providers.base import Provider, ProviderResult


class DiscoveryProvider(Provider[Any]):
    """Abstract contract for asset-discovery providers."""

    @property
    @abstractmethod
    def capabilities(self) -> tuple[str, ...]:
        """Return discovery capabilities supported by the provider."""
        raise NotImplementedError

    @abstractmethod
    def discover(self, target: Any) -> ProviderResult[Any]:
        """Discover candidate assets for the supplied target."""
        raise NotImplementedError

    def execute(self, context: Any) -> ProviderResult[Any]:
        """Execute discovery using the supplied provider context."""
        return self.discover(context)