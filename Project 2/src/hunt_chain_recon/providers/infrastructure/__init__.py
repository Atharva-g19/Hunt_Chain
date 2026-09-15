"""Infrastructure provider contracts for Hunt_Chain Project 2."""

from __future__ import annotations

from abc import abstractmethod
from typing import Any

from hunt_chain_recon.providers.base import Provider, ProviderResult


class InfrastructureProvider(Provider[Any]):
    """Abstract contract for infrastructure intelligence providers.

    Infrastructure providers collect lightweight infrastructure metadata
    such as shared-IP or provider-related observations.

    V1 intentionally avoids full cloud enumeration, aggressive network
    scanning, or intrusive infrastructure discovery.
    """

    @property
    @abstractmethod
    def capabilities(self) -> tuple[str, ...]:
        """Return infrastructure capabilities supported by the provider."""
        raise NotImplementedError

    @abstractmethod
    def categorize(
        self,
        ip_addresses: list[str],
    ) -> ProviderResult[Any]:
        """Collect infrastructure observations for IP addresses."""
        raise NotImplementedError

    def execute(
        self,
        context: list[str],
    ) -> ProviderResult[Any]:
        """Execute infrastructure categorization."""
        return self.categorize(context)