"""Discovery provider registry for Hunt_Chain Project 2.

The registry maps configured discovery-provider names to their concrete
implementations.

It keeps provider selection separate from the pipeline engine so the
pipeline does not need provider-specific conditional logic.

The registry performs no network activity.
"""

from __future__ import annotations

from collections.abc import Callable

from hunt_chain_recon.providers.discovery.base import DiscoveryProvider
from hunt_chain_recon.providers.discovery.certificate_transparency import (
    CertificateTransparencyProvider,
)
from hunt_chain_recon.providers.discovery.cli import AmassProvider, SubfinderProvider


class DiscoveryProviderError(Exception):
    """Raised when a discovery provider cannot be resolved."""


DiscoveryProviderFactory = Callable[[], DiscoveryProvider]


class DiscoveryProviderRegistry:
    """Registry of available Project 2 discovery providers.

    Providers are registered by a stable configuration name.

    V1 initially exposes:

        certificate_transparency
    """

    def __init__(self) -> None:
        """Initialize the registry with built-in V1 providers."""
        self._factories: dict[str, DiscoveryProviderFactory] = {
            "certificate_transparency": CertificateTransparencyProvider,
            "subfinder": SubfinderProvider,
            "amass": AmassProvider,
        }

    def register(
        self,
        name: str,
        factory: DiscoveryProviderFactory,
    ) -> None:
        """Register a discovery-provider factory.

        Args:
            name: Stable provider configuration name.
            factory: Callable that creates the provider instance.

        Raises:
            ValueError: If the name is empty or already registered.
            TypeError: If the factory is not callable.
        """
        normalized_name = self._normalize_name(name)

        if not callable(factory):
            raise TypeError(
                "Discovery provider factory must be callable."
            )

        if normalized_name in self._factories:
            raise ValueError(
                f"Discovery provider '{normalized_name}' "
                "is already registered."
            )

        self._factories[normalized_name] = factory

    def create(self, name: str) -> DiscoveryProvider:
        """Create a provider from its registered configuration name.

        Args:
            name: Registered provider configuration name.

        Returns:
            A new discovery-provider instance.

        Raises:
            DiscoveryProviderError: If the provider is unavailable or the
                factory does not return a valid DiscoveryProvider.
        """
        try:
            normalized_name = self._normalize_name(name)
        except (TypeError, ValueError) as exc:
            raise DiscoveryProviderError(str(exc)) from exc

        factory = self._factories.get(normalized_name)

        if factory is None:
            raise DiscoveryProviderError(
                f"Unknown discovery provider: {normalized_name}"
            )

        try:
            provider = factory()
        except Exception as exc:
            raise DiscoveryProviderError(
                f"Failed to create discovery provider "
                f"'{normalized_name}': {exc}"
            ) from exc

        if not hasattr(provider, "discover") or not callable(
            provider.discover
        ):
            raise DiscoveryProviderError(
                f"Provider factory '{normalized_name}' returned an invalid "
                "discovery provider."
            )

        if not hasattr(provider, "capabilities"):
            raise DiscoveryProviderError(
                f"Provider factory '{normalized_name}' returned an invalid "
                "discovery provider."
            )

        return provider

    def available(self) -> tuple[str, ...]:
        """Return registered provider names in deterministic order."""
        return tuple(sorted(self._factories))

    @staticmethod
    def _normalize_name(name: str) -> str:
        """Normalize and validate a provider configuration name.

        Args:
            name: Provider name supplied by configuration or registration.

        Returns:
            Lowercase provider name without surrounding whitespace.

        Raises:
            TypeError: If the supplied name is not a string.
            ValueError: If the normalized name is empty.
        """
        if not isinstance(name, str):
            raise TypeError(
                "Discovery provider name must be a string."
            )

        normalized_name = name.strip().lower()

        if not normalized_name:
            raise ValueError(
                "Discovery provider name must not be empty."
            )

        return normalized_name
