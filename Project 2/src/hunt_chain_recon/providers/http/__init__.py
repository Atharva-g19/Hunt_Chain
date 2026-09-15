"""HTTP provider contracts for Hunt_Chain Project 2."""

from __future__ import annotations

from abc import abstractmethod

from hunt_chain_recon.models.endpoints import Endpoint
from hunt_chain_recon.models.http import HTTPObservation
from hunt_chain_recon.providers.base import Provider, ProviderResult


class HTTPProvider(Provider[HTTPObservation]):
    """Abstract contract for HTTP and HTTPS probing providers.

    HTTP providers collect application-layer response observations.

    They do not perform:
    - vulnerability scanning,
    - exploitation,
    - authentication attacks,
    - technology conclusions,
    - response similarity interpretation.
    """

    @property
    @abstractmethod
    def capabilities(self) -> tuple[str, ...]:
        """Return HTTP capabilities supported by the provider."""
        raise NotImplementedError

    @abstractmethod
    def probe(
        self,
        endpoints: list[Endpoint],
    ) -> ProviderResult[HTTPObservation]:
        """Probe the supplied endpoints and return observations."""
        raise NotImplementedError

    def execute(
        self,
        context: list[Endpoint],
    ) -> ProviderResult[HTTPObservation]:
        """Execute HTTP probing using an endpoint list as context."""
        return self.probe(context)