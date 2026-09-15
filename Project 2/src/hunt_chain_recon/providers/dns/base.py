"""Base DNS-provider contract for Hunt_Chain Project 2.

DNS providers collect DNS observations for authorized targets.

Providers are responsible for observation collection only.

They must not:
- perform vulnerability testing,
- confirm DNS takeover,
- declare a CNAME takeover,
- perform exploitation,
- silently discard unresolved hosts,
- perform technology fingerprinting,
- perform HTTP probing,
- make authorization decisions.

DNS analysis, wildcard detection, dangling-CNAME analysis, normalization,
and correlation are handled by later Project 2 processing stages.

V1 DNS providers return:

    ProviderResult[DNSObservation]
"""

from __future__ import annotations

from abc import abstractmethod
from collections.abc import Sequence
from typing import Any

from hunt_chain_recon.models.dns import DNSObservation
from hunt_chain_recon.providers.base import Provider, ProviderResult


class DNSProvider(Provider[DNSObservation]):
    """Abstract contract for Project 2 DNS providers."""

    @property
    @abstractmethod
    def capabilities(self) -> tuple[str, ...]:
        """Return capabilities supported by this DNS provider."""
        raise NotImplementedError

    @abstractmethod
    def resolve(
        self,
        hostnames: Sequence[str],
    ) -> ProviderResult[DNSObservation]:
        """Resolve hostnames and return DNS observations."""
        raise NotImplementedError

    def execute(
        self,
        context: Any,
    ) -> ProviderResult[DNSObservation]:
        """Execute DNS resolution using a provider-specific context.

        A string is treated as a single hostname.

        A sequence is treated as a collection of hostnames.

        Concrete providers may override this method when they need a
        richer execution context.
        """
        if isinstance(context, str):
            hostnames = [context]
        elif isinstance(context, Sequence):
            hostnames = list(context)
        else:
            raise TypeError(
                "DNS provider execution context must contain "
                "a hostname or hostname sequence."
            )

        return self.resolve(hostnames)