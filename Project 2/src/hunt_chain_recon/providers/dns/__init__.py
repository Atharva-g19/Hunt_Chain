"""DNS providers for Hunt_Chain Project 2.

This package exposes the DNS provider contract and built-in DNS
resolution provider.

Provider responsibilities are limited to collecting DNS observations.

DNS analysis remains separate and is responsible for:
- wildcard DNS detection,
- dangling CNAME indicators,
- DNS correlation,
- attack-surface interpretation.
"""

from __future__ import annotations

from hunt_chain_recon.providers.dns.base import DNSProvider
from hunt_chain_recon.providers.dns.resolver import (
    DNSResolverProvider,
)

__all__ = [
    "DNSProvider",
    "DNSResolverProvider",
]