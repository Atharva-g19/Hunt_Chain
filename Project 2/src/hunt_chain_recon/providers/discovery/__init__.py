"""Discovery providers for Hunt_Chain Project 2.

This package exposes the discovery-provider contract and the built-in
discovery providers.

Provider implementations collect observations only. Processing,
normalization, deduplication, and correlation remain separate concerns.
"""

from hunt_chain_recon.providers.discovery.base import DiscoveryProvider
from hunt_chain_recon.providers.discovery.certificate_transparency import (
    CertificateTransparencyProvider,
)

__all__ = [
    "CertificateTransparencyProvider",
    "DiscoveryProvider",
]