"""Tests for the Hunt_Chain Project 2 discovery-provider registry."""

from __future__ import annotations

import pytest

from hunt_chain_recon.providers.discovery.base import DiscoveryProvider
from hunt_chain_recon.providers.discovery.certificate_transparency import (
    CertificateTransparencyProvider,
)
from hunt_chain_recon.providers.discovery.registry import (
    DiscoveryProviderError,
    DiscoveryProviderRegistry,
)


class DummyDiscoveryProvider(DiscoveryProvider):
    """Minimal valid provider used for registry tests."""

    name = "dummy-provider"
    version = "1.0.0"

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Return capabilities exposed by the dummy provider."""
        return ("test",)

    def discover(self, target: object):
        """Return no observations for the test provider."""
        raise NotImplementedError


def test_registry_contains_builtin_certificate_transparency_provider():
    """The V1 registry exposes the built-in CT provider."""
    registry = DiscoveryProviderRegistry()

    assert registry.available() == (
        "amass",
        "certificate_transparency",
        "subfinder",
    )


def test_registry_creates_certificate_transparency_provider():
    """The registry creates the configured CT provider."""
    registry = DiscoveryProviderRegistry()

    provider = registry.create("certificate_transparency")

    assert isinstance(provider, CertificateTransparencyProvider)
    assert isinstance(provider, DiscoveryProvider)


def test_registry_normalizes_provider_name():
    """Provider names are normalized before lookup."""
    registry = DiscoveryProviderRegistry()

    provider = registry.create(
        "  CERTIFICATE_TRANSPARENCY  "
    )

    assert isinstance(provider, CertificateTransparencyProvider)


def test_registry_rejects_unknown_provider():
    """An unknown provider name produces an explicit registry error."""
    registry = DiscoveryProviderRegistry()

    with pytest.raises(
        DiscoveryProviderError,
        match="Unknown discovery provider",
    ):
        registry.create("unknown_provider")


def test_registry_rejects_empty_provider_name():
    """An empty provider name is rejected."""
    registry = DiscoveryProviderRegistry()

    with pytest.raises(
        DiscoveryProviderError,
        match="must not be empty",
    ):
        registry.create("   ")


def test_registry_rejects_non_string_provider_name():
    """Provider names must be strings."""
    registry = DiscoveryProviderRegistry()

    with pytest.raises(
        DiscoveryProviderError,
        match="must be a string",
    ):
        registry.create(None)


def test_registry_rejects_duplicate_provider():
    """A provider name cannot be registered twice."""
    registry = DiscoveryProviderRegistry()

    with pytest.raises(
        ValueError,
        match="already registered",
    ):
        registry.register(
            "certificate_transparency",
            CertificateTransparencyProvider,
        )


def test_registry_rejects_non_callable_factory():
    """Provider factories must be callable."""
    registry = DiscoveryProviderRegistry()

    with pytest.raises(
        TypeError,
        match="factory must be callable",
    ):
        registry.register(
            "invalid",
            object(),
        )


def test_registry_rejects_invalid_factory_result():
    """A factory must return a DiscoveryProvider."""
    registry = DiscoveryProviderRegistry()

    registry.register(
        "invalid_provider",
        lambda: object(),
    )

    with pytest.raises(
        DiscoveryProviderError,
        match="returned an invalid discovery provider",
    ):
        registry.create("invalid_provider")


def test_registry_accepts_valid_custom_provider():
    """A valid custom provider can be registered and created."""
    registry = DiscoveryProviderRegistry()

    registry.register(
        "dummy",
        DummyDiscoveryProvider,
    )

    provider = registry.create("dummy")

    assert isinstance(provider, DummyDiscoveryProvider)
    assert "dummy" in registry.available()


def test_registry_available_is_deterministically_sorted():
    """Registered provider names are returned in sorted order."""
    registry = DiscoveryProviderRegistry()

    registry.register(
        "zeta",
        DummyDiscoveryProvider,
    )
    registry.register(
        "alpha",
        DummyDiscoveryProvider,
    )

    assert registry.available() == (
        "alpha",
        "amass",
        "certificate_transparency",
        "subfinder",
        "zeta",
    )


def test_registry_factory_failure_becomes_registry_error():
    """Factory exceptions are converted into an explicit registry error."""
    registry = DiscoveryProviderRegistry()

    def failing_factory():
        raise RuntimeError("factory failed")

    registry.register(
        "failing",
        failing_factory,
    )

    with pytest.raises(
        DiscoveryProviderError,
        match="Failed to create discovery provider",
    ):
        registry.create("failing")
