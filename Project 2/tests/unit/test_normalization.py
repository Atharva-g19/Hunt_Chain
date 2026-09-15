"""Tests for Hunt_Chain Project 2 asset normalization."""

from __future__ import annotations

import pytest

from hunt_chain_recon.models.assets import Asset
from hunt_chain_recon.processing.normalization import (
    AssetNormalizer,
    NormalizationError,
)


@pytest.fixture
def normalizer() -> AssetNormalizer:
    """Return a fresh asset normalizer."""
    return AssetNormalizer()


def test_normalize_hostname_lowercases_value(
    normalizer: AssetNormalizer,
):
    """Hostname values are normalized to lowercase."""
    asset = normalizer.normalize(
        {
            "value": "WWW.Example.COM",
            "type": "HOSTNAME",
            "source": "test",
        }
    )

    assert isinstance(asset, Asset)
    assert asset.value == "WWW.Example.COM"
    assert asset.normalized_value == "www.example.com"


def test_normalize_hostname_removes_trailing_dot(
    normalizer: AssetNormalizer,
):
    """Trailing DNS dots are removed from hostname identity."""
    asset = normalizer.normalize(
        {
            "value": "www.example.com.",
            "type": "HOSTNAME",
            "source": "test",
        }
    )

    assert asset.normalized_value == "www.example.com"


def test_normalize_domain_lowercases_value(
    normalizer: AssetNormalizer,
):
    """Domain values are normalized to lowercase."""
    asset = normalizer.normalize(
        {
            "value": "Example.COM",
            "type": "DOMAIN",
            "source": "test",
        }
    )

    assert asset.normalized_value == "example.com"


def test_normalize_domain_removes_trailing_dot(
    normalizer: AssetNormalizer,
):
    """Trailing DNS dots are removed from domain identity."""
    asset = normalizer.normalize(
        {
            "value": "Example.COM.",
            "type": "DOMAIN",
            "source": "test",
        }
    )

    assert asset.normalized_value == "example.com"


def test_normalize_ipv4_address(
    normalizer: AssetNormalizer,
):
    """Standard IPv4 addresses are represented canonically."""
    asset = normalizer.normalize(
        {
            "value": "192.168.1.1",
            "type": "IP_ADDRESS",
            "source": "test",
        }
    )

    assert asset.normalized_value == "192.168.1.1"


def test_normalize_ipv4_with_leading_zeroes_is_rejected(
    normalizer: AssetNormalizer,
):
    """IPv4 addresses with padded octets are rejected as invalid input."""
    with pytest.raises(
        NormalizationError,
        match="Invalid IP address",
    ):
        normalizer.normalize(
            {
                "value": "192.168.001.001",
                "type": "IP_ADDRESS",
                "source": "test",
            }
        )


def test_normalize_ipv6_address(
    normalizer: AssetNormalizer,
):
    """IPv6 addresses are represented canonically."""
    asset = normalizer.normalize(
        {
            "value": "2001:0DB8:0000:0000:0000:0000:0000:0001",
            "type": "IP_ADDRESS",
            "source": "test",
        }
    )

    assert asset.normalized_value == "2001:db8::1"


def test_normalize_invalid_ip_address(
    normalizer: AssetNormalizer,
):
    """Invalid IP addresses are rejected."""
    with pytest.raises(
        NormalizationError,
        match="Invalid IP address",
    ):
        normalizer.normalize(
            {
                "value": "999.999.999.999",
                "type": "IP_ADDRESS",
                "source": "test",
            }
        )


def test_normalize_rejects_empty_value(
    normalizer: AssetNormalizer,
):
    """Empty discovery values are rejected."""
    with pytest.raises(
        NormalizationError,
        match="must not be empty",
    ):
        normalizer.normalize(
            {
                "value": "   ",
                "type": "HOSTNAME",
                "source": "test",
            }
        )


def test_normalize_rejects_non_string_value(
    normalizer: AssetNormalizer,
):
    """Non-string discovery values are rejected."""
    with pytest.raises(
        NormalizationError,
        match="value must be a string",
    ):
        normalizer.normalize(
            {
                "value": 123,
                "type": "HOSTNAME",
                "source": "test",
            }
        )


def test_normalize_rejects_non_string_type(
    normalizer: AssetNormalizer,
):
    """Non-string asset types are rejected."""
    with pytest.raises(
        NormalizationError,
        match="type must be a string",
    ):
        normalizer.normalize(
            {
                "value": "example.com",
                "type": None,
                "source": "test",
            }
        )


def test_normalize_rejects_unsupported_asset_type(
    normalizer: AssetNormalizer,
):
    """Unsupported asset types are rejected."""
    with pytest.raises(
        NormalizationError,
        match="Unsupported asset type",
    ):
        normalizer.normalize(
            {
                "value": "https://example.com",
                "type": "URL",
                "source": "test",
            }
        )


def test_normalize_string_source(
    normalizer: AssetNormalizer,
):
    """A string source is converted into a source list."""
    asset = normalizer.normalize(
        {
            "value": "example.com",
            "type": "DOMAIN",
            "source": "certificate_transparency",
        }
    )

    assert asset.sources == [
        "certificate_transparency",
    ]


def test_normalize_source_list(
    normalizer: AssetNormalizer,
):
    """A source list is preserved without duplicates."""
    asset = normalizer.normalize(
        {
            "value": "example.com",
            "type": "DOMAIN",
            "source": [
                "ct",
                "dns",
                "ct",
            ],
        }
    )

    assert asset.sources == [
        "ct",
        "dns",
    ]


def test_normalize_empty_source(
    normalizer: AssetNormalizer,
):
    """Missing or empty source information produces an empty list."""
    asset = normalizer.normalize(
        {
            "value": "example.com",
            "type": "DOMAIN",
            "source": "   ",
        }
    )

    assert asset.sources == []


def test_normalize_invalid_source_items_are_ignored(
    normalizer: AssetNormalizer,
):
    """Non-string source entries are ignored."""
    asset = normalizer.normalize(
        {
            "value": "example.com",
            "type": "DOMAIN",
            "source": [
                "ct",
                123,
                None,
                "dns",
            ],
        }
    )

    assert asset.sources == [
        "ct",
        "dns",
    ]


def test_normalize_many(
    normalizer: AssetNormalizer,
):
    """Multiple observations can be normalized together."""
    observations = [
        {
            "value": "WWW.Example.COM",
            "type": "HOSTNAME",
            "source": "ct",
        },
        {
            "value": "192.168.1.10",
            "type": "IP_ADDRESS",
            "source": "dns",
        },
    ]

    assets = normalizer.normalize_many(
        observations
    )

    assert len(assets) == 2
    assert assets[0].normalized_value == "www.example.com"
    assert assets[1].normalized_value == "192.168.1.10"


def test_normalize_preserves_original_value(
    normalizer: AssetNormalizer,
):
    """Normalization does not overwrite the original observed value."""
    asset = normalizer.normalize(
        {
            "value": "WWW.Example.COM.",
            "type": "HOSTNAME",
            "source": "test",
        }
    )

    assert asset.value == "WWW.Example.COM."
    assert asset.normalized_value == "www.example.com"