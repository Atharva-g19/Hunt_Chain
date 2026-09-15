"""Tests for Hunt_Chain Project 2 asset deduplication."""

from __future__ import annotations

from uuid import UUID

import pytest

from hunt_chain_recon.models.assets import Asset
from hunt_chain_recon.processing.deduplication import (
    AssetDeduplicator,
    DeduplicationError,
)


@pytest.fixture
def deduplicator() -> AssetDeduplicator:
    """Return a fresh asset deduplicator."""
    return AssetDeduplicator()


def make_asset(
    value: str,
    asset_type: str,
    normalized_value: str,
    sources: list[str] | None = None,
) -> Asset:
    """Create a deterministic test Asset."""
    return Asset(
        value=value,
        type=asset_type,
        normalized_value=normalized_value,
        sources=sources or [],
    )


def test_deduplicate_identical_assets(
    deduplicator: AssetDeduplicator,
):
    """Identical canonical assets are reduced to one asset."""
    first = make_asset(
        "WWW.Example.COM",
        "HOSTNAME",
        "www.example.com",
        ["certificate_transparency"],
    )

    second = make_asset(
        "www.example.com.",
        "HOSTNAME",
        "www.example.com",
        ["dns"],
    )

    result = deduplicator.deduplicate(
        [first, second]
    )

    assert len(result) == 1
    assert result[0].normalized_value == "www.example.com"


def test_deduplicate_merges_provenance(
    deduplicator: AssetDeduplicator,
):
    """Duplicate assets combine their discovery sources."""
    first = make_asset(
        "www.example.com",
        "HOSTNAME",
        "www.example.com",
        ["certificate_transparency"],
    )

    second = make_asset(
        "www.example.com",
        "HOSTNAME",
        "www.example.com",
        ["dns"],
    )

    third = make_asset(
        "www.example.com",
        "HOSTNAME",
        "www.example.com",
        ["http"],
    )

    result = deduplicator.deduplicate(
        [first, second, third]
    )

    assert len(result) == 1
    assert result[0].sources == [
        "certificate_transparency",
        "dns",
        "http",
    ]


def test_deduplicate_does_not_duplicate_existing_sources(
    deduplicator: AssetDeduplicator,
):
    """Repeated provenance sources occur only once."""
    first = make_asset(
        "www.example.com",
        "HOSTNAME",
        "www.example.com",
        ["ct"],
    )

    second = make_asset(
        "www.example.com",
        "HOSTNAME",
        "www.example.com",
        ["ct", "dns"],
    )

    result = deduplicator.deduplicate(
        [first, second]
    )

    assert result[0].sources == [
        "ct",
        "dns",
    ]


def test_deduplicate_preserves_first_observation(
    deduplicator: AssetDeduplicator,
):
    """The first observation retains its original value."""
    first = make_asset(
        "WWW.Example.COM",
        "HOSTNAME",
        "www.example.com",
        ["ct"],
    )

    second = make_asset(
        "www.example.com.",
        "HOSTNAME",
        "www.example.com",
        ["dns"],
    )

    result = deduplicator.deduplicate(
        [first, second]
    )

    assert result[0].value == "WWW.Example.COM"


def test_deduplicate_preserves_first_asset_id(
    deduplicator: AssetDeduplicator,
):
    """Deduplication preserves the UUID of the first asset."""
    first = make_asset(
        "www.example.com",
        "HOSTNAME",
        "www.example.com",
        ["ct"],
    )

    second = make_asset(
        "www.example.com.",
        "HOSTNAME",
        "www.example.com",
        ["dns"],
    )

    first_id = first.id

    result = deduplicator.deduplicate(
        [first, second]
    )

    assert result[0].id == first_id
    assert isinstance(result[0].id, UUID)


def test_deduplicate_keeps_different_asset_types_separate(
    deduplicator: AssetDeduplicator,
):
    """Different asset types are separate identities."""
    domain = make_asset(
        "example.com",
        "DOMAIN",
        "example.com",
        ["manual"],
    )

    hostname = make_asset(
        "example.com",
        "HOSTNAME",
        "example.com",
        ["ct"],
    )

    result = deduplicator.deduplicate(
        [domain, hostname]
    )

    assert len(result) == 2
    assert result[0].type == "DOMAIN"
    assert result[1].type == "HOSTNAME"


def test_deduplicate_keeps_different_canonical_values_separate(
    deduplicator: AssetDeduplicator,
):
    """Different canonical values remain separate."""
    first = make_asset(
        "api.example.com",
        "HOSTNAME",
        "api.example.com",
        ["ct"],
    )

    second = make_asset(
        "www.example.com",
        "HOSTNAME",
        "www.example.com",
        ["ct"],
    )

    result = deduplicator.deduplicate(
        [first, second]
    )

    assert len(result) == 2


def test_deduplicate_preserves_first_seen_order(
    deduplicator: AssetDeduplicator,
):
    """Unique assets retain first-seen ordering."""
    assets = [
        make_asset(
            "b.example.com",
            "HOSTNAME",
            "b.example.com",
            ["ct"],
        ),
        make_asset(
            "a.example.com",
            "HOSTNAME",
            "a.example.com",
            ["ct"],
        ),
        make_asset(
            "c.example.com",
            "HOSTNAME",
            "c.example.com",
            ["ct"],
        ),
    ]

    result = deduplicator.deduplicate(assets)

    assert [
        asset.normalized_value
        for asset in result
    ] == [
        "b.example.com",
        "a.example.com",
        "c.example.com",
    ]


def test_deduplicate_accepts_empty_input(
    deduplicator: AssetDeduplicator,
):
    """An empty input produces an empty result."""
    assert deduplicator.deduplicate([]) == []


def test_deduplicate_accepts_generators(
    deduplicator: AssetDeduplicator,
):
    """The deduplicator accepts general iterables."""
    assets = (
        make_asset(
            "www.example.com",
            "HOSTNAME",
            "www.example.com",
            ["ct"],
        )
        for _ in range(2)
    )

    result = deduplicator.deduplicate(assets)

    assert len(result) == 1


def test_deduplicate_rejects_non_asset_input(
    deduplicator: AssetDeduplicator,
):
    """Non-Asset values are rejected."""
    with pytest.raises(
        DeduplicationError,
        match="must contain Asset objects",
    ):
        deduplicator.deduplicate(
            ["www.example.com"]
        )


def test_deduplicate_rejects_missing_normalized_value(
    deduplicator: AssetDeduplicator,
):
    """Assets without canonical values cannot be deduplicated."""
    asset = make_asset(
        "example.com",
        "HOSTNAME",
        "example.com",
    )

    invalid_asset = asset.model_copy(
        update={
            "normalized_value": None,
        }
    )

    with pytest.raises(
        DeduplicationError,
        match="normalized_value is required",
    ):
        deduplicator.deduplicate(
            [invalid_asset]
        )


def test_deduplicate_is_case_insensitive_for_identity(
    deduplicator: AssetDeduplicator,
):
    """Canonical identity comparison is case-insensitive."""
    first = make_asset(
        "example.com",
        "hostname",
        "Example.COM",
        ["source_a"],
    )

    second = make_asset(
        "EXAMPLE.COM",
        "HOSTNAME",
        "example.com",
        ["source_b"],
    )

    result = deduplicator.deduplicate(
        [first, second]
    )

    assert len(result) == 1
    assert result[0].sources == [
        "source_a",
        "source_b",
    ]