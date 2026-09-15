"""Asset models for Hunt_Chain Project 2.

These models represent discovered assets and their provenance.

The Asset model stores both the original observed value and an optional
canonical normalized value. Full normalization and deduplication are
responsibilities of the processing layer.
"""

from __future__ import annotations

from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AssetType(str, Enum):
    """Asset types supported by Project 2 V1."""

    DOMAIN = "DOMAIN"
    HOSTNAME = "HOSTNAME"
    IP_ADDRESS = "IP_ADDRESS"


class Asset(BaseModel):
    """Represents a discovered reconnaissance asset.

    ``value`` preserves the original value observed by a provider.

    ``normalized_value`` stores the canonical representation when
    normalization has been performed. It is optional at model creation
    time because normalization belongs to the processing layer.

    The model itself performs only lightweight input validation and does
    not perform DNS lookups, network requests, deduplication, or
    reconnaissance.
    """

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for the asset.",
    )

    value: str = Field(
        ...,
        min_length=1,
        description="Original value observed by a discovery provider.",
    )

    normalized_value: str | None = Field(
        default=None,
        description=(
            "Canonical normalized value when normalization has been "
            "performed by the processing layer."
        ),
    )

    type: AssetType = Field(
        ...,
        description="Type of discovered asset.",
    )

    sources: list[str] = Field(
        default_factory=list,
        description=(
            "Provenance references identifying discovery providers or "
            "sources that produced this asset."
        ),
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Additional observation-only asset metadata. "
            "Must not contain vulnerability conclusions."
        ),
    )

    @field_validator("value")
    @classmethod
    def validate_value(cls, value: str) -> str:
        """Validate and clean the original asset value."""
        normalized = value.strip()

        if not normalized:
            raise ValueError("Asset value must not be empty.")

        return normalized

    @field_validator("normalized_value")
    @classmethod
    def validate_normalized_value(
        cls,
        value: str | None,
    ) -> str | None:
        """Validate an optional canonical asset value."""
        if value is None:
            return None

        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "normalized_value must not be empty when supplied."
            )

        return normalized

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(cls, value: AssetType | str) -> AssetType:
        """Normalize and validate the asset type."""
        if isinstance(value, AssetType):
            return value

        if isinstance(value, str):
            normalized = value.strip().upper()

            try:
                return AssetType(normalized)
            except ValueError as exc:
                raise ValueError(
                    "Asset type must be one of: "
                    "DOMAIN, HOSTNAME, IP_ADDRESS."
                ) from exc

        raise ValueError(
            "Asset type must be one of: "
            "DOMAIN, HOSTNAME, IP_ADDRESS."
        )

    @field_validator("sources")
    @classmethod
    def validate_sources(cls, value: list[str]) -> list[str]:
        """Normalize provenance references while preserving order."""
        normalized_sources: list[str] = []
        seen: set[str] = set()

        for source in value:
            cleaned = source.strip()

            if not cleaned:
                raise ValueError(
                    "Asset source references must not be empty."
                )

            if cleaned not in seen:
                seen.add(cleaned)
                normalized_sources.append(cleaned)

        return normalized_sources