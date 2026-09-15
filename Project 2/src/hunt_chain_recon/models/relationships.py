"""Attack-surface relationship models for Hunt_Chain Project 2.

These models represent relationships between reconnaissance entities.

Relationships are used to construct the V1 attack-surface graph. They do
not perform discovery, network requests, vulnerability testing, exploitation,
or security assessment.
"""

from __future__ import annotations

from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RelationshipType(str, Enum):
    """Relationships supported by the Project 2 V1 attack-surface model."""

    HOSTNAME_RESOLVES_TO_IP = "HOSTNAME_RESOLVES_TO_IP"
    HOSTNAME_USES_CNAME = "HOSTNAME_USES_CNAME"
    HOSTNAME_EXPOSES_SERVICE = "HOSTNAME_EXPOSES_SERVICE"
    SERVICE_SERVES_ENDPOINT = "SERVICE_SERVES_ENDPOINT"
    ENDPOINT_INDICATES_TECHNOLOGY = "ENDPOINT_INDICATES_TECHNOLOGY"
    ASSET_HAS_INDICATOR = "ASSET_HAS_INDICATOR"
    IP_SHARED_BY_HOSTNAMES = "IP_SHARED_BY_HOSTNAMES"


class Relationship(BaseModel):
    """Represents a directed relationship between two reconnaissance entities.

    The relationship connects existing entities through their UUIDs.

    The model intentionally does not validate whether the referenced IDs
    actually exist. Reference-integrity validation is the responsibility
    of the Attack Surface correlation and schema-validation layers.
    """

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for the relationship.",
    )

    type: RelationshipType = Field(
        ...,
        description="Type of relationship represented by this edge.",
    )

    source_id: UUID = Field(
        ...,
        description="Identifier of the source entity.",
    )

    target_id: UUID = Field(
        ...,
        description="Identifier of the target entity.",
    )

    evidence_ids: list[UUID] = Field(
        default_factory=list,
        description=(
            "Identifiers of observations or evidence supporting the relationship."
        ),
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Additional correlation metadata. "
            "Must not contain vulnerability conclusions."
        ),
    )

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(cls, value: Any) -> RelationshipType:
        """Normalize and validate the relationship type."""
        if isinstance(value, RelationshipType):
            return value

        if isinstance(value, str):
            normalized = value.strip().upper()

            try:
                return RelationshipType(normalized)
            except ValueError as exc:
                raise ValueError(
                    "Relationship type must be one of: "
                    "HOSTNAME_RESOLVES_TO_IP, "
                    "HOSTNAME_USES_CNAME, "
                    "HOSTNAME_EXPOSES_SERVICE, "
                    "SERVICE_SERVES_ENDPOINT, "
                    "ENDPOINT_INDICATES_TECHNOLOGY, "
                    "ASSET_HAS_INDICATOR, "
                    "IP_SHARED_BY_HOSTNAMES."
                ) from exc

        raise ValueError(
            "Relationship type must be one of: "
            "HOSTNAME_RESOLVES_TO_IP, "
            "HOSTNAME_USES_CNAME, "
            "HOSTNAME_EXPOSES_SERVICE, "
            "SERVICE_SERVES_ENDPOINT, "
            "ENDPOINT_INDICATES_TECHNOLOGY, "
            "ASSET_HAS_INDICATOR, "
            "IP_SHARED_BY_HOSTNAMES."
        )

    @field_validator("evidence_ids")
    @classmethod
    def validate_evidence_ids(
        cls,
        value: list[UUID],
    ) -> list[UUID]:
        """Remove duplicate evidence references while preserving order."""
        unique_ids: list[UUID] = []
        seen: set[UUID] = set()

        for evidence_id in value:
            if evidence_id not in seen:
                seen.add(evidence_id)
                unique_ids.append(evidence_id)

        return unique_ids