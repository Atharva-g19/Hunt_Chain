"""Infrastructure observation models for Hunt_Chain Project 2.

These models represent lightweight infrastructure intelligence collected
during reconnaissance.

V1 supports:
- shared-IP observations,
- provider/edge observations.

These models do not perform network activity and do not make vulnerability
or security conclusions.
"""

from __future__ import annotations

from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class InfrastructureObservationType(str, Enum):
    """Infrastructure observation types supported by V1."""

    SHARED_IP = "SHARED_IP"
    PROVIDER = "PROVIDER"
    CDN = "CDN"
    CLOUD_PLATFORM = "CLOUD_PLATFORM"
    OTHER = "OTHER"


class InfrastructureConfidence(str, Enum):
    """Explainable confidence tiers for infrastructure observations."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class InfrastructureObservation(BaseModel):
    """Represents lightweight infrastructure intelligence."""

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for the infrastructure observation.",
    )

    observation_type: InfrastructureObservationType = Field(
        ...,
        description="Type of infrastructure observation.",
    )

    ip_address: str | None = Field(
        default=None,
        description="IP address associated with the observation.",
    )

    value: str = Field(
        ...,
        min_length=1,
        description="Observed infrastructure value.",
    )

    evidence: str = Field(
        ...,
        min_length=1,
        description="Human-readable explanation of the observation.",
    )

    confidence: InfrastructureConfidence = Field(
        ...,
        description="Explainable confidence tier.",
    )

    metadata: dict[str, str] = Field(
        default_factory=dict,
        description="Additional observation-only metadata.",
    )

    @field_validator("observation_type", mode="before")
    @classmethod
    def normalize_observation_type(
        cls,
        value: str | InfrastructureObservationType,
    ) -> InfrastructureObservationType:
        """Normalize the observation type."""
        if isinstance(value, InfrastructureObservationType):
            return value

        if isinstance(value, str):
            normalized = value.strip().upper()

            try:
                return InfrastructureObservationType(normalized)
            except ValueError as exc:
                raise ValueError(
                    "Observation type must be one of: "
                    "SHARED_IP, PROVIDER, CDN, CLOUD_PLATFORM, OTHER."
                ) from exc

        raise ValueError(
            "Observation type must be one of: "
            "SHARED_IP, PROVIDER, CDN, CLOUD_PLATFORM, OTHER."
        )

    @field_validator("confidence", mode="before")
    @classmethod
    def normalize_confidence(
        cls,
        value: str | InfrastructureConfidence,
    ) -> InfrastructureConfidence:
        """Normalize the confidence tier."""
        if isinstance(value, InfrastructureConfidence):
            return value

        if isinstance(value, str):
            normalized = value.strip().upper()

            try:
                return InfrastructureConfidence(normalized)
            except ValueError as exc:
                raise ValueError(
                    "Confidence must be one of: LOW, MEDIUM, HIGH."
                ) from exc

        raise ValueError(
            "Confidence must be one of: LOW, MEDIUM, HIGH."
        )

    @field_validator("ip_address")
    @classmethod
    def normalize_ip_address(
        cls,
        value: str | None,
    ) -> str | None:
        """Normalize an optional IP address value."""
        if value is None:
            return None

        normalized = value.strip()

        return normalized if normalized else None

    @field_validator("value", "evidence")
    @classmethod
    def normalize_required_text(
        cls,
        value: str,
    ) -> str:
        """Normalize required textual fields."""
        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "Infrastructure observation text must not be empty."
            )

        return normalized