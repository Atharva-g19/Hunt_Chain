"""Technology intelligence models for Hunt_Chain Project 2.

These models represent technologies observed or inferred from reconnaissance
evidence. They do not perform fingerprinting, vulnerability detection, or
security assessment themselves.

Technology confidence is intentionally limited to explainable V1 tiers:
LOW, MEDIUM, and HIGH.
"""

from __future__ import annotations

from enum import Enum
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TechnologyCategory(str, Enum):
    """Technology categories supported by the V1 model."""

    WEB_SERVER = "WEB_SERVER"
    WEB_FRAMEWORK = "WEB_FRAMEWORK"
    JAVASCRIPT_FRAMEWORK = "JAVASCRIPT_FRAMEWORK"
    CMS = "CMS"
    PROGRAMMING_LANGUAGE = "PROGRAMMING_LANGUAGE"
    DATABASE = "DATABASE"
    CDN = "CDN"
    CLOUD_PLATFORM = "CLOUD_PLATFORM"
    OTHER = "OTHER"


class TechnologyConfidence(str, Enum):
    """Explainable confidence tiers for technology observations."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class TechnologyEvidenceType(str, Enum):
    """Types of evidence that can support a technology observation."""

    HTTP_HEADER = "HTTP_HEADER"
    HTTP_BODY = "HTTP_BODY"
    HTML = "HTML"
    COOKIE = "COOKIE"
    TLS = "TLS"
    DNS = "DNS"
    RESPONSE_HASH = "RESPONSE_HASH"
    PROVIDER_METADATA = "PROVIDER_METADATA"
    OTHER = "OTHER"


class Technology(BaseModel):
    """Represents a technology identified during reconnaissance.

    A Technology object represents an observed or inferred technology
    associated with an asset or endpoint.

    It does not claim that the technology is vulnerable or that a specific
    version is insecure.
    """

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for the technology.",
    )

    name: str = Field(
        ...,
        min_length=1,
        description="Human-readable technology name.",
    )

    category: TechnologyCategory = Field(
        ...,
        description="Technology category.",
    )

    version: str | None = Field(
        default=None,
        description="Observed or inferred technology version, if available.",
    )

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value: str) -> str:
        """Normalize the technology name."""
        normalized = value.strip()

        if not normalized:
            raise ValueError("Technology name must not be empty.")

        return normalized

    @field_validator("version")
    @classmethod
    def normalize_version(cls, value: str | None) -> str | None:
        """Normalize an optional technology version."""
        if value is None:
            return None

        normalized = value.strip()

        return normalized if normalized else None


class TechnologyEvidence(BaseModel):
    """Evidence supporting a technology observation.

    Evidence explains why a technology was identified. It should contain
    an observable fact or deterministic fingerprinting result rather than
    a vulnerability conclusion.
    """

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for the technology evidence.",
    )

    technology_id: UUID = Field(
        ...,
        description="Identifier of the technology supported by this evidence.",
    )

    evidence_type: TechnologyEvidenceType = Field(
        ...,
        description="Type of evidence supporting the technology observation.",
    )

    source_id: UUID | None = Field(
        default=None,
        description=(
            "Optional identifier of the observation that produced the evidence."
        ),
    )

    observation: str = Field(
        ...,
        min_length=1,
        description="Human-readable description of the observed evidence.",
    )

    rule: str = Field(
        ...,
        min_length=1,
        description=(
            "Deterministic fingerprinting rule or method that produced "
            "the evidence."
        ),
    )

    confidence: TechnologyConfidence = Field(
        ...,
        description="Explainable confidence tier for this evidence.",
    )

    @field_validator("evidence_type", mode="before")
    @classmethod
    def normalize_evidence_type(
        cls,
        value: str | TechnologyEvidenceType,
    ) -> TechnologyEvidenceType:
        """Normalize and validate the evidence type."""
        if isinstance(value, TechnologyEvidenceType):
            return value

        if isinstance(value, str):
            normalized = value.strip().upper()

            try:
                return TechnologyEvidenceType(normalized)
            except ValueError as exc:
                raise ValueError(
                    "Evidence type must be one of: "
                    "HTTP_HEADER, HTTP_BODY, HTML, COOKIE, TLS, "
                    "DNS, RESPONSE_HASH, PROVIDER_METADATA, OTHER."
                ) from exc

        raise ValueError(
            "Evidence type must be one of: "
            "HTTP_HEADER, HTTP_BODY, HTML, COOKIE, TLS, "
            "DNS, RESPONSE_HASH, PROVIDER_METADATA, OTHER."
        )

    @field_validator("confidence", mode="before")
    @classmethod
    def normalize_confidence(
        cls,
        value: str | TechnologyConfidence,
    ) -> TechnologyConfidence:
        """Normalize and validate the confidence tier."""
        if isinstance(value, TechnologyConfidence):
            return value

        if isinstance(value, str):
            normalized = value.strip().upper()

            try:
                return TechnologyConfidence(normalized)
            except ValueError as exc:
                raise ValueError(
                    "Confidence must be one of: LOW, MEDIUM, HIGH."
                ) from exc

        raise ValueError(
            "Confidence must be one of: LOW, MEDIUM, HIGH."
        )

    @field_validator("observation", "rule")
    @classmethod
    def validate_text(cls, value: str) -> str:
        """Ensure required evidence text is not empty."""
        normalized = value.strip()

        if not normalized:
            raise ValueError("Evidence text must not be empty.")

        return normalized