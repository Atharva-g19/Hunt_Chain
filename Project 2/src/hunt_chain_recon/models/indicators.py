"""Reconnaissance indicator models for Hunt_Chain Project 2.

These models represent observations or signals that may require further
investigation. They are not vulnerability findings and do not confirm
exploitation or compromise.

Project 2 V1 intentionally includes lightweight indicators such as
potential dangling CNAME observations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class IndicatorType(str, Enum):
    """Indicator types supported by Project 2 V1."""

    POTENTIAL_DANGLING_CNAME = "POTENTIAL_DANGLING_CNAME"


class IndicatorConfidence(str, Enum):
    """Explainable confidence levels for reconnaissance indicators."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class IndicatorStatus(str, Enum):
    """Lifecycle state of a reconnaissance indicator."""

    OBSERVED = "OBSERVED"
    NEEDS_REVIEW = "NEEDS_REVIEW"


class Indicator(BaseModel):
    """Represents a reconnaissance indicator requiring attention.

    An Indicator is deliberately different from a vulnerability finding.

    For example, POTENTIAL_DANGLING_CNAME means that reconnaissance
    produced evidence consistent with a potentially dangling CNAME.
    It does not mean that DNS takeover has been confirmed.

    Confirmation, exploitation, and vulnerability assessment belong to
    later Hunt_Chain projects.
    """

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for the indicator.",
    )

    asset_id: UUID = Field(
        ...,
        description="Identifier of the asset associated with the indicator.",
    )

    type: IndicatorType = Field(
        ...,
        description="Type of reconnaissance indicator.",
    )

    status: IndicatorStatus = Field(
        default=IndicatorStatus.OBSERVED,
        description="Current observation status of the indicator.",
    )

    confidence: IndicatorConfidence = Field(
        ...,
        description="Explainable confidence tier for the indicator.",
    )

    title: str = Field(
        ...,
        min_length=1,
        description="Short human-readable indicator title.",
    )

    description: str = Field(
        ...,
        min_length=1,
        description="Explanation of the observed indicator.",
    )

    evidence: list[str] = Field(
        default_factory=list,
        description="Observable evidence supporting the indicator.",
    )

    source_ids: list[UUID] = Field(
        default_factory=list,
        description="Identifiers of observations supporting the indicator.",
    )

    observed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the indicator was generated.",
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Additional indicator context. This must not claim "
            "confirmed exploitation or vulnerability status."
        ),
    )

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(cls, value: Any) -> IndicatorType:
        """Normalize and validate the indicator type."""
        if isinstance(value, IndicatorType):
            return value

        if isinstance(value, str):
            normalized = value.strip().upper()

            try:
                return IndicatorType(normalized)
            except ValueError as exc:
                raise ValueError(
                    "Indicator type must be: POTENTIAL_DANGLING_CNAME."
                ) from exc

        raise ValueError(
            "Indicator type must be: POTENTIAL_DANGLING_CNAME."
        )

    @field_validator("status", mode="before")
    @classmethod
    def normalize_status(cls, value: Any) -> IndicatorStatus:
        """Normalize and validate the indicator status."""
        if isinstance(value, IndicatorStatus):
            return value

        if isinstance(value, str):
            normalized = value.strip().upper()

            try:
                return IndicatorStatus(normalized)
            except ValueError as exc:
                raise ValueError(
                    "Indicator status must be one of: "
                    "OBSERVED, NEEDS_REVIEW."
                ) from exc

        raise ValueError(
            "Indicator status must be one of: "
            "OBSERVED, NEEDS_REVIEW."
        )

    @field_validator("confidence", mode="before")
    @classmethod
    def normalize_confidence(
        cls,
        value: Any,
    ) -> IndicatorConfidence:
        """Normalize and validate indicator confidence."""
        if isinstance(value, IndicatorConfidence):
            return value

        if isinstance(value, str):
            normalized = value.strip().upper()

            try:
                return IndicatorConfidence(normalized)
            except ValueError as exc:
                raise ValueError(
                    "Confidence must be one of: LOW, MEDIUM, HIGH."
                ) from exc

        raise ValueError(
            "Confidence must be one of: LOW, MEDIUM, HIGH."
        )

    @field_validator("title", "description")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        """Ensure required descriptive fields are not empty."""
        normalized = value.strip()

        if not normalized:
            raise ValueError("Indicator text must not be empty.")

        return normalized

    @field_validator("evidence")
    @classmethod
    def validate_evidence(cls, value: list[str]) -> list[str]:
        """Normalize and validate evidence descriptions."""
        normalized: list[str] = []

        for item in value:
            cleaned = item.strip()

            if not cleaned:
                raise ValueError(
                    "Indicator evidence entries must not be empty."
                )

            normalized.append(cleaned)

        return normalized