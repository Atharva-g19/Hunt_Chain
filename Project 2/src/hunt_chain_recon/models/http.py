"""HTTP and TLS observation models for Hunt_Chain Project 2.

These models represent observed HTTP/HTTPS responses and lightweight TLS
observations.

They do not perform network requests, vulnerability scanning, technology
fingerprinting, or security assessment.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class HTTPObservationState(str, Enum):
    """Result state of an HTTP observation."""

    SUCCESS = "SUCCESS"
    CONNECTION_ERROR = "CONNECTION_ERROR"
    TIMEOUT = "TIMEOUT"
    TLS_ERROR = "TLS_ERROR"
    REDIRECT = "REDIRECT"
    ERROR = "ERROR"


class TLSObservation(BaseModel):
    """Lightweight TLS information observed from an HTTPS interaction.

    This model records TLS metadata only. It is not a TLS vulnerability
    scanner and does not determine whether a TLS configuration is secure.
    """

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for the TLS observation.",
    )

    version: str | None = Field(
        default=None,
        description="Observed TLS protocol version.",
    )

    cipher: str | None = Field(
        default=None,
        description="Observed TLS cipher suite.",
    )

    certificate_subject: str | None = Field(
        default=None,
        description="Observed certificate subject.",
    )

    certificate_issuer: str | None = Field(
        default=None,
        description="Observed certificate issuer.",
    )

    certificate_not_before: datetime | None = Field(
        default=None,
        description="Certificate validity start time when observed.",
    )

    certificate_not_after: datetime | None = Field(
        default=None,
        description="Certificate validity end time when observed.",
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional TLS observation metadata.",
    )

    @field_validator(
        "version",
        "cipher",
        "certificate_subject",
        "certificate_issuer",
    )
    @classmethod
    def normalize_optional_text(
        cls,
        value: str | None,
    ) -> str | None:
        """Normalize optional textual TLS fields."""
        if value is None:
            return None

        normalized = value.strip()

        return normalized if normalized else None


class HTTPObservation(BaseModel):
    """Represents an observed HTTP or HTTPS interaction.

    The model stores response evidence without interpreting it as a
    vulnerability or confirmed technology.

    Response hashing and technology fingerprinting are performed later
    by dedicated processing components.
    """

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for the HTTP observation.",
    )

    endpoint_id: UUID = Field(
        ...,
        description="Identifier of the endpoint that was observed.",
    )

    state: HTTPObservationState = Field(
        ...,
        description="Result state of the HTTP interaction.",
    )

    status_code: int | None = Field(
        default=None,
        ge=100,
        le=599,
        description="Observed HTTP status code.",
    )

    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Observed HTTP response headers.",
    )

    content_type: str | None = Field(
        default=None,
        description="Observed HTTP Content-Type value.",
    )

    body_length: int | None = Field(
        default=None,
        ge=0,
        description="Observed response body length in bytes.",
    )

    body_hash: str | None = Field(
        default=None,
        description=(
            "Deterministic response body hash, normally SHA-256 in V1."
        ),
    )

    redirect_chain: list[str] = Field(
        default_factory=list,
        description="Observed redirect locations in request order.",
    )

    tls: TLSObservation | None = Field(
        default=None,
        description="Optional TLS observation associated with HTTPS.",
    )

    observed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the HTTP observation was captured.",
    )

    error_message: str | None = Field(
        default=None,
        description="Error description when the interaction did not complete normally.",
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Additional observation-only HTTP context. "
            "Must not contain vulnerability conclusions."
        ),
    )

    @field_validator("state", mode="before")
    @classmethod
    def normalize_state(
        cls,
        value: Any,
    ) -> HTTPObservationState:
        """Normalize and validate the HTTP observation state."""
        if isinstance(value, HTTPObservationState):
            return value

        if isinstance(value, str):
            normalized = value.strip().upper()

            try:
                return HTTPObservationState(normalized)
            except ValueError as exc:
                raise ValueError(
                    "State must be one of: "
                    "SUCCESS, CONNECTION_ERROR, TIMEOUT, "
                    "TLS_ERROR, REDIRECT, ERROR."
                ) from exc

        raise ValueError(
            "State must be one of: "
            "SUCCESS, CONNECTION_ERROR, TIMEOUT, "
            "TLS_ERROR, REDIRECT, ERROR."
        )

    @field_validator("content_type", "body_hash", "error_message")
    @classmethod
    def normalize_optional_text(
        cls,
        value: str | None,
    ) -> str | None:
        """Normalize optional textual response fields."""
        if value is None:
            return None

        normalized = value.strip()

        return normalized if normalized else None

    @field_validator("headers")
    @classmethod
    def normalize_headers(
        cls,
        value: dict[str, str],
    ) -> dict[str, str]:
        """Normalize HTTP header names and values."""
        normalized: dict[str, str] = {}

        for name, header_value in value.items():
            normalized_name = name.strip().lower()
            normalized_value = header_value.strip()

            if not normalized_name:
                raise ValueError(
                    "HTTP header names must not be empty."
                )

            normalized[normalized_name] = normalized_value

        return normalized

    @field_validator("redirect_chain")
    @classmethod
    def normalize_redirect_chain(
        cls,
        value: list[str],
    ) -> list[str]:
        """Normalize redirect locations while preserving their order."""
        normalized: list[str] = []

        for location in value:
            cleaned = location.strip()

            if not cleaned:
                raise ValueError(
                    "Redirect locations must not be empty."
                )

            normalized.append(cleaned)

        return normalized