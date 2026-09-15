"""Endpoint models for Hunt_Chain Project 2.

These models represent HTTP/HTTPS application endpoints without performing
network requests or making assumptions about endpoint availability.

They are intentionally limited to the V1 endpoint representation layer.
"""

from __future__ import annotations

from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EndpointScheme(str, Enum):
    """Supported endpoint schemes for V1."""

    HTTP = "http"
    HTTPS = "https"


class Endpoint(BaseModel):
    """Represents an HTTP or HTTPS application endpoint.

    An endpoint describes a network/application location. Its existence
    does not imply that the endpoint is reachable or that an application
    is actually serving content.

    HTTP interaction and response observations are represented separately
    by HTTPObservation.
    """

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for the endpoint.",
    )

    asset_id: UUID = Field(
        ...,
        description="Identifier of the asset associated with this endpoint.",
    )

    service_id: UUID | None = Field(
        default=None,
        description="Optional identifier of the associated service.",
    )

    scheme: EndpointScheme = Field(
        ...,
        description="Endpoint communication scheme.",
    )

    hostname: str = Field(
        ...,
        min_length=1,
        description="Hostname associated with the endpoint.",
    )

    port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description="Optional network port.",
    )

    url: str = Field(
        ...,
        min_length=1,
        description="Endpoint URL or canonical application location.",
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Additional observation-only endpoint context. "
            "Must not contain vulnerability conclusions."
        ),
    )

    @field_validator("scheme", mode="before")
    @classmethod
    def normalize_scheme(cls, value: Any) -> EndpointScheme:
        """Normalize and validate the endpoint scheme."""
        if isinstance(value, EndpointScheme):
            return value

        if isinstance(value, str):
            normalized = value.strip().lower()

            try:
                return EndpointScheme(normalized)
            except ValueError as exc:
                raise ValueError(
                    "Scheme must be one of: http, https."
                ) from exc

        raise ValueError(
            "Scheme must be one of: http, https."
        )

    @field_validator("hostname")
    @classmethod
    def normalize_hostname(cls, value: str) -> str:
        """Perform lightweight hostname canonicalization."""
        normalized = value.strip().lower().rstrip(".")

        if not normalized:
            raise ValueError("Hostname must not be empty.")

        return normalized

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        """Validate that the endpoint URL is not empty."""
        normalized = value.strip()

        if not normalized:
            raise ValueError("Endpoint URL must not be empty.")

        return normalized