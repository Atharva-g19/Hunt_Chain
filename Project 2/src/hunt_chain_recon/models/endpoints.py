"""Endpoint models for Hunt_Chain Project 2.

These models represent HTTP/HTTPS application endpoints without performing
network requests or making assumptions about endpoint availability.

They provide the normalized endpoint representation consumed by downstream security testing.
"""

from __future__ import annotations

from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EndpointScheme(str, Enum):
    """Supported endpoint communication schemes."""

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

    method: str = Field(
        default="GET",
        min_length=1,
        description="Observed or discovered HTTP method.",
    )

    path: str = Field(
        default="/",
        min_length=1,
        description="Normalized URL path.",
    )

    query_parameters: dict[str, str | None] = Field(
        default_factory=dict,
        description="Query parameters discovered on the endpoint.",
    )

    query_parameter_values: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Observed values for discovered query parameters.",
    )

    body_parameters: dict[str, str | None] = Field(
        default_factory=dict,
        description="Form or structured-body parameters discovered on the endpoint.",
    )

    content_type: str | None = Field(
        default=None,
        description="Observed or discovered request content type.",
    )

    source: str = Field(
        default="configured",
        min_length=1,
        description="Discovery provenance for the endpoint.",
    )

    parent_endpoint: UUID | None = Field(
        default=None,
        description="Endpoint from which this endpoint was discovered.",
    )

    discovered_from: str | None = Field(
        default=None,
        description="Source URL or artifact that yielded this endpoint.",
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Additional observation-only endpoint context. "
            "Must not contain vulnerability conclusions."
        ),
    )

    @field_validator("method")
    @classmethod
    def normalize_method(cls, value: str) -> str:
        normalized = value.strip().upper()
        if not normalized:
            raise ValueError("Method must not be empty.")
        return normalized

    @field_validator("path")
    @classmethod
    def normalize_path(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("Path must not be empty.")
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        return normalized

    @field_validator("source")
    @classmethod
    def normalize_source(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not normalized:
            raise ValueError("Source must not be empty.")
        return normalized

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