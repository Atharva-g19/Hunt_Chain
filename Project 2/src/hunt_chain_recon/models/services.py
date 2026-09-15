"""Service observation models for Hunt_Chain Project 2.

These models represent observed or associated network services without
performing port scanning, network requests, protocol inference, or
vulnerability detection.

They are intentionally limited to the V1 service observation layer.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ServiceState(str, Enum):
    """Observation state of a network service."""

    OBSERVED = "OBSERVED"
    UNKNOWN = "UNKNOWN"


class TransportProtocol(str, Enum):
    """Supported transport protocols for V1."""

    TCP = "TCP"
    UDP = "UDP"


class Service(BaseModel):
    """Represents a network service associated with an asset.

    This model records service-level observations only.

    It intentionally does not infer an application protocol from a port.
    For example, port 80 does not automatically mean HTTP and port 443
    does not automatically mean HTTPS.

    Network discovery and port scanning are responsibilities of providers,
    while interpretation and correlation are handled by later processing
    stages.
    """

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for the service.",
    )

    asset_id: UUID = Field(
        ...,
        description="Identifier of the asset associated with this service.",
    )

    state: ServiceState = Field(
        ...,
        description="Observation state of the service.",
    )

    port: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description="Optional transport-layer port number.",
    )

    transport: TransportProtocol | None = Field(
        default=None,
        description="Optional transport protocol.",
    )

    source_reference: str | None = Field(
        default=None,
        description="Optional reference identifying the observation source.",
    )

    observed_at: datetime | None = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the service observation was captured.",
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Additional observation-only provider context. "
            "Must not contain vulnerability or interpretation results."
        ),
    )

    @field_validator("state", mode="before")
    @classmethod
    def normalize_state(cls, value: Any) -> ServiceState:
        """Normalize and validate the service state."""
        if isinstance(value, ServiceState):
            return value

        if isinstance(value, str):
            normalized = value.strip().upper()

            try:
                return ServiceState(normalized)
            except ValueError as exc:
                raise ValueError(
                    "State must be one of: OBSERVED, UNKNOWN."
                ) from exc

        raise ValueError(
            "State must be one of: OBSERVED, UNKNOWN."
        )

    @field_validator("transport", mode="before")
    @classmethod
    def normalize_transport(
        cls,
        value: Any,
    ) -> TransportProtocol | None:
        """Normalize and validate the transport protocol."""
        if value is None:
            return None

        if isinstance(value, TransportProtocol):
            return value

        if isinstance(value, str):
            normalized = value.strip().upper()

            try:
                return TransportProtocol(normalized)
            except ValueError as exc:
                raise ValueError(
                    "Transport must be one of: TCP, UDP."
                ) from exc

        raise ValueError(
            "Transport must be one of: TCP, UDP."
        )

    @field_validator("source_reference")
    @classmethod
    def validate_source_reference(
        cls,
        value: str | None,
    ) -> str | None:
        """Normalize an optional source reference."""
        if value is None:
            return None

        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "source_reference must not be empty when supplied."
            )

        return normalized