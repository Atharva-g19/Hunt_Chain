"""Base provider contracts for Hunt_Chain Project 2.

Providers are responsible for collecting observations from a specific
reconnaissance source or mechanism.

Providers must not:
- bypass ScopeGuard authorization,
- perform vulnerability testing,
- perform exploitation,
- make vulnerability conclusions,
- silently alter observations into findings.

The pipeline and processing layers are responsible for normalization,
deduplication, correlation, and interpretation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
from typing import Any, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator


ObservationT = TypeVar("ObservationT")


class ProviderStatus(str, Enum):
    """Execution status returned by a provider."""

    SUCCESS = "SUCCESS"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class ProviderErrorType(str, Enum):
    """Standardized provider error categories."""

    TIMEOUT = "TIMEOUT"
    NETWORK_ERROR = "NETWORK_ERROR"
    INVALID_RESPONSE = "INVALID_RESPONSE"
    CONFIGURATION_ERROR = "CONFIGURATION_ERROR"
    PERMISSION_ERROR = "PERMISSION_ERROR"
    EXECUTION_ERROR = "EXECUTION_ERROR"
    NOT_INSTALLED = "NOT_INSTALLED"


class ProviderError(BaseModel):
    """Represents an error encountered during provider execution.

    Provider errors describe execution problems. They are not vulnerability
    findings.
    """

    model_config = ConfigDict(extra="forbid")

    type: ProviderErrorType = Field(
        ...,
        description="Category of provider execution error.",
    )

    message: str = Field(
        ...,
        min_length=1,
        description="Human-readable description of the error.",
    )

    retryable: bool = Field(
        default=False,
        description="Whether retrying the provider operation may be useful.",
    )

    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional structured execution context.",
    )

    @field_validator("type", mode="before")
    @classmethod
    def normalize_type(
        cls,
        value: ProviderErrorType | str,
    ) -> ProviderErrorType:
        """Normalize and validate the provider error type."""
        if isinstance(value, ProviderErrorType):
            return value

        if isinstance(value, str):
            normalized = value.strip().upper()

            try:
                return ProviderErrorType(normalized)
            except ValueError as exc:
                raise ValueError(
                    "Provider error type must be one of: "
                    "TIMEOUT, NETWORK_ERROR, INVALID_RESPONSE, "
                    "CONFIGURATION_ERROR, PERMISSION_ERROR, "
                    "EXECUTION_ERROR, NOT_INSTALLED."
                ) from exc

        raise ValueError(
            "Provider error type must be one of: "
            "TIMEOUT, NETWORK_ERROR, INVALID_RESPONSE, "
            "CONFIGURATION_ERROR, PERMISSION_ERROR, "
            "EXECUTION_ERROR, NOT_INSTALLED."
        )

    @field_validator("message")
    @classmethod
    def validate_message(cls, value: str) -> str:
        """Ensure the provider error message is not empty."""
        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "Provider error message must not be empty."
            )

        return normalized


class ProviderResult(BaseModel, Generic[ObservationT]):
    """Standard result envelope returned by a provider."""

    model_config = ConfigDict(extra="forbid")

    status: ProviderStatus = Field(
        ...,
        description="Overall execution status of the provider.",
    )

    observations: list[ObservationT] = Field(
        default_factory=list,
        description="Observations collected by the provider.",
    )

    errors: list[ProviderError] = Field(
        default_factory=list,
        description="Errors encountered during provider execution.",
    )

    provider: str = Field(
        ...,
        min_length=1,
        description="Stable provider name.",
    )

    version: str = Field(
        default="unknown",
        min_length=1,
        description="Provider implementation version.",
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional provider execution metadata.",
    )

    @field_validator("status", mode="before")
    @classmethod
    def normalize_status(
        cls,
        value: ProviderStatus | str,
    ) -> ProviderStatus:
        """Normalize and validate provider status."""
        if isinstance(value, ProviderStatus):
            return value

        if isinstance(value, str):
            normalized = value.strip().upper()

            try:
                return ProviderStatus(normalized)
            except ValueError as exc:
                raise ValueError(
                    "Provider status must be one of: "
                    "SUCCESS, PARTIAL, FAILED, SKIPPED."
                ) from exc

        raise ValueError(
            "Provider status must be one of: "
            "SUCCESS, PARTIAL, FAILED, SKIPPED."
        )

    @field_validator("provider", "version")
    @classmethod
    def validate_provider_metadata(cls, value: str) -> str:
        """Validate required provider metadata."""
        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "Provider name and version must not be empty."
            )

        return normalized


class Provider(ABC, Generic[ObservationT]):
    """Abstract base contract for all Project 2 providers.

    Concrete providers implement ``execute`` and return a ProviderResult.

    The base contract deliberately does not know how a provider performs
    discovery or network interaction.
    """

    name: str
    version: str

    @property
    @abstractmethod
    def capabilities(self) -> tuple[str, ...]:
        """Return the capabilities exposed by this provider."""
        raise NotImplementedError

    @abstractmethod
    def execute(self, context: Any) -> ProviderResult[ObservationT]:
        """Execute the provider using the supplied pipeline context."""
        raise NotImplementedError