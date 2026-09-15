"""Authorization models for Hunt_Chain Project 2.

These models represent authorization decisions received from ScopeGuard.

Project 2 does not independently determine whether a target is
authorized. It consumes an authorization decision and enforces the
result before reconnaissance execution.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class AuthorizationDecision(str, Enum):
    """Authorization decisions recognized by Project 2."""

    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNKNOWN = "UNKNOWN"
    CONFLICT = "CONFLICT"


class AuthorizationResult(BaseModel):
    """Represents an authorization decision for a reconnaissance target.

    The result is treated as authoritative input from the configured
    authorization provider.

    Only IN_SCOPE permits Project 2 reconnaissance to continue.
    """

    model_config = ConfigDict(extra="forbid")

    id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for this authorization decision.",
    )

    target: str = Field(
        ...,
        min_length=1,
        description="Target for which authorization was evaluated.",
    )

    decision: AuthorizationDecision = Field(
        ...,
        description="Authorization decision returned by the provider.",
    )

    provider: str = Field(
        ...,
        min_length=1,
        description="Authorization provider that produced the decision.",
    )

    reference: str = Field(
        ...,
        min_length=1,
        description="Reference identifying the authorization source or record.",
    )

    evaluated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the authorization result was evaluated.",
    )

    reason: str | None = Field(
        default=None,
        description="Optional explanation supplied by the authorization provider.",
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional provider-supplied authorization metadata.",
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_legacy_fields(cls, value: Any) -> Any:
        """Accept the earlier authorized/status input shape."""
        if not isinstance(value, dict):
            return value

        normalized = dict(value)
        legacy_status = normalized.pop("status", None)
        legacy_authorized = normalized.pop("authorized", None)

        if "decision" not in normalized:
            if legacy_status is not None:
                normalized["decision"] = legacy_status
            elif legacy_authorized is not None:
                normalized["decision"] = (
                    AuthorizationDecision.IN_SCOPE
                    if legacy_authorized
                    else AuthorizationDecision.UNKNOWN
                )

        return normalized

    @field_validator("target")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        """Perform lightweight target normalization."""
        normalized = value.strip().lower().rstrip(".")

        if not normalized:
            raise ValueError("Authorization target must not be empty.")

        return normalized

    @field_validator("decision", mode="before")
    @classmethod
    def normalize_decision(
        cls,
        value: AuthorizationDecision | str,
    ) -> AuthorizationDecision:
        """Normalize and validate the authorization decision."""
        if isinstance(value, AuthorizationDecision):
            return value

        if isinstance(value, str):
            normalized = value.strip().upper()

            try:
                return AuthorizationDecision(normalized)
            except ValueError as exc:
                raise ValueError(
                    "Authorization decision must be one of: "
                    "IN_SCOPE, OUT_OF_SCOPE, UNKNOWN, CONFLICT."
                ) from exc

        raise ValueError(
            "Authorization decision must be one of: "
            "IN_SCOPE, OUT_OF_SCOPE, UNKNOWN, CONFLICT."
        )

    @field_validator("provider", "reference")
    @classmethod
    def validate_required_text(cls, value: str) -> str:
        """Validate required provider/reference values."""
        normalized = value.strip()

        if not normalized:
            raise ValueError(
                "Authorization provider and reference must not be empty."
            )

        return normalized

    @field_validator("reason")
    @classmethod
    def normalize_reason(cls, value: str | None) -> str | None:
        """Normalize an optional authorization reason."""
        if value is None:
            return None

        normalized = value.strip()

        return normalized if normalized else None

    @property
    def is_authorized(self) -> bool:
        """Return whether reconnaissance may proceed."""
        legacy_authorized = self.__dict__.get("authorized")
        if legacy_authorized is not None:
            return bool(legacy_authorized)

        legacy_status = self.__dict__.get("status")
        if legacy_status is not None:
            return str(legacy_status).upper() == AuthorizationDecision.IN_SCOPE

        return self.decision is AuthorizationDecision.IN_SCOPE

    @property
    def authorized(self) -> bool:
        """Return the legacy boolean authorization view."""
        return self.is_authorized

    @property
    def status(self) -> AuthorizationDecision:
        """Return the legacy status view of the authorization decision."""
        legacy_status = self.__dict__.get("status")
        if legacy_status is not None:
            return legacy_status

        return self.decision