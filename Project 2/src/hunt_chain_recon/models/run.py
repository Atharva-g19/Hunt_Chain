"""Reconnaissance run metadata models for Hunt_Chain Project 2.

These models describe the execution metadata of a reconnaissance run.
They do not perform reconnaissance, authorization, network requests,
or result correlation.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ReconRunStatus(str, Enum):
    """Lifecycle status of a reconnaissance run."""

    INITIALIZED = "INITIALIZED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    PARTIAL = "PARTIAL"
    FAILED = "FAILED"
    BLOCKED = "BLOCKED"


class ExecutionMode(str, Enum):
    """Execution modes supported by Project 2."""

    ACTIVE = "active"
    PASSIVE_ONLY = "passive_only"


class ReconRun(BaseModel):
    """Metadata describing one Project 2 reconnaissance execution.

    A ReconRun identifies and describes the execution itself. It does not
    contain reconnaissance observations or vulnerability findings.
    """

    model_config = ConfigDict(extra="forbid")

    @classmethod
    def create(
        cls,
        *,
        target: str,
        execution_mode: ExecutionMode | str = ExecutionMode.ACTIVE,
        status: ReconRunStatus | str = ReconRunStatus.INITIALIZED,
        **kwargs: Any,
    ) -> "ReconRun":
        """Create a ReconRun using the pipeline’s expected factory pattern."""
        return cls(
            target=target,
            execution_mode=execution_mode,
            status=status,
            **kwargs,
        )

    id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for the reconnaissance run.",
    )

    target: str = Field(
        ...,
        min_length=1,
        description="Target supplied for the reconnaissance run.",
    )

    execution_mode: ExecutionMode = Field(
        default=ExecutionMode.ACTIVE,
        description="Execution mode used by the reconnaissance run.",
    )

    status: ReconRunStatus = Field(
        default=ReconRunStatus.INITIALIZED,
        description="Current lifecycle status of the reconnaissance run.",
    )

    started_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the run was initialized.",
    )

    completed_at: datetime | None = Field(
        default=None,
        description="UTC timestamp when the run completed or stopped.",
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Additional execution metadata. "
            "Must not contain vulnerability conclusions."
        ),
    )

    @field_validator("target")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        """Perform lightweight target normalization."""
        normalized = value.strip().lower().rstrip(".")

        if not normalized:
            raise ValueError("Target must not be empty.")

        return normalized

    @field_validator("execution_mode", mode="before")
    @classmethod
    def normalize_execution_mode(
        cls,
        value: ExecutionMode | str,
    ) -> ExecutionMode:
        """Normalize and validate the execution mode."""
        if isinstance(value, ExecutionMode):
            return value

        if isinstance(value, str):
            normalized = value.strip().lower()

            try:
                return ExecutionMode(normalized)
            except ValueError as exc:
                raise ValueError(
                    "Execution mode must be one of: "
                    "active, passive_only."
                ) from exc

        raise ValueError(
            "Execution mode must be one of: active, passive_only."
        )

    @field_validator("status", mode="before")
    @classmethod
    def normalize_status(
        cls,
        value: ReconRunStatus | str,
    ) -> ReconRunStatus:
        """Normalize and validate the run status."""
        if isinstance(value, ReconRunStatus):
            return value

        if isinstance(value, str):
            normalized = value.strip().upper()

            try:
                return ReconRunStatus(normalized)
            except ValueError as exc:
                raise ValueError(
                    "Run status must be one of: "
                    "INITIALIZED, RUNNING, COMPLETED, PARTIAL, "
                    "FAILED, BLOCKED."
                ) from exc

        raise ValueError(
            "Run status must be one of: "
            "INITIALIZED, RUNNING, COMPLETED, PARTIAL, "
            "FAILED, BLOCKED."
        )