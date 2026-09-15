"""
The engine is responsible for orchestrating the authorized reconnaissance
pipeline.

Its primary responsibilities are:
- enforce ScopeGuard authorization,
- enforce execution policy,
- execute registered stages in order,
- preserve stage results,
- maintain reconnaissance run lifecycle state,
- stop when a required policy check fails.

The engine itself does not perform reconnaissance. Concrete discovery,
processing, DNS, HTTP, fingerprinting, infrastructure, correlation, and
Attack Surface stages are connected through dedicated pipeline stages.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from hunt_chain_recon.models.run import ReconRunStatus
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.policy.execution import (
    ExecutionActivity,
    ExecutionPolicyError,
)


class PipelineError(Exception):
    """Base exception for pipeline execution failures."""


class PipelineAuthorizationError(PipelineError):
    """Raised when pipeline execution is attempted without authorization."""


class PipelineStageError(PipelineError):
    """Raised when a pipeline stage fails during execution."""


@dataclass(frozen=True)
class PipelineStage:
    """A single executable Project 2 pipeline stage."""

    name: str
    activity: ExecutionActivity
    handler: Callable[[PipelineContext], Any]

    def __post_init__(self) -> None:
        if not isinstance(
            self.name,
            str,
        ):
            raise TypeError(
                "Pipeline stage name must be a string."
            )

        if not self.name.strip():
            raise ValueError(
                "Pipeline stage name must not be empty."
            )

        if not callable(
            self.handler
        ):
            raise TypeError(
                "Pipeline stage handler must be callable."
            )


@dataclass
class PipelineResult:
    """Result returned after pipeline execution."""

    completed: bool = False
    blocked: bool = False
    stage_results: dict[str, Any] = field(
        default_factory=dict
    )
    failed_stage: str | None = None
    error: str | None = None


class PipelineEngine:
    """Execute registered Project 2 stages in deterministic order."""

    def __init__(
        self,
        context: PipelineContext,
        *,
        include_default_stages: bool = False,
    ) -> None:
        self._context = context
        self._stages: list[PipelineStage] = []

        if include_default_stages:
            self.register_default_stages()

    @property
    def context(self) -> PipelineContext:
        """Return the pipeline execution context."""

        return self._context

    @property
    def stages(self) -> tuple[PipelineStage, ...]:
        """Return registered stages in execution order."""

        return tuple(
            self._stages
        )

    def add_stage(
        self,
        stage: PipelineStage,
    ) -> None:
        """Register a pipeline stage."""

        if any(
            existing.name == stage.name
            for existing in self._stages
        ):
            raise ValueError(
                f"Pipeline stage '{stage.name}' is already registered."
            )

        self._stages.append(
            stage
        )

    def clear_stages(self) -> None:
        """Remove all registered stages."""

        self._stages.clear()

    def register_default_stages(self) -> None:
        """Register the built-in Project 2 V1 pipeline stages.

        Current default flow:

            TargetStage
                ->
            DiscoveryStage
                ->
            AssetProcessingStage
                ->
            AssetMergeStage
                ->
            DNSStage
                ->
            DNSAnalysisStage
                ->
            EndpointStage
                ->
            HTTPStage
                ->
            FingerprintingStage
                ->
            InfrastructureStage
                ->
            AttackSurfaceStage

        AttackSurfaceStage performs deterministic correlation using all
        observations accumulated by the preceding stages.
        """

        from hunt_chain_recon.pipeline.asset_merge import (
            AssetMergeStage,
        )
        from hunt_chain_recon.pipeline.asset_processing import (
            AssetProcessingStage,
        )
        from hunt_chain_recon.pipeline.attack_surface import (
            AttackSurfaceStage,
        )
        from hunt_chain_recon.pipeline.discovery import (
            DiscoveryStage,
        )
        from hunt_chain_recon.pipeline.dns import (
            DNSStage,
        )
        from hunt_chain_recon.pipeline.dns_analysis import (
            DNSAnalysisStage,
        )
        from hunt_chain_recon.pipeline.endpoints import (
            EndpointStage,
        )
        from hunt_chain_recon.pipeline.fingerprinting import (
            FingerprintingStage,
        )
        from hunt_chain_recon.pipeline.http import (
            HTTPStage,
        )
        from hunt_chain_recon.pipeline.infrastructure import (
            InfrastructureStage,
        )
        from hunt_chain_recon.pipeline.target import (
            TargetStage,
        )

        stages = [
            TargetStage(),
            DiscoveryStage(),
            AssetProcessingStage(),
            AssetMergeStage(),
            DNSStage(),
            DNSAnalysisStage(),
            EndpointStage(),
            HTTPStage(),
            FingerprintingStage(),
            InfrastructureStage(),
            AttackSurfaceStage(),
        ]

        for stage in stages:
            self.add_stage(
                PipelineStage(
                    name=stage.name,
                    activity=stage.activity,
                    handler=stage.execute,
                )
            )

    def _set_run_status(
        self,
        status: ReconRunStatus,
    ) -> None:
        """Update the lifecycle status of the current reconnaissance run."""

        self._context.run.status = status

    def _complete_run(
        self,
        status: ReconRunStatus,
    ) -> None:
        """Set the terminal lifecycle state and completion timestamp."""

        self._context.run.status = status
        self._context.run.completed_at = datetime.now(
            timezone.utc
        )

    def run(self) -> PipelineResult:
        """Execute all registered stages after authorization checks."""

        if not self._context.is_authorized():
            self._complete_run(
                ReconRunStatus.BLOCKED
            )

            return PipelineResult(
                completed=False,
                blocked=True,
                error=(
                    "Pipeline execution blocked: target is not authorized "
                    "by ScopeGuard."
                ),
            )

        self._set_run_status(
            ReconRunStatus.RUNNING
        )

        results: dict[str, Any] = {}

        for stage in self._stages:
            try:
                self._context.execution_policy.require_allowed(
                    stage.activity
                )
            except ExecutionPolicyError as exc:
                self._complete_run(
                    ReconRunStatus.BLOCKED
                )

                return PipelineResult(
                    completed=False,
                    blocked=True,
                    stage_results=results,
                    failed_stage=stage.name,
                    error=str(exc),
                )

            try:
                results[stage.name] = stage.handler(
                    self._context
                )
            except Exception as exc:
                self._complete_run(
                    ReconRunStatus.FAILED
                )

                return PipelineResult(
                    completed=False,
                    blocked=False,
                    stage_results=results,
                    failed_stage=stage.name,
                    error=(
                        f"Pipeline stage '{stage.name}' failed: {exc}"
                    ),
                )

        self._complete_run(
            ReconRunStatus.COMPLETED
        )

        return PipelineResult(
            completed=True,
            blocked=False,
            stage_results=results,
        )