"""Pipeline engine for Hunt_Chain Project 2.

The pipeline engine coordinates Project 2 execution after authorization
has been obtained.

Its primary responsibilities are:
- enforce ScopeGuard authorization,
- enforce execution policy,
- execute registered stages in order,
- preserve stage results,
- stop when a required policy check fails.

The engine itself does not perform reconnaissance. Concrete discovery,
processing, DNS, endpoint generation, HTTP, infrastructure, and Attack
Surface stages are connected through dedicated pipeline stages.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

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
        """Remove all registered pipeline stages."""

        self._stages.clear()

    def register_default_stages(self) -> None:
        """Register the built-in Project 2 V1 pipeline stages.

        Current default flow:

            DiscoveryStage
                ->
            AssetProcessingStage
                ->
            DNSStage
                ->
            DNSAnalysisStage
                ->
            EndpointStage
                ->
            AttackSurfaceStage

        DNS runs after asset processing because DNS resolution operates
        on canonical HOSTNAME assets.

        DNS analysis runs after DNS because it consumes DNS observations.

        Endpoint generation runs after canonical asset processing and DNS
        analysis. It performs deterministic processing only and does not
        perform network activity.

        Attack Surface assembly runs after endpoint generation because
        it consumes the accumulated reconnaissance state.
        """

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

        discovery_stage = DiscoveryStage()
        asset_processing_stage = AssetProcessingStage()
        dns_stage = DNSStage()
        dns_analysis_stage = DNSAnalysisStage()
        endpoint_stage = EndpointStage()
        attack_surface_stage = AttackSurfaceStage()

        self.add_stage(
            PipelineStage(
                name=discovery_stage.name,
                activity=discovery_stage.activity,
                handler=discovery_stage.execute,
            )
        )

        self.add_stage(
            PipelineStage(
                name=asset_processing_stage.name,
                activity=asset_processing_stage.activity,
                handler=asset_processing_stage.execute,
            )
        )

        self.add_stage(
            PipelineStage(
                name=dns_stage.name,
                activity=dns_stage.activity,
                handler=dns_stage.execute,
            )
        )

        self.add_stage(
            PipelineStage(
                name=dns_analysis_stage.name,
                activity=dns_analysis_stage.activity,
                handler=dns_analysis_stage.execute,
            )
        )

        self.add_stage(
            PipelineStage(
                name=endpoint_stage.name,
                activity=endpoint_stage.activity,
                handler=endpoint_stage.execute,
            )
        )

        self.add_stage(
            PipelineStage(
                name=attack_surface_stage.name,
                activity=attack_surface_stage.activity,
                handler=attack_surface_stage.execute,
            )
        )

    def run(self) -> PipelineResult:
        """Execute all registered stages after authorization checks."""

        if not self._context.is_authorized():
            return PipelineResult(
                completed=False,
                blocked=True,
                error=(
                    "Pipeline execution blocked: target is not authorized "
                    "by ScopeGuard."
                ),
            )

        results: dict[str, Any] = {}

        for stage in self._stages:
            try:
                self._context.execution_policy.require_allowed(
                    stage.activity
                )
            except ExecutionPolicyError as exc:
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
                return PipelineResult(
                    completed=False,
                    blocked=False,
                    stage_results=results,
                    failed_stage=stage.name,
                    error=(
                        f"Pipeline stage '{stage.name}' failed: {exc}"
                    ),
                )

        return PipelineResult(
            completed=True,
            blocked=False,
            stage_results=results,
        )