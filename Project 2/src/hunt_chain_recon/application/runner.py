"""Application orchestration for Hunt_Chain Project 2."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from hunt_chain_recon.authorization.models import AuthorizationResult
from hunt_chain_recon.config.models import ReconConfig
from hunt_chain_recon.models.attack_surface import AttackSurface
from hunt_chain_recon.models.run import ReconRun
from hunt_chain_recon.output.manager import OutputManager, OutputResult
from hunt_chain_recon.pipeline.attack_surface import (
    AttackSurfaceStageResult,
)
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.pipeline.engine import PipelineEngine
from hunt_chain_recon.policy.execution import ExecutionPolicy
from hunt_chain_recon.policy.politeness import PolitenessController


class ApplicationRunnerError(Exception):
    """Raised when Project 2 application orchestration fails."""


@dataclass(frozen=True)
class ApplicationResult:
    """Result of a Project 2 application run."""

    pipeline_completed: bool
    pipeline_blocked: bool
    attack_surface: AttackSurface | None
    output: OutputResult | None


class ApplicationRunner:
    """Coordinate Project 2 pipeline execution and output generation."""

    def __init__(
        self,
        *,
        output_manager: OutputManager | None = None,
    ) -> None:
        self._output_manager = (
            output_manager
            if output_manager is not None
            else OutputManager()
        )

    def run(
        self,
        config: ReconConfig,
        authorization: AuthorizationResult,
        *,
        output_directory: str | Path | None = None,
        json_enabled: bool = True,
        report_enabled: bool = True,
    ) -> ApplicationResult:
        """Execute the Project 2 pipeline."""

        if not isinstance(config, ReconConfig):
            raise TypeError(
                "config must be a ReconConfig instance."
            )

        if not isinstance(
            authorization,
            AuthorizationResult,
        ):
            raise TypeError(
                "authorization must be an AuthorizationResult instance."
            )

        configured_target = (
            config.target.value.strip().lower().rstrip(".")
        )

        if authorization.target != configured_target:
            raise ApplicationRunnerError(
                "Authorization target does not match configured target."
            )

        execution_policy = ExecutionPolicy(
            config.execution
        )

        politeness = PolitenessController(
            config.politeness
        )

        run = ReconRun.create(
            target=config.target.value,
            execution_mode=config.execution.mode,
        )

        context = PipelineContext(
            config=config,
            authorization=authorization,
            execution_policy=execution_policy,
            politeness=politeness,
            run=run,
        )

        engine = PipelineEngine(
            context,
            include_default_stages=True,
        )

        pipeline_result = engine.run()

        if pipeline_result.blocked:
            return ApplicationResult(
                pipeline_completed=False,
                pipeline_blocked=True,
                attack_surface=None,
                output=None,
            )

        if not pipeline_result.completed:
            raise ApplicationRunnerError(
                "Project 2 pipeline failed."
            )

        stage_result = pipeline_result.stage_results.get(
            "attack_surface"
        )

        if not isinstance(
            stage_result,
            AttackSurfaceStageResult,
        ):
            raise ApplicationRunnerError(
                "Pipeline completed without producing "
                "an AttackSurface stage result."
            )

        attack_surface = stage_result.attack_surface

        if not isinstance(
            attack_surface,
            AttackSurface,
        ):
            raise ApplicationRunnerError(
                "Attack Surface stage produced an invalid "
                "AttackSurface."
            )

        output_result: OutputResult | None = None

        if output_directory is not None:
            output_result = self._output_manager.write(
                attack_surface,
                output_directory,
                json_enabled=json_enabled,
                report_enabled=report_enabled,
            )

        return ApplicationResult(
            pipeline_completed=True,
            pipeline_blocked=False,
            attack_surface=attack_surface,
            output=output_result,
        )