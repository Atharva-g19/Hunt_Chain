"""Attack Surface pipeline stage for Hunt_Chain Project 2."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunt_chain_recon.models.attack_surface import AttackSurface
from hunt_chain_recon.models.assets import Asset
from hunt_chain_recon.models.dns import DNSObservation
from hunt_chain_recon.models.endpoints import Endpoint
from hunt_chain_recon.models.http import HTTPObservation
from hunt_chain_recon.models.indicators import Indicator
from hunt_chain_recon.models.run import ReconRun
from hunt_chain_recon.models.services import Service
from hunt_chain_recon.models.technology import (
    Technology,
    TechnologyEvidence,
)
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.pipeline.dns import (
    DNS_RESULTS_STATE_KEY,
    DNSStageResult,
)
from hunt_chain_recon.pipeline.dns_analysis import (
    DNS_ANALYSIS_RESULTS_STATE_KEY,
    DNSAnalysisStageResult,
)
from hunt_chain_recon.pipeline.endpoints import (
    ENDPOINTS_STATE_KEY,
    EndpointStageResult,
)
from hunt_chain_recon.pipeline.fingerprinting import (
    FINGERPRINTING_RESULTS_STATE_KEY,
    FingerprintingStageResult,
)
from hunt_chain_recon.pipeline.http import (
    HTTP_RESULTS_STATE_KEY,
    HTTPStageResult,
)
from hunt_chain_recon.pipeline.infrastructure import (
    INFRASTRUCTURE_RESULTS_STATE_KEY,
)
from hunt_chain_recon.policy.execution import ExecutionActivity
from hunt_chain_recon.processing.attack_surface import (
    AttackSurfaceBuilder,
    AttackSurfaceBuilderError,
)
from hunt_chain_recon.processing.correlation import (
    CorrelationEngine,
    CorrelationError,
)


ATTACK_SURFACE_STATE_KEY = "attack_surface"


class AttackSurfaceStageError(RuntimeError):
    """Raised when the Attack Surface stage cannot complete."""


@dataclass(frozen=True)
class AttackSurfaceStageResult:
    """Result produced by the Attack Surface pipeline stage."""

    attack_surface: AttackSurface
    relationships_created: int
    assets_included: int
    indicators_included: int
    endpoints_included: int
    http_observations_included: int
    technologies_included: int = 0
    technology_evidence_included: int = 0
    metadata: dict[str, Any] = field(
        default_factory=dict
    )


class AttackSurfaceStage:
    """Assemble pipeline observations into Attack Surface Model V1."""

    name = "attack_surface"
    activity = ExecutionActivity.PASSIVE_DISCOVERY

    def __init__(
        self,
        *,
        correlation_engine: CorrelationEngine | None = None,
        builder: AttackSurfaceBuilder | None = None,
    ) -> None:
        self._correlation_engine = (
            correlation_engine or CorrelationEngine()
        )

        self._builder = (
            builder or AttackSurfaceBuilder()
        )

    @property
    def correlation_engine(self) -> CorrelationEngine:
        """Return the configured correlation engine."""

        return self._correlation_engine

    @property
    def builder(self) -> AttackSurfaceBuilder:
        """Return the configured Attack Surface builder."""

        return self._builder

    def execute(
        self,
        context: PipelineContext,
    ) -> AttackSurfaceStageResult:
        """Build the Attack Surface from existing pipeline state."""

        context.require_authorized()

        context.execution_policy.require_allowed(
            self.activity
        )

        assets = self._get_assets(
            context
        )

        dns_observations = self._get_dns_observations(
            context
        )

        indicators = self._get_indicators(
            context
        )

        endpoints = self._get_endpoints(
            context
        )

        http_observations = self._get_http_observations(
            context
        )

        technologies, technology_evidence = (
            self._get_fingerprinting_results(
                context
            )
        )

        services = self._get_services(
            context
        )

        run = self._get_run(
            context
        )

        try:
            relationships = self._correlation_engine.correlate(
                assets=assets,
                dns_observations=dns_observations,
                services=services,
                endpoints=endpoints,
                http_observations=http_observations,
                technologies=technologies,
                technology_evidence=technology_evidence,
                indicators=indicators,
            )
        except CorrelationError as exc:
            raise AttackSurfaceStageError(
                f"Attack Surface correlation failed: {exc}"
            ) from exc

        try:
            attack_surface = self._builder.build(
                run=run,
                target=context.config.target,
                authorization=context.config.authorization,
                execution=context.config.execution,
                assets=assets,
                dns_observations=dns_observations,
                services=services,
                endpoints=endpoints,
                http_observations=http_observations,
                technologies=technologies,
                technology_evidence=technology_evidence,
                indicators=indicators,
                relationships=relationships,
                metadata=self._build_metadata(
                    context=context,
                    assets=assets,
                    dns_observations=dns_observations,
                    endpoints=endpoints,
                    http_observations=http_observations,
                    technologies=technologies,
                    technology_evidence=technology_evidence,
                    indicators=indicators,
                    services=services,
                ),
            )
        except (
            AttackSurfaceBuilderError,
            ValueError,
        ) as exc:
            raise AttackSurfaceStageError(
                f"Attack Surface construction failed: {exc}"
            ) from exc

        result = AttackSurfaceStageResult(
            attack_surface=attack_surface,
            relationships_created=len(
                relationships
            ),
            assets_included=len(
                assets
            ),
            indicators_included=len(
                indicators
            ),
            endpoints_included=len(
                endpoints
            ),
            http_observations_included=len(
                http_observations
            ),
            technologies_included=len(
                technologies
            ),
            technology_evidence_included=len(
                technology_evidence
            ),
            metadata={
                "schema_version": "v1",
                "dns_observations_included": len(
                    dns_observations
                ),
                "services_included": len(
                    services
                ),
                "endpoints_included": len(
                    endpoints
                ),
                "http_observations_included": len(
                    http_observations
                ),
                "technologies_included": len(
                    technologies
                ),
                "technology_evidence_included": len(
                    technology_evidence
                ),
                "relationships_created": len(
                    relationships
                ),
            },
        )

        context.set_state(
            ATTACK_SURFACE_STATE_KEY,
            result,
        )

        return result

    @staticmethod
    def _get_assets(
        context: PipelineContext,
    ) -> list[Asset]:
        value = context.get_state(
            "assets"
        )

        if value is None:
            raise AttackSurfaceStageError(
                "Attack Surface construction requires canonical assets."
            )

        if not isinstance(
            value,
            list,
        ):
            raise AttackSurfaceStageError(
                "Pipeline state 'assets' must contain a list."
            )

        for asset in value:
            if not isinstance(
                asset,
                Asset,
            ):
                raise AttackSurfaceStageError(
                    "Pipeline state 'assets' contains an invalid Asset."
                )

        return list(
            value
        )

    @staticmethod
    def _get_dns_observations(
        context: PipelineContext,
    ) -> list[DNSObservation]:
        value = context.get_state(
            DNS_RESULTS_STATE_KEY
        )

        if value is None:
            return []

        if not isinstance(
            value,
            DNSStageResult,
        ):
            raise AttackSurfaceStageError(
                "Pipeline state 'dns_results' must contain "
                "a DNSStageResult."
            )

        return list(
            value.observations
        )

    @staticmethod
    def _get_indicators(
        context: PipelineContext,
    ) -> list[Indicator]:
        value = context.get_state(
            DNS_ANALYSIS_RESULTS_STATE_KEY
        )

        if value is None:
            return []

        if not isinstance(
            value,
            DNSAnalysisStageResult,
        ):
            raise AttackSurfaceStageError(
                "Pipeline state 'dns_analysis_results' must contain "
                "a DNSAnalysisStageResult."
            )

        return list(
            value.indicators
        )

    @staticmethod
    def _get_endpoints(
        context: PipelineContext,
    ) -> list[Endpoint]:
        value = context.get_state(
            ENDPOINTS_STATE_KEY
        )

        if value is None:
            return []

        if isinstance(
            value,
            EndpointStageResult,
        ):
            endpoints = value.endpoints
        elif isinstance(
            value,
            list,
        ):
            endpoints = value
        else:
            endpoints = getattr(
                value,
                "endpoints",
                None,
            )

        if endpoints is None:
            raise AttackSurfaceStageError(
                "Pipeline state 'endpoints' has no endpoints."
            )

        for endpoint in endpoints:
            if not isinstance(
                endpoint,
                Endpoint,
            ):
                raise AttackSurfaceStageError(
                    "Endpoint results contain an invalid endpoint."
                )

        return list(
            endpoints
        )

    @staticmethod
    def _get_http_observations(
        context: PipelineContext,
    ) -> list[HTTPObservation]:
        value = context.get_state(
            HTTP_RESULTS_STATE_KEY
        )

        if value is None:
            return []

        if isinstance(
            value,
            HTTPStageResult,
        ):
            observations = value.observations
        elif isinstance(
            value,
            list,
        ):
            observations = value
        else:
            observations = getattr(
                value,
                "observations",
                None,
            )

        if observations is None:
            raise AttackSurfaceStageError(
                "Pipeline state 'http_results' has no observations."
            )

        for observation in observations:
            if not isinstance(
                observation,
                HTTPObservation,
            ):
                raise AttackSurfaceStageError(
                    "HTTP results contain an invalid observation."
                )

        return list(
            observations
        )

    @staticmethod
    def _get_fingerprinting_results(
        context: PipelineContext,
    ) -> tuple[
        list[Technology],
        list[TechnologyEvidence],
    ]:
        value = context.get_state(
            FINGERPRINTING_RESULTS_STATE_KEY
        )

        if value is None:
            return [], []

        if not isinstance(
            value,
            FingerprintingStageResult,
        ):
            raise AttackSurfaceStageError(
                "Pipeline state 'fingerprinting_results' must contain "
                "a FingerprintingStageResult."
            )

        for technology in value.technologies:
            if not isinstance(
                technology,
                Technology,
            ):
                raise AttackSurfaceStageError(
                    "Fingerprinting results contain an invalid technology."
                )

        for evidence in value.evidence:
            if not isinstance(
                evidence,
                TechnologyEvidence,
            ):
                raise AttackSurfaceStageError(
                    "Fingerprinting results contain invalid evidence."
                )

        return (
            list(value.technologies),
            list(value.evidence),
        )

    @staticmethod
    def _get_services(
        context: PipelineContext,
    ) -> list[Service]:
        """Retrieve service observations when a stage provides them."""

        value = context.get_state(
            "services"
        )

        if value is None:
            return []

        services = getattr(
            value,
            "services",
            value,
        )

        if not isinstance(
            services,
            list,
        ):
            raise AttackSurfaceStageError(
                "Pipeline state 'services' must contain a list."
            )

        for service in services:
            if not isinstance(
                service,
                Service,
            ):
                raise AttackSurfaceStageError(
                    "Service results contain an invalid service."
                )

        return list(
            services
        )

    @staticmethod
    def _get_run(
        context: PipelineContext,
    ) -> ReconRun:
        run = context.run

        if not isinstance(
            run,
            ReconRun,
        ):
            raise AttackSurfaceStageError(
                "Pipeline context contains an invalid ReconRun."
            )

        return run

    @staticmethod
    def _build_metadata(
        *,
        context: PipelineContext,
        assets: list[Asset],
        dns_observations: list[DNSObservation],
        services: list[Service],
        endpoints: list[Endpoint],
        http_observations: list[HTTPObservation],
        technologies: list[Technology],
        technology_evidence: list[TechnologyEvidence],
        indicators: list[Indicator],
    ) -> dict[str, Any]:
        return {
            "target": context.target(),
            "execution_mode": context.config.execution.mode,
            "asset_count": len(
                assets
            ),
            "dns_observation_count": len(
                dns_observations
            ),
            "service_count": len(
                services
            ),
            "endpoint_count": len(
                endpoints
            ),
            "http_observation_count": len(
                http_observations
            ),
            "technology_count": len(
                technologies
            ),
            "technology_evidence_count": len(
                technology_evidence
            ),
            "indicator_count": len(
                indicators
            ),
            "attack_surface_schema": "v1",
        }


__all__ = [
    "ATTACK_SURFACE_STATE_KEY",
    "AttackSurfaceStage",
    "AttackSurfaceStageError",
    "AttackSurfaceStageResult",
]