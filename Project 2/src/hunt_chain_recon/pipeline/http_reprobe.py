"""Bounded second-pass HTTP probing for newly discovered endpoints."""

from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

from hunt_chain_recon.models.endpoints import Endpoint
from hunt_chain_recon.models.http import HTTPObservation
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.pipeline.http import HTTPStageResult
from hunt_chain_recon.pipeline.http_endpoint_merge import (
    HTTP_ENDPOINT_MERGE_STATE_KEY,
)
from hunt_chain_recon.policy.execution import ExecutionActivity
from hunt_chain_recon.providers.base import ProviderResult, ProviderStatus
from hunt_chain_recon.providers.http.client import HTTPObservationProvider


HTTP_REPROBE_RESULTS_STATE_KEY = "http_reprobe_results"


@dataclass
class HTTPReprobeStageResult:
    """Result produced by the bounded second HTTP pass."""

    provider_results: list[ProviderResult[HTTPObservation]] = field(
        default_factory=list
    )
    observations: list[HTTPObservation] = field(
        default_factory=list
    )
    raw_bodies: dict[UUID, bytes] = field(
        default_factory=dict
    )
    metadata: dict[str, object] = field(
        default_factory=dict
    )

    @property
    def status(self) -> ProviderStatus:
        """Return the aggregate status of the reprobe stage."""

        if not self.provider_results:
            return ProviderStatus.SKIPPED

        statuses = {
            result.status
            for result in self.provider_results
        }

        if ProviderStatus.PARTIAL in statuses:
            return ProviderStatus.PARTIAL

        if ProviderStatus.FAILED in statuses:
            if all(
                status in {
                    ProviderStatus.FAILED,
                    ProviderStatus.SKIPPED,
                }
                for status in statuses
            ):
                return ProviderStatus.FAILED

            return ProviderStatus.PARTIAL

        if ProviderStatus.SUCCESS in statuses:
            return ProviderStatus.SUCCESS

        return ProviderStatus.SKIPPED


class HTTPReprobeStage:
    """Probe only endpoints newly discovered from HTTP responses."""

    name = "http_reprobe"
    activity = ExecutionActivity.HTTP_PROBING

    def execute(
        self,
        context: PipelineContext,
    ) -> HTTPReprobeStageResult:
        context.require_authorized()
        context.execution_policy.require_allowed(
            self.activity
        )

        config = context.config.http

        if not config.enabled:
            result = self._skipped(
                reason="HTTP probing disabled by configuration"
            )
            context.set_state(
                HTTP_REPROBE_RESULTS_STATE_KEY,
                result,
            )
            return result

        merge_result = context.get_state(
            HTTP_ENDPOINT_MERGE_STATE_KEY
        )

        if merge_result is None:
            result = self._skipped(
                reason="HTTP endpoint merge result unavailable"
            )
            context.set_state(
                HTTP_REPROBE_RESULTS_STATE_KEY,
                result,
            )
            return result

        endpoints = getattr(
            merge_result,
            "new_endpoints",
            None,
        )

        if not isinstance(endpoints, list):
            raise TypeError(
                "HTTP endpoint merge result must contain "
                "a list of new_endpoints."
            )

        validated: list[Endpoint] = []

        for endpoint in endpoints:
            if not isinstance(endpoint, Endpoint):
                raise TypeError(
                    "HTTP reprobe received a non-Endpoint value."
                )

            validated.append(endpoint)

        if not validated:
            result = self._skipped(
                reason="No newly discovered endpoints require reprobe"
            )
            context.set_state(
                HTTP_REPROBE_RESULTS_STATE_KEY,
                result,
            )
            return result

        provider = HTTPObservationProvider(
            timeout_seconds=config.timeout_seconds,
            follow_redirects=config.follow_redirects,
            max_redirects=config.max_redirects,
            verify_tls=config.verify_tls,
            collect_headers=config.response.collect_headers,
            collect_body_hash=config.response.collect_body_hash,
        )

        with context.politeness.operation():
            provider_result = provider.probe(
                validated
            )

        observations = list(
            provider_result.observations
        )

        raw_bodies = HTTPReprobeStage._get_raw_bodies(
            provider
        )

        result = HTTPReprobeStageResult(
            provider_results=[
                provider_result
            ],
            observations=observations,
            raw_bodies=raw_bodies,
            metadata={
                "enabled": True,
                "endpoint_count": len(validated),
                "observation_count": len(observations),
                "raw_body_observation_count": len(raw_bodies),
                "bounded": True,
                "new_endpoints_only": True,
                "provider": provider.name,
                "provider_version": provider.version,
            },
        )

        context.set_state(
            HTTP_REPROBE_RESULTS_STATE_KEY,
            result,
        )

        return result

    @staticmethod
    def _skipped(
        *,
        reason: str,
    ) -> HTTPReprobeStageResult:
        return HTTPReprobeStageResult(
            provider_results=[
                ProviderResult(
                    status=ProviderStatus.SKIPPED,
                    observations=[],
                    errors=[],
                    provider="http-observer",
                    version="1.0.0",
                    metadata={
                        "reason": reason,
                    },
                )
            ],
            observations=[],
            raw_bodies={},
            metadata={
                "enabled": False,
                "endpoint_count": 0,
                "observation_count": 0,
                "raw_body_observation_count": 0,
                "reason": reason,
                "bounded": True,
                "new_endpoints_only": True,
            },
        )

    @staticmethod
    def _get_raw_bodies(
        provider: HTTPObservationProvider,
    ) -> dict[UUID, bytes]:
        raw_bodies = getattr(
            provider,
            "raw_bodies",
            None,
        )

        if not isinstance(raw_bodies, dict):
            return {}

        validated: dict[UUID, bytes] = {}

        for observation_id, body in raw_bodies.items():
            if not isinstance(observation_id, UUID):
                continue

            if not isinstance(body, bytes):
                continue

            validated[observation_id] = body

        return validated
