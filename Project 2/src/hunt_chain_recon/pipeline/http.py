from __future__ import annotations

from dataclasses import dataclass, field
from uuid import UUID

from hunt_chain_recon.models.endpoints import Endpoint
from hunt_chain_recon.models.http import HTTPObservation
from hunt_chain_recon.pipeline.engine import PipelineStage
from hunt_chain_recon.policy.execution import ExecutionActivity
from hunt_chain_recon.providers.base import ProviderResult, ProviderStatus
from hunt_chain_recon.providers.http.client import HTTPObservationProvider


HTTP_RESULTS_STATE_KEY = "http_results"
ENDPOINTS_STATE_KEY = "endpoints"


@dataclass
class HTTPStageResult:
    """Result produced by the HTTP probing stage."""

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
        """Return the aggregate status of the HTTP stage."""

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


class HTTPStage(PipelineStage):
    """Probe configured HTTP/HTTPS endpoints.

    This stage performs application-layer observation only.

    It does not perform:

    - vulnerability scanning,
    - exploitation,
    - authentication attacks,
    - credential attacks,
    - technology conclusions.
    """

    name = "http"
    activity = ExecutionActivity.HTTP_PROBING

    def __init__(self) -> None:
        super().__init__(
            name=self.name,
            activity=self.activity,
            handler=self.execute,
        )

    def execute(self, context) -> HTTPStageResult:
        """Execute HTTP probing for the endpoints in pipeline state."""

        context.require_authorized()
        context.execution_policy.require_allowed(
            self.activity
        )

        config = context.config.http

        if not config.enabled:
            result = HTTPStageResult(
                provider_results=[
                    ProviderResult(
                        status=ProviderStatus.SKIPPED,
                        observations=[],
                        errors=[],
                        provider="http-observer",
                        version="1.0.0",
                        metadata={
                            "reason": (
                                "HTTP probing disabled by configuration"
                            ),
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
                },
            )

            context.set_state(
                HTTP_RESULTS_STATE_KEY,
                result,
            )

            return result

        endpoints = self._get_endpoints(
            context
        )

        if not endpoints:
            result = HTTPStageResult(
                provider_results=[],
                observations=[],
                raw_bodies={},
                metadata={
                    "enabled": True,
                    "endpoint_count": 0,
                    "observation_count": 0,
                    "raw_body_observation_count": 0,
                    "reason": "No endpoints available",
                },
            )

            context.set_state(
                HTTP_RESULTS_STATE_KEY,
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
                endpoints
            )

        observations = list(
            provider_result.observations
        )

        raw_bodies = self._get_raw_bodies(
            provider
        )

        result = HTTPStageResult(
            provider_results=[
                provider_result
            ],
            observations=observations,
            raw_bodies=raw_bodies,
            metadata={
                "enabled": True,
                "endpoint_count": len(
                    endpoints
                ),
                "observation_count": len(
                    observations
                ),
                "raw_body_observation_count": len(
                    raw_bodies
                ),
                "provider": provider.name,
                "provider_version": provider.version,
            },
        )

        context.set_state(
            HTTP_RESULTS_STATE_KEY,
            result,
        )

        return result

    def run(
        self,
        context,
    ) -> HTTPStageResult:
        """Compatibility alias for direct stage execution tests."""

        return self.execute(
            context
        )

    @staticmethod
    def _get_raw_bodies(
        provider: HTTPObservationProvider,
    ) -> dict[UUID, bytes]:
        """Return internally retained response bodies when available.

        Runtime raw bodies are optional enrichment. A provider implementation
        or test double that does not expose them must not invalidate an
        otherwise successful HTTP observation.
        """

        raw_bodies = getattr(
            provider,
            "raw_bodies",
            None,
        )

        if not isinstance(
            raw_bodies,
            dict,
        ):
            return {}

        validated: dict[UUID, bytes] = {}

        for observation_id, body in raw_bodies.items():
            if not isinstance(
                observation_id,
                UUID,
            ):
                continue

            if not isinstance(
                body,
                bytes,
            ):
                continue

            validated[
                observation_id
            ] = body

        return validated

    @staticmethod
    def _get_endpoints(
        context,
    ) -> list[Endpoint]:
        """Read and validate endpoints from pipeline state."""

        state_value = context.get_state(
            ENDPOINTS_STATE_KEY
        )

        if state_value is None:
            return []

        if isinstance(
            state_value,
            list,
        ):
            endpoints = state_value
        else:
            endpoints = getattr(
                state_value,
                "endpoints",
                None,
            )

            if endpoints is None:
                raise TypeError(
                    "Pipeline state 'endpoints' must contain "
                    "a list of Endpoint objects or an object "
                    "with an 'endpoints' attribute."
                )

        validated: list[Endpoint] = []

        for endpoint in endpoints:
            if not isinstance(
                endpoint,
                Endpoint,
            ):
                raise TypeError(
                    "Pipeline state 'endpoints' contains "
                    "a non-Endpoint value."
                )

            validated.append(
                endpoint
            )

        return validated