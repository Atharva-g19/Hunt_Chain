"""Technology fingerprinting pipeline stage for Hunt_Chain Project 2.

This stage interprets already-collected HTTP observations.

It performs no network activity.

V1 responsibilities:
- read HTTP observations and configured endpoints,
- obtain internally retained response bodies from the HTTP stage,
- run deterministic technology fingerprinting,
- preserve technology observations and evidence in pipeline state.

It does not:
- perform HTTP requests,
- perform DNS queries,
- scan ports,
- test vulnerabilities,
- exploit technologies.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunt_chain_recon.models.endpoints import Endpoint
from hunt_chain_recon.models.http import (
    HTTPObservation,
    HTTPObservationState,
)
from hunt_chain_recon.models.technology import (
    Technology,
    TechnologyEvidence,
)
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.pipeline.http import (
    HTTP_RESULTS_STATE_KEY,
    HTTPStageResult,
)
from hunt_chain_recon.policy.execution import ExecutionActivity
from hunt_chain_recon.processing.fingerprinting import (
    FingerprintingError,
    TechnologyFingerprinter,
)


FINGERPRINTING_RESULTS_STATE_KEY = "fingerprinting_results"


class FingerprintingStageError(RuntimeError):
    """Raised when technology fingerprinting cannot complete."""


@dataclass(frozen=True)
class FingerprintingStageResult:
    """Result produced by the technology fingerprinting stage."""

    technologies: list[Technology] = field(default_factory=list)
    evidence: list[TechnologyEvidence] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class FingerprintingStage:
    """Run deterministic technology fingerprinting on HTTP observations."""

    name = "fingerprinting"

    activity = ExecutionActivity.PASSIVE_DISCOVERY

    def __init__(
        self,
        *,
        fingerprinter: TechnologyFingerprinter | None = None,
    ) -> None:
        self.fingerprinter = (
            fingerprinter or TechnologyFingerprinter()
        )

    def execute(
        self,
        context: PipelineContext,
    ) -> FingerprintingStageResult:
        """Fingerprint technologies from existing HTTP observations."""

        context.require_authorized()
        context.execution_policy.require_allowed(
            self.activity
        )

        config = context.config.fingerprinting

        if not config.enabled:
            result = FingerprintingStageResult(
                metadata={
                    "enabled": False,
                    "technology_count": 0,
                    "evidence_count": 0,
                }
            )

            context.set_state(
                FINGERPRINTING_RESULTS_STATE_KEY,
                result,
            )

            return result

        endpoints = self._get_endpoints(
            context
        )

        http_result = context.get_state(
            HTTP_RESULTS_STATE_KEY
        )

        if http_result is None:
            raise FingerprintingStageError(
                "Technology fingerprinting requires HTTP results."
            )

        if isinstance(
            http_result,
            HTTPStageResult,
        ):
            observations = http_result.observations
        else:
            observations = getattr(
                http_result,
                "observations",
                None,
            )

        if observations is None:
            raise FingerprintingStageError(
                "Pipeline state 'http_results' must contain HTTP observations."
            )

        endpoint_by_id = {
            endpoint.id: endpoint
            for endpoint in endpoints
        }

        all_technologies: list[Technology] = []
        all_evidence: list[TechnologyEvidence] = []

        technology_keys: set[tuple[str, object]] = set()
        evidence_keys: set[
            tuple[object, object, str]
        ] = set()

        raw_bodies = self._get_raw_bodies(
            http_result
        )

        for observation in observations:
            if not isinstance(
                observation,
                HTTPObservation,
            ):
                raise FingerprintingStageError(
                    "HTTP results contain an invalid observation."
                )

            # A redirect can include the final response's headers/body.  It
            # remains redirect evidence in the HTTP model, but it is still
            # valid input for non-invasive technology fingerprinting.
            if observation.state not in {
                HTTPObservationState.SUCCESS,
                HTTPObservationState.REDIRECT,
            }:
                continue

            endpoint = endpoint_by_id.get(
                observation.endpoint_id
            )

            if endpoint is None:
                continue

            # Headers are independently useful fingerprint evidence.  A
            # response body is optional runtime enrichment, so its absence
            # must not suppress header-based technology observations.
            body = raw_bodies.get(observation.id, b"")

            try:
                result = self.fingerprinter.fingerprint(
                    endpoint=endpoint,
                    observation_id=observation.id,
                    headers=observation.headers,
                    body=body,
                    response_hash=observation.body_hash,
                )
            except FingerprintingError as exc:
                raise FingerprintingStageError(
                    f"Technology fingerprinting failed for "
                    f"{endpoint.url}: {exc}"
                ) from exc

            technology_id_map: dict[
                object,
                Technology,
            ] = {}

            for technology in result.technologies:
                key = (
                    technology.name.lower(),
                    technology.category,
                )

                existing = next(
                    (
                        item
                        for item in all_technologies
                        if (
                            item.name.lower(),
                            item.category,
                        ) == key
                    ),
                    None,
                )

                if existing is None:
                    all_technologies.append(
                        technology
                    )
                    existing = technology

                technology_id_map[
                    technology.id
                ] = existing

            for evidence in result.evidence:
                technology = technology_id_map.get(
                    evidence.technology_id
                )

                if technology is None:
                    continue

                evidence.technology_id = technology.id

                key = (
                    technology.id,
                    evidence.evidence_type,
                    evidence.rule,
                )

                if key in evidence_keys:
                    continue

                evidence_keys.add(
                    key
                )

                all_evidence.append(
                    evidence
                )

        result = FingerprintingStageResult(
            technologies=all_technologies,
            evidence=all_evidence,
            metadata={
                "enabled": True,
                "observations_processed": len(
                    observations
                ),
                "technology_count": len(
                    all_technologies
                ),
                "evidence_count": len(
                    all_evidence
                ),
                "raw_body_observation_count": len(
                    raw_bodies
                ),
            },
        )

        context.set_state(
            FINGERPRINTING_RESULTS_STATE_KEY,
            result,
        )

        return result

    @staticmethod
    def _get_endpoints(
        context: PipelineContext,
    ) -> list[Endpoint]:
        value = context.get_state(
            "endpoints"
        )

        if value is None:
            return []

        endpoints = getattr(
            value,
            "endpoints",
            value,
        )

        if not isinstance(
            endpoints,
            list,
        ):
            raise FingerprintingStageError(
                "Pipeline state 'endpoints' must contain a list."
            )

        for endpoint in endpoints:
            if not isinstance(
                endpoint,
                Endpoint,
            ):
                raise FingerprintingStageError(
                    "Endpoint results contain an invalid endpoint."
                )

        return list(
            endpoints
        )

    @staticmethod
    def _get_raw_bodies(
        http_result: Any,
    ) -> dict:
        """Return internally retained response bodies.

        Raw response bodies are pipeline-internal data and are never placed
        into the public Attack Surface V1 model.
        """

        raw_bodies = getattr(
            http_result,
            "raw_bodies",
            None,
        )

        if raw_bodies is None:
            provider_results = getattr(
                http_result,
                "provider_results",
                [],
            )

            for provider_result in provider_results:
                metadata = getattr(
                    provider_result,
                    "metadata",
                    {},
                )

                candidate = metadata.get(
                    "_raw_bodies"
                )

                if isinstance(
                    candidate,
                    dict,
                ):
                    return dict(
                        candidate
                    )

            return {}

        if not isinstance(
            raw_bodies,
            dict,
        ):
            raise FingerprintingStageError(
                "HTTP raw bodies must be stored as a dictionary."
            )

        return dict(
            raw_bodies
        )


__all__ = [
    "FINGERPRINTING_RESULTS_STATE_KEY",
    "FingerprintingStage",
    "FingerprintingStageError",
    "FingerprintingStageResult",
]
