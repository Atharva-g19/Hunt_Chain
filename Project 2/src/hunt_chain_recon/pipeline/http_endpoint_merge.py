"""Merge HTTP-response-discovered endpoints into the endpoint inventory."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunt_chain_recon.models.endpoints import Endpoint
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.pipeline.endpoints import ENDPOINTS_STATE_KEY
from hunt_chain_recon.pipeline.http_response_discovery import (
    HTTP_RESPONSE_DISCOVERY_STATE_KEY,
)
from hunt_chain_recon.policy.execution import ExecutionActivity


HTTP_ENDPOINT_MERGE_STATE_KEY = "http_endpoint_merge"


class HTTPEndpointMergeError(RuntimeError):
    """Raised when endpoint merging cannot complete."""


@dataclass(frozen=True)
class HTTPEndpointMergeResult:
    """Result of merging HTTP-response-discovered endpoints."""

    endpoints: list[Endpoint]
    new_endpoints: list[Endpoint]
    existing_count: int
    discovered_count: int
    metadata: dict[str, Any] = field(default_factory=dict)


class HTTPEndpointMergeStage:
    """Merge newly discovered HTTP endpoints without duplication."""

    name = "http_endpoint_merge"
    activity = ExecutionActivity.PASSIVE_DISCOVERY

    def execute(
        self,
        context: PipelineContext,
    ) -> HTTPEndpointMergeResult:
        context.require_authorized()

        state_value = context.get_state(ENDPOINTS_STATE_KEY)

        if state_value is None:
            raise HTTPEndpointMergeError(
                "Endpoint merge requires the endpoint inventory."
            )

        if isinstance(state_value, list):
            existing = state_value
        else:
            existing = getattr(
                state_value,
                "endpoints",
                None,
            )

            if existing is None:
                raise HTTPEndpointMergeError(
                    "Pipeline state 'endpoints' must contain "
                    "a list of Endpoint objects or an object "
                    "with an 'endpoints' attribute."
                )

        if not isinstance(existing, list):
            raise HTTPEndpointMergeError(
                "Pipeline endpoint inventory must be a list."
            )

        for endpoint in existing:
            if not isinstance(endpoint, Endpoint):
                raise HTTPEndpointMergeError(
                    "Endpoint inventory contains an invalid Endpoint."
                )

        discovery_result = context.get_state(
            HTTP_RESPONSE_DISCOVERY_STATE_KEY
        )

        discovered: list[Endpoint] = []

        if discovery_result is not None:
            candidate_endpoints = getattr(
                discovery_result,
                "endpoints",
                None,
            )

            if not isinstance(candidate_endpoints, list):
                raise HTTPEndpointMergeError(
                    "HTTP response discovery returned invalid endpoints."
                )

            discovered = [
                endpoint
                for endpoint in candidate_endpoints
                if isinstance(endpoint, Endpoint)
            ]

        merged = list(existing)
        new_endpoints: list[Endpoint] = []

        seen = {
            self._identity(endpoint)
            for endpoint in existing
        }

        for endpoint in discovered:
            identity = self._identity(endpoint)

            if identity in seen:
                continue

            seen.add(identity)
            merged.append(endpoint)
            new_endpoints.append(endpoint)

        result = HTTPEndpointMergeResult(
            endpoints=merged,
            new_endpoints=new_endpoints,
            existing_count=len(existing),
            discovered_count=len(discovered),
            metadata={
                "network_activity": False,
                "deduplicated": True,
            },
        )

        context.set_state(
            ENDPOINTS_STATE_KEY,
            merged,
        )

        context.set_state(
            HTTP_ENDPOINT_MERGE_STATE_KEY,
            result,
        )

        return result

    @staticmethod
    def _identity(
        endpoint: Endpoint,
    ) -> tuple[str, str, str]:
        return (
            endpoint.method.upper(),
            endpoint.url.lower(),
            endpoint.path,
        )
