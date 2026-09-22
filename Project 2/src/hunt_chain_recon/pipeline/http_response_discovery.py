"""Discover additional endpoints from HTTP response metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlparse

from hunt_chain_recon.models.endpoints import Endpoint
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.pipeline.endpoints import EndpointStage
from hunt_chain_recon.pipeline.http import HTTP_RESULTS_STATE_KEY
from hunt_chain_recon.policy.execution import ExecutionActivity


HTTP_RESPONSE_DISCOVERY_STATE_KEY = "http_response_discovery"


class HTTPResponseDiscoveryError(RuntimeError):
    """Raised when HTTP response discovery cannot complete."""


@dataclass(frozen=True)
class HTTPResponseDiscoveryResult:
    """Result of endpoint discovery from HTTP response metadata."""

    endpoints: list[Endpoint]
    source_observations: int
    endpoints_discovered: int
    metadata: dict[str, Any] = field(default_factory=dict)


class HTTPResponseDiscoveryStage:
    """Convert HTTP response-discovery metadata into endpoints."""

    name = "http_response_discovery"
    activity = ExecutionActivity.PASSIVE_DISCOVERY

    def execute(
        self,
        context: PipelineContext,
    ) -> HTTPResponseDiscoveryResult:
        context.require_authorized()

        http_result = context.get_state(HTTP_RESULTS_STATE_KEY)

        if http_result is None:
            raise HTTPResponseDiscoveryError(
                "HTTP response discovery requires HTTP results."
            )

        observations = getattr(http_result, "observations", None)

        if not isinstance(observations, list):
            raise HTTPResponseDiscoveryError(
                "HTTP results contain no valid observations."
            )

        assets = context.get_state("assets")

        if not isinstance(assets, list):
            raise HTTPResponseDiscoveryError(
                "HTTP response discovery requires canonical assets."
            )

        endpoints: list[Endpoint] = []
        seen: set[tuple[str, str]] = set()
        source_observations = 0

        for observation in observations:
            metadata = getattr(observation, "metadata", None)

            if not isinstance(metadata, dict):
                continue

            discoveries = metadata.get("response_discovery", [])

            if not isinstance(discoveries, list):
                continue

            source_url = self._observation_url(observation)

            if not source_url:
                continue

            source_observations += 1

            for item in discoveries:
                if not isinstance(item, dict):
                    continue

                raw_url = item.get("url")

                if not isinstance(raw_url, str) or not raw_url.strip():
                    continue

                resolved_url = urljoin(source_url, raw_url.strip())

                if not self._is_http_url(resolved_url):
                    continue

                if not self._same_origin(source_url, resolved_url):
                    continue

                endpoint = self._build_endpoint(
                    context=context,
                    assets=assets,
                    url=resolved_url,
                    source=str(
                        item.get(
                            "source",
                            "http_response",
                        )
                    ),
                    parent_url=source_url,
                    method=str(
                        item.get(
                            "method",
                            "GET",
                        )
                    ),
                )

                if endpoint is None:
                    continue

                identity = EndpointStage.endpoint_identity(endpoint)

                if identity in seen:
                    continue

                seen.add(identity)
                endpoints.append(endpoint)

        result = HTTPResponseDiscoveryResult(
            endpoints=endpoints,
            source_observations=source_observations,
            endpoints_discovered=len(endpoints),
            metadata={
                "network_activity": False,
                "same_origin_only": True,
                "bounded": True,
            },
        )

        context.set_state(
            HTTP_RESPONSE_DISCOVERY_STATE_KEY,
            result,
        )

        return result

    @staticmethod
    def _observation_url(observation: Any) -> str | None:
        metadata = getattr(observation, "metadata", None)

        if isinstance(metadata, dict):
            for key in ("final_url", "url"):
                value = metadata.get(key)

                if isinstance(value, str) and value.strip():
                    return value.strip()

        value = getattr(observation, "url", None)

        if isinstance(value, str) and value.strip():
            return value.strip()

        return None

    @staticmethod
    def _is_http_url(url: str) -> bool:
        parsed = urlparse(url)

        return (
            parsed.scheme.lower() in {"http", "https"}
            and bool(parsed.hostname)
        )

    @staticmethod
    def _same_origin(
        source_url: str,
        candidate_url: str,
    ) -> bool:
        source = urlparse(source_url)
        candidate = urlparse(candidate_url)

        source_scheme = source.scheme.lower()
        candidate_scheme = candidate.scheme.lower()

        if source_scheme != candidate_scheme:
            return False

        source_host = (source.hostname or "").lower().rstrip(".")
        candidate_host = (candidate.hostname or "").lower().rstrip(".")

        if source_host != candidate_host:
            return False

        source_port = source.port or (
            443 if source_scheme == "https" else 80
        )
        candidate_port = candidate.port or (
            443 if candidate_scheme == "https" else 80
        )

        return source_port == candidate_port

    @staticmethod
    def _build_endpoint(
        *,
        context: PipelineContext,
        assets: list[Any],
        url: str,
        source: str,
        parent_url: str,
        method: str,
    ) -> Endpoint | None:
        parsed = urlparse(url)

        hostname = parsed.hostname

        if not hostname:
            return None

        asset = EndpointStage._find_asset(
            assets=assets,
            hostname=hostname,
        )

        if asset is None:
            return None

        scheme = parsed.scheme.lower()

        if scheme not in {"http", "https"}:
            return None

        try:
            endpoint_scheme = EndpointStage._normalize_scheme(scheme)
        except Exception:
            return None

        port = parsed.port or EndpointStage._default_port(
            endpoint_scheme
        )

        normalized_method = method.strip().upper() or "GET"

        return Endpoint(
            asset_id=asset.id,
            scheme=endpoint_scheme,
            hostname=hostname.lower(),
            port=port,
            url=url,
            method=normalized_method,
            path=parsed.path or "/",
            query_parameters=EndpointStage._normalize_parameters(
                {
                    key: None
                    for key in (
                        parsed.query.split("&")
                        if parsed.query
                        else []
                    )
                    if key
                }
            ),
            source=source.strip() or "http_response",
            discovered_from=parent_url,
            metadata={
                "source": source.strip() or "http_response",
                "parent_url": parent_url,
                "discovered_by": "http_response",
            },
        )
