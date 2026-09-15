"""Endpoint generation pipeline stage for Hunt_Chain Project 2.

This module converts canonical assets into explicitly configured HTTP/HTTPS
endpoints.

Pipeline flow:

    Canonical Assets
        ->
    Endpoint Generation
        ->
    Endpoint objects
        ->
    HTTP Provider

The stage performs no network activity.

It is responsible for:
- enforcing authorization,
- enforcing execution policy,
- reading canonical assets,
- reading HTTP scheme and port configuration,
- generating deterministic Endpoint models,
- removing duplicate endpoint locations,
- storing endpoints in pipeline state.

It does not:
- perform HTTP requests,
- perform port scanning,
- determine whether an endpoint is reachable,
- fingerprint technologies,
- perform vulnerability testing,
- perform exploitation.

Only explicitly configured ports are used. This is endpoint generation,
not arbitrary port scanning.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from hunt_chain_recon.models.assets import Asset
from hunt_chain_recon.models.endpoints import Endpoint, EndpointScheme
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.policy.execution import ExecutionActivity


ENDPOINTS_STATE_KEY = "endpoints"


class EndpointStageError(RuntimeError):
    """Raised when endpoint generation cannot complete."""


@dataclass(frozen=True)
class EndpointStageResult:
    """Result produced by the endpoint generation stage."""

    endpoints: list[Endpoint]
    assets_processed: int
    endpoints_generated: int
    metadata: dict[str, Any] = field(
        default_factory=dict
    )


class EndpointStage:
    """Generate HTTP/HTTPS endpoints from canonical assets."""

    name = "endpoints"

    # Endpoint generation is deterministic processing and performs no
    # network interaction, so it is permitted in passive-only mode.
    activity = ExecutionActivity.PASSIVE_DISCOVERY

    def execute(
        self,
        context: PipelineContext,
    ) -> EndpointStageResult:
        """Generate endpoints from canonical assets."""

        context.require_authorized()

        context.execution_policy.require_allowed(
            self.activity
        )

        assets = self._get_assets(
            context
        )

        schemes = list(
            context.config.http.schemes
        )

        ports = list(
            context.config.http.ports
        )

        endpoints = self._generate_endpoints(
            assets=assets,
            schemes=schemes,
            ports=ports,
        )

        result = EndpointStageResult(
            endpoints=endpoints,
            assets_processed=len(
                assets
            ),
            endpoints_generated=len(
                endpoints
            ),
            metadata={
                "schemes": schemes,
                "ports": ports,
                "network_activity": False,
            },
        )

        context.set_state(
            ENDPOINTS_STATE_KEY,
            result,
        )

        return result

    @staticmethod
    def _get_assets(
        context: PipelineContext,
    ) -> list[Asset]:
        """Retrieve and validate canonical assets."""

        value = context.get_state(
            "assets"
        )

        if value is None:
            raise EndpointStageError(
                "Endpoint generation requires canonical assets."
            )

        if not isinstance(
            value,
            list,
        ):
            raise EndpointStageError(
                "Pipeline state 'assets' must contain a list."
            )

        for asset in value:
            if not isinstance(
                asset,
                Asset,
            ):
                raise EndpointStageError(
                    "Pipeline state 'assets' contains an invalid Asset."
                )

        return list(
            value
        )

    @classmethod
    def _generate_endpoints(
        cls,
        *,
        assets: list[Asset],
        schemes: list[str],
        ports: list[int],
    ) -> list[Endpoint]:
        """Generate unique endpoints from assets and configured locations."""

        endpoints: list[Endpoint] = []
        seen: set[tuple[str, str]] = set()

        for asset in assets:
            hostname = cls._asset_host(
                asset
            )

            if hostname is None:
                continue

            for scheme in schemes:
                normalized_scheme = cls._normalize_scheme(
                    scheme
                )

                for port in ports:
                    normalized_port = cls._normalize_port(
                        port
                    )

                    url = cls._build_url(
                        scheme=normalized_scheme,
                        hostname=hostname,
                        port=normalized_port,
                    )

                    key = (
                        normalized_scheme.value,
                        url,
                    )

                    if key in seen:
                        continue

                    seen.add(
                        key
                    )

                    endpoints.append(
                        Endpoint(
                            asset_id=asset.id,
                            scheme=normalized_scheme,
                            hostname=hostname,
                            port=normalized_port,
                            url=url,
                            metadata={
                                "source": "configured_http_endpoint",
                                "asset_type": asset.type,
                            },
                        )
                    )

        return endpoints

    @staticmethod
    def _asset_host(
        asset: Asset,
    ) -> str | None:
        """Return the host representation usable by an HTTP endpoint."""

        if asset.type not in {
            "DOMAIN",
            "HOSTNAME",
            "IP_ADDRESS",
        }:
            return None

        value = asset.normalized_value.strip()

        if not value:
            return None

        return value

    @staticmethod
    def _normalize_scheme(
        scheme: str,
    ) -> EndpointScheme:
        """Normalize and validate an HTTP scheme."""

        if isinstance(
            scheme,
            EndpointScheme,
        ):
            return scheme

        if not isinstance(
            scheme,
            str,
        ):
            raise EndpointStageError(
                "HTTP scheme must be a string."
            )

        normalized = scheme.strip().lower()

        try:
            return EndpointScheme(
                normalized
            )
        except ValueError as exc:
            raise EndpointStageError(
                f"Unsupported HTTP scheme: {scheme!r}."
            ) from exc

    @staticmethod
    def _normalize_port(
        port: int,
    ) -> int:
        """Normalize and validate an explicitly configured HTTP port."""

        if isinstance(
            port,
            bool,
        ):
            raise EndpointStageError(
                "HTTP port must be an integer."
            )

        if not isinstance(
            port,
            int,
        ):
            raise EndpointStageError(
                "HTTP port must be an integer."
            )

        if not 1 <= port <= 65535:
            raise EndpointStageError(
                f"HTTP port must be between 1 and 65535: {port}."
            )

        return port

    @staticmethod
    def _build_url(
        *,
        scheme: EndpointScheme,
        hostname: str,
        port: int,
    ) -> str:
        """Build a canonical endpoint URL."""

        host_for_url = hostname

        # IPv6 literals require square brackets in URLs.
        if ":" in hostname and not hostname.startswith("["):
            host_for_url = f"[{hostname}]"

        default_port = (
            (scheme == EndpointScheme.HTTP and port == 80)
            or (
                scheme == EndpointScheme.HTTPS
                and port == 443
            )
        )

        if default_port:
            return f"{scheme.value}://{host_for_url}"

        return f"{scheme.value}://{host_for_url}:{port}"

    @staticmethod
    def endpoint_identity(
        endpoint: Endpoint,
    ) -> tuple[str, str]:
        """Return a stable endpoint identity for testing/correlation."""

        parsed = urlparse(
            endpoint.url
        )

        return (
            parsed.scheme.lower(),
            endpoint.url.lower(),
        )