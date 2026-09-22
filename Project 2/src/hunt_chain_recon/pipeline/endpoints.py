"""Endpoint generation pipeline stage for Hunt_Chain Project 2."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from hunt_chain_recon.models.assets import Asset
from hunt_chain_recon.models.endpoints import Endpoint, EndpointScheme
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.pipeline.discovery import (
    DISCOVERY_RESULTS_STATE_KEY,
    DiscoveryStageResult,
)
from hunt_chain_recon.policy.execution import ExecutionActivity
from hunt_chain_recon.providers.base import ProviderResult


ENDPOINTS_STATE_KEY = "endpoints"


class EndpointStageError(RuntimeError):
    """Raised when endpoint generation cannot complete."""


@dataclass(frozen=True)
class EndpointStageResult:
    """Result produced by the endpoint generation stage."""

    endpoints: list[Endpoint]
    assets_processed: int
    endpoints_generated: int
    metadata: dict[str, Any] = field(default_factory=dict)


class EndpointStage:
    """Generate configured and discovered HTTP endpoints."""

    name = "endpoints"
    activity = ExecutionActivity.PASSIVE_DISCOVERY

    def execute(
        self,
        context: PipelineContext,
    ) -> EndpointStageResult:
        context.require_authorized()
        context.execution_policy.require_allowed(self.activity)

        assets = self._get_assets(context)

        schemes = [
            self._normalize_scheme(scheme)
            for scheme in context.config.http.schemes
        ]

        ports = [
            self._normalize_port(port)
            for port in context.config.http.ports
        ]

        endpoints = self._generate_endpoints(
            context=context,
            assets=assets,
            schemes=schemes,
            ports=ports,
        )

        result = EndpointStageResult(
            endpoints=endpoints,
            assets_processed=len(assets),
            endpoints_generated=len(endpoints),
            metadata={
                "schemes": [scheme.value for scheme in schemes],
                "ports": ports,
                "network_activity": False,
                "discovered_endpoints_included": True,
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
        value = context.get_state("assets")

        if value is None:
            raise EndpointStageError(
                "Endpoint generation requires canonical assets."
            )

        if not isinstance(value, list):
            raise EndpointStageError(
                "Pipeline state 'assets' must contain a list."
            )

        for asset in value:
            if not isinstance(asset, Asset):
                raise EndpointStageError(
                    "Pipeline state 'assets' contains an invalid Asset."
                )

        return list(value)

    @classmethod
    def _generate_endpoints(
        cls,
        *,
        context: PipelineContext | None = None,
        assets: list[Asset],
        schemes: list[EndpointScheme],
        ports: list[int],
    ) -> list[Endpoint]:
        """Generate configured seed endpoints plus discovered web endpoints."""

        endpoints: list[Endpoint] = []
        seen: set[tuple[str, str, str, str]] = set()

        # --------------------------------------------------------------
        # Determine whether the configured target is an exact URL.
        #
        # URL-scoped assessments must not synthesize hostname-root
        # endpoints. The no-context/unit-test path retains the normal
        # HTTP/HTTPS seed behavior.
        # --------------------------------------------------------------
        target_value = context.target() if context is not None else None

        if target_value:
            target_value = str(target_value).strip()

        exact_url_target = bool(
            target_value
            and target_value.startswith(("http://", "https://"))
        )

        # --------------------------------------------------------------
        # 1. Configured HTTP/HTTPS endpoints.
        #
        # Preserve normal hostname/domain behavior, but do not create
        # implicit root endpoints for an exact URL-scoped target.
        # --------------------------------------------------------------
        if not exact_url_target:
            for asset in assets:
                hostname = cls._asset_host(asset)

                if hostname is None:
                    continue

                for scheme in schemes:
                    normalized_scheme = cls._normalize_scheme(scheme)
                    default_port = cls._default_port(normalized_scheme)

                    if default_port not in ports:
                        continue

                    url = cls._build_url(
                        scheme=normalized_scheme,
                        hostname=hostname,
                        port=default_port,
                    )

                    cls._append_endpoint(
                        endpoints=endpoints,
                        seen=seen,
                        asset=asset,
                        url=url,
                        source="configured_http_endpoint",
                        metadata={
                            "source": "configured_http_endpoint",
                            "asset_type": asset.type,
                        },
                    )

        # --------------------------------------------------------------
        # 2. Explicit authorized URL seed.
        # --------------------------------------------------------------
        if target_value and target_value.startswith(("http://", "https://")):
            cls._append_discovered_url(
                endpoints=endpoints,
                seen=seen,
                assets=assets,
                url=target_value,
                source="configured_target",
                parent_url=None,
                method="GET",
                query_parameters=[],
                metadata={
                    "source": "configured_target",
                    "authorized_seed": True,
                },
            )

        # --------------------------------------------------------------
        # 3. Web discovery observations.
        # --------------------------------------------------------------
        # Web discovery is optional.  The direct unit-test/API path
        # intentionally works without a PipelineContext.
        if context is not None:
            cls._append_web_discovery_endpoints(
                context=context,
                endpoints=endpoints,
                seen=seen,
                assets=assets,
            )

        return endpoints

    @classmethod
    def _append_web_discovery_endpoints(
        cls,
        *,
        context: PipelineContext,
        endpoints: list[Endpoint],
        seen: set[tuple[str, str]],
        assets: list[Asset],
    ) -> None:
        """Convert web discovery observations into Endpoint models."""

        discovery_result = context.get_state(
            DISCOVERY_RESULTS_STATE_KEY
        )

        if discovery_result is None:
            return

        if not isinstance(
            discovery_result,
            DiscoveryStageResult,
        ):
            raise EndpointStageError(
                "Pipeline state contains an invalid discovery result."
            )

        for provider_name, provider_result in (
            discovery_result.provider_results.items()
        ):
            if not isinstance(provider_result, ProviderResult):
                raise EndpointStageError(
                    f"Discovery provider '{provider_name}' returned "
                    "an invalid provider result."
                )

            for observation in provider_result.observations:
                if not isinstance(observation, dict):
                    continue

                url = observation.get("url")

                if not isinstance(url, str) or not url.strip():
                    continue

                cls._append_discovered_url(
                    endpoints=endpoints,
                    seen=seen,
                    assets=assets,
                    url=url,
                    source=str(
                        observation.get(
                            "source",
                            provider_name,
                        )
                    ),
                    parent_url=observation.get("parent_url"),
                    method=str(
                        observation.get(
                            "method",
                            "GET",
                        )
                    ),
                    query_parameters=observation.get(
                        "query_parameters",
                        [],
                    ),
                    metadata={
                        "source": observation.get(
                            "source",
                            provider_name,
                        ),
                        "parent_url": observation.get(
                            "parent_url"
                        ),
                        "discovered_by": provider_name,
                    },
                )

    @classmethod
    def _append_discovered_url(
        cls,
        *,
        endpoints: list[Endpoint],
        seen: set[tuple[str, str, str, str]],
        assets: list[Asset],
        url: str,
        source: str,
        parent_url: str | None,
        method: str,
        query_parameters: list[str] | dict[str, Any] | None,
        metadata: dict[str, Any],
    ) -> None:
        """Convert a discovered URL into a canonical Endpoint."""

        normalized_url = url.strip()

        parsed = urlparse(normalized_url)

        if parsed.scheme.lower() not in {"http", "https"}:
            return

        if not parsed.hostname:
            return

        hostname = parsed.hostname.strip().lower()

        asset = cls._find_asset(
            assets=assets,
            hostname=hostname,
        )

        if asset is None:
            return

        try:
            scheme = EndpointScheme(
                parsed.scheme.lower()
            )
        except ValueError:
            return

        port = parsed.port

        if port is None:
            port = cls._default_port(scheme)

        path = parsed.path or "/"
        normalized_method = method.upper().strip() or "GET"

        parameter_values = cls._extract_query_values(
            parsed.query
        )

        parameter_names = cls._normalize_parameters(
            query_parameters
        )

        for name in parameter_values:
            parameter_names.setdefault(name, None)

        identity = (
            scheme.value,
            hostname,
            str(port),
            f"{normalized_method}:{path}",
        )

        existing_index = next(
            (
                index
                for index, endpoint in enumerate(endpoints)
                if (
                    endpoint.scheme.value,
                    endpoint.hostname,
                    str(endpoint.port),
                    f"{endpoint.method}:{endpoint.path}",
                ) == identity
                and endpoint.asset_id == asset.id
            ),
            None,
        )

        if existing_index is not None:
            existing = endpoints[existing_index]

            merged_parameters = dict(existing.query_parameters)
            merged_parameters.update(parameter_names)

            merged_values = {
                name: list(values)
                for name, values in existing.query_parameter_values.items()
            }

            for name, values in parameter_values.items():
                bucket = merged_values.setdefault(name, [])
                for value in values:
                    if value not in bucket:
                        bucket.append(value)

            existing.query_parameters = merged_parameters
            existing.query_parameter_values = merged_values

            existing_metadata = dict(existing.metadata)
            sources = set(
                existing_metadata.get("sources", [])
            )
            if existing.source:
                sources.add(existing.source)
            if source:
                sources.add(str(source).strip().lower())
            existing_metadata["sources"] = sorted(
                source_name for source_name in sources if source_name
            )

            discovered_from_values = list(
                existing_metadata.get("discovered_from_values", [])
            )
            if parent_url and parent_url not in discovered_from_values:
                discovered_from_values.append(parent_url)
            existing_metadata["discovered_from_values"] = (
                discovered_from_values
            )

            existing.metadata = existing_metadata
            return

        seen.add(identity)

        endpoint_metadata = dict(metadata)

        if parent_url:
            endpoint_metadata["parent_url"] = parent_url

        endpoint_metadata["sources"] = [
            str(source).strip().lower()
        ] if str(source).strip() else []

        endpoints.append(
            Endpoint(
                asset_id=asset.id,
                scheme=scheme,
                hostname=hostname,
                port=port,
                url=(
                    f"{scheme.value}://{hostname}"
                    f"{':' + str(port) if port != cls._default_port(scheme) else ''}"
                    f"{path}"
                ),
                method=normalized_method,
                path=path,
                query_parameters=parameter_names,
                query_parameter_values=parameter_values,
                source=str(source).strip() or "web_discovery",
                discovered_from=parent_url,
                metadata=endpoint_metadata,
            )
        )

    @staticmethod
    def _normalize_parameters(
        parameters: list[str] | dict[str, Any] | None,
    ) -> dict[str, str | None]:
        if isinstance(parameters, dict):
            result: dict[str, str | None] = {}

            for key, value in parameters.items():
                if not isinstance(key, str):
                    continue

                name = key.strip()

                if not name:
                    continue

                result[name] = (
                    value
                    if isinstance(value, str)
                    else None
                )

            return result

        if not isinstance(parameters, list):
            return {}

        result: dict[str, str | None] = {}

        for parameter in parameters:
            if not isinstance(parameter, str):
                continue

            name = parameter.strip()

            if not name:
                continue

            result[name] = None

        return result

    @staticmethod
    def _extract_query_values(
        query: str,
    ) -> dict[str, list[str]]:
        from urllib.parse import parse_qs

        if not query:
            return {}

        parsed = parse_qs(
            query,
            keep_blank_values=True,
        )

        return {
            str(name): [
                str(value)
                for value in values
            ]
            for name, values in parsed.items()
        }

    @staticmethod
    def _find_asset(
        *,
        assets: list[Asset],
        hostname: str,
    ) -> Asset | None:
        target = hostname.strip().lower().rstrip(".")

        for asset in assets:
            value = (
                asset.normalized_value
                or asset.value
            ).strip().lower().rstrip(".")

            if value == target:
                return asset

        return None

    @staticmethod
    def _append_endpoint(
        *,
        endpoints: list[Endpoint],
        seen: set[tuple[str, str]],
        asset: Asset,
        url: str,
        source: str,
        metadata: dict[str, Any],
    ) -> None:
        parsed = urlparse(url)

        identity = (
            parsed.scheme.lower(),
            url.lower(),
        )

        if identity in seen:
            return

        seen.add(identity)

        scheme = EndpointScheme(
            parsed.scheme.lower()
        )

        endpoints.append(
            Endpoint(
                asset_id=asset.id,
                scheme=scheme,
                hostname=parsed.hostname or "",
                port=parsed.port or EndpointStage._default_port(scheme),
                url=url,
                method="GET",
                path=parsed.path or "/",
                query_parameters={},
                source=source,
                discovered_from=None,
                metadata=metadata,
            )
        )

    @staticmethod
    def _default_port(
        scheme: EndpointScheme,
    ) -> int:
        return 80 if scheme is EndpointScheme.HTTP else 443

    @staticmethod
    def _asset_host(
        asset: Asset,
    ) -> str | None:
        if asset.type not in {
            "DOMAIN",
            "HOSTNAME",
            "IP_ADDRESS",
        }:
            return None

        value = (
            asset.normalized_value
            or asset.value
        ).strip()

        if not value:
            return None

        return value

    @staticmethod
    def _normalize_scheme(
        scheme: str,
    ) -> EndpointScheme:
        if isinstance(scheme, EndpointScheme):
            return scheme

        if not isinstance(scheme, str):
            raise EndpointStageError(
                "HTTP scheme must be a string."
            )

        try:
            return EndpointScheme(
                scheme.strip().lower()
            )
        except ValueError as exc:
            raise EndpointStageError(
                f"Unsupported HTTP scheme: {scheme!r}."
            ) from exc

    @staticmethod
    def _normalize_port(
        port: int,
    ) -> int:
        if isinstance(port, bool) or not isinstance(port, int):
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
        host_for_url = hostname

        if ":" in hostname and not hostname.startswith("["):
            host_for_url = f"[{hostname}]"

        default_port = (
            scheme is EndpointScheme.HTTP
            and port == 80
        ) or (
            scheme is EndpointScheme.HTTPS
            and port == 443
        )

        if default_port:
            return f"{scheme.value}://{host_for_url}"

        return f"{scheme.value}://{host_for_url}:{port}"

    @staticmethod
    def endpoint_identity(
        endpoint: Endpoint,
    ) -> tuple[str, str]:
        parsed = urlparse(endpoint.url)

        return (
            parsed.scheme.lower(),
            endpoint.url.lower(),
        )
