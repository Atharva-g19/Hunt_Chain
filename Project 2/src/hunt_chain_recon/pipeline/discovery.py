"""Discovery pipeline stage for Hunt_Chain Project 2.

This module connects configured discovery providers to the Project 2
pipeline.

The discovery stage is responsible for:
- checking passive discovery permission,
- resolving configured discovery providers,
- executing providers,
- validating provider results,
- preserving provider results,
- storing discovery observations in pipeline state.

Provider-level SUCCESS, PARTIAL, FAILED, and SKIPPED results are preserved.
A provider failure is not automatically treated as a pipeline failure.

The stage does not normalize, deduplicate, resolve DNS, probe HTTP/HTTPS,
fingerprint technologies, or perform vulnerability testing.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.policy.execution import ExecutionActivity
from hunt_chain_recon.providers.base import ProviderResult
from hunt_chain_recon.providers.discovery.registry import (
    DiscoveryProviderError,
    DiscoveryProviderRegistry,
)


DISCOVERY_RESULTS_STATE_KEY = "discovery_results"


class DiscoveryStageError(Exception):
    """Raised when the discovery stage cannot execute correctly."""


@dataclass(frozen=True)
class DiscoveryStageResult:
    """Results collected from all enabled discovery providers."""

    provider_results: dict[str, ProviderResult[Any]]

    @property
    def successful_providers(self) -> tuple[str, ...]:
        """Return providers that completed successfully."""
        return tuple(
            name
            for name, result in self.provider_results.items()
            if result.status.value == "SUCCESS"
        )

    @property
    def partial_providers(self) -> tuple[str, ...]:
        """Return providers that completed partially."""
        return tuple(
            name
            for name, result in self.provider_results.items()
            if result.status.value == "PARTIAL"
        )

    @property
    def failed_providers(self) -> tuple[str, ...]:
        """Return providers that reported a controlled failure."""
        return tuple(
            name
            for name, result in self.provider_results.items()
            if result.status.value == "FAILED"
        )

    @property
    def skipped_providers(self) -> tuple[str, ...]:
        """Return providers that were skipped."""
        return tuple(
            name
            for name, result in self.provider_results.items()
            if result.status.value == "SKIPPED"
        )

    @property
    def has_failures(self) -> bool:
        """Return whether any provider reported FAILED."""
        return bool(self.failed_providers)


class DiscoveryStage:
    """Execute configured passive discovery providers."""

    name = "discovery"
    activity = ExecutionActivity.PASSIVE_DISCOVERY

    def __init__(
        self,
        registry: DiscoveryProviderRegistry | None = None,
    ) -> None:
        self._registry = registry or DiscoveryProviderRegistry()

    @property
    def registry(self) -> DiscoveryProviderRegistry:
        """Return the discovery-provider registry."""
        return self._registry

    def execute(
        self,
        context: PipelineContext,
    ) -> DiscoveryStageResult:
        """Execute enabled discovery providers."""
        context.require_authorized()

        context.execution_policy.require_allowed(
            self.activity
        )

        provider_results: dict[str, ProviderResult[Any]] = {}

        configured_providers = self._configured_providers(
            context
        )

        if not configured_providers or all(
            provider_name == "certificate_transparency"
            for provider_name in configured_providers
        ):
            for provider_name in self._registry.available():
                if provider_name not in configured_providers:
                    configured_providers[provider_name] = {
                        "enabled": True,
                    }

        for provider_name, provider_config in configured_providers.items():
            if isinstance(provider_config, dict):
                enabled = provider_config.get("enabled", True)
            else:
                enabled = getattr(provider_config, "enabled", True)

            if not enabled:
                continue

            try:
                provider = self._registry.create(
                    provider_name
                )
            except DiscoveryProviderError as exc:
                raise DiscoveryStageError(
                    f"Unable to initialize discovery provider "
                    f"'{provider_name}': {exc}"
                ) from exc

            try:
                result = provider.discover(
                    context.target()
                )
            except Exception as exc:
                raise DiscoveryStageError(
                    f"Discovery provider '{provider_name}' failed: {exc}"
                ) from exc

            self._validate_provider_result(
                provider_name,
                result,
            )

            provider_results[provider_name] = result

        stage_result = DiscoveryStageResult(
            provider_results=provider_results,
        )

        context.set_state(
            DISCOVERY_RESULTS_STATE_KEY,
            stage_result,
        )

        return stage_result

    @staticmethod
    def _configured_providers(
        context: PipelineContext,
    ) -> dict[str, dict[str, Any]]:
        """Return configured discovery providers as plain dictionaries."""
        providers = context.config.discovery.providers

        if providers is None:
            return {}

        if isinstance(providers, dict):
            return providers

        try:
            if getattr(providers, "model_extra", None):
                serialized = providers.model_extra
            else:
                serialized = providers.model_dump()
        except AttributeError:
            return {}

        if not isinstance(serialized, dict):
            return {}

        normalized: dict[str, dict[str, Any]] = {}

        for provider_name, provider_config in serialized.items():
            if not isinstance(provider_name, str):
                continue

            if isinstance(provider_config, dict):
                normalized[provider_name] = provider_config
            else:
                normalized[provider_name] = {}

        return normalized

    @staticmethod
    def _validate_provider_result(
        provider_name: str,
        result: object,
    ) -> None:
        """Validate the common ProviderResult contract.

        The configured registry name and the provider-reported name are
        intentionally treated as separate identifiers.

        For example:

            certificate_transparency
                ->
            certificate-transparency

        Both can legitimately refer to the same provider.

        Provider-level failures are valid ProviderResult objects and
        must be preserved rather than converted into DiscoveryStageError.
        """
        if not isinstance(
            result,
            ProviderResult,
        ):
            raise DiscoveryStageError(
                f"Discovery provider '{provider_name}' returned "
                "an invalid ProviderResult."
            )