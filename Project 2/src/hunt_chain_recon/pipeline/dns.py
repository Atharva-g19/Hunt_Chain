"""DNS pipeline stage for Hunt_Chain Project 2.

This module connects canonical hostname assets to the configured DNS
provider.

Pipeline flow:

    Canonical Assets
        ->
    HOSTNAME assets
        ->
    DNSProvider
        ->
    ProviderResult[DNSObservation]
        ->
    Pipeline State

The stage is responsible for:
- enforcing authorization,
- enforcing execution policy,
- checking DNS configuration,
- selecting hostname assets,
- executing the DNS provider,
- preserving DNS provider results.

The stage does not:
- perform wildcard interpretation,
- determine dangling CNAME indicators,
- confirm DNS takeover,
- perform HTTP probing,
- fingerprint technologies,
- perform vulnerability testing.

Unresolved, timeout, and error observations are preserved.

Authorization remains the responsibility of ScopeGuard and the pipeline
context.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunt_chain_recon.models.assets import Asset
from hunt_chain_recon.models.dns import DNSObservation
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.policy.execution import ExecutionActivity
from hunt_chain_recon.providers.base import ProviderResult
from hunt_chain_recon.providers.dns.resolver import DNSResolverProvider


DNS_RESULTS_STATE_KEY = "dns_results"


class DNSStageError(Exception):
    """Raised when the DNS pipeline stage cannot execute."""


@dataclass(frozen=True)
class DNSStageResult:
    """Result produced by the DNS pipeline stage."""

    provider_result: ProviderResult[DNSObservation]
    hostnames_processed: int

    @property
    def observations(self) -> list[DNSObservation]:
        """Return DNS observations collected by the provider."""
        return self.provider_result.observations

    @property
    def has_failures(self) -> bool:
        """Return whether the provider reported a controlled failure."""
        return self.provider_result.status.value == "FAILED"


class DNSStage:
    """Resolve canonical hostname assets using the configured DNS provider."""

    name = "dns"

    activity = ExecutionActivity.DNS_RESOLUTION

    def __init__(
        self,
        provider: DNSResolverProvider | None = None,
    ) -> None:
        self._provider = provider

    @property
    def provider(self) -> DNSResolverProvider | None:
        """Return the configured DNS provider."""
        return self._provider

    def execute(
        self,
        context: PipelineContext,
    ) -> DNSStageResult:
        """Resolve hostname assets and store DNS results in pipeline state."""
        context.require_authorized()

        context.execution_policy.require_allowed(
            self.activity
        )

        if not context.config.dns.enabled:
            result = DNSStageResult(
                provider_result=ProviderResult(
                    status="SKIPPED",
                    observations=[],
                    errors=[],
                    provider="dns-resolver",
                    version="1.0.0",
                    metadata={
                        "reason": "DNS resolution disabled by configuration."
                    },
                ),
                hostnames_processed=0,
            )

            context.set_state(
                DNS_RESULTS_STATE_KEY,
                result,
            )

            return result

        hostnames = self._collect_hostnames(
            context
        )

        provider = self._provider or DNSResolverProvider(
            timeout_seconds=context.config.dns.timeout_seconds
        )

        try:
            with context.politeness.operation():
                provider_result = provider.resolve(
                    hostnames
                )
        except Exception as exc:
            raise DNSStageError(
                f"DNS provider '{provider.name}' failed: {exc}"
            ) from exc

        if not isinstance(
            provider_result,
            ProviderResult,
        ):
            raise DNSStageError(
                "DNS provider returned an invalid ProviderResult."
            )

        self._validate_observations(
            provider_result.observations
        )

        result = DNSStageResult(
            provider_result=provider_result,
            hostnames_processed=len(hostnames),
        )

        context.set_state(
            DNS_RESULTS_STATE_KEY,
            result,
        )

        return result

    @staticmethod
    def _collect_hostnames(
        context: PipelineContext,
    ) -> list[str]:
        """Collect unique hostname values from canonical assets."""
        assets = context.get_state("assets")

        if assets is None:
            raise DNSStageError(
                "Canonical assets are not available in pipeline state."
            )

        if not isinstance(
            assets,
            list,
        ):
            raise DNSStageError(
                "Pipeline assets state must contain a list."
            )

        hostnames: list[str] = []
        seen: set[str] = set()

        for asset in assets:
            if not isinstance(
                asset,
                Asset,
            ):
                raise DNSStageError(
                    "Pipeline assets state contains an invalid Asset."
                )

            if asset.type != "HOSTNAME":
                continue

            hostname = asset.normalized_value.strip().lower()

            if not hostname or hostname in seen:
                continue

            seen.add(hostname)
            hostnames.append(hostname)

        return hostnames

    @staticmethod
    def _validate_observations(
        observations: list[Any],
    ) -> None:
        """Validate DNS provider observations before storing them."""
        for observation in observations:
            if not isinstance(
                observation,
                DNSObservation,
            ):
                raise DNSStageError(
                    "DNS provider returned a non-DNSObservation value."
                )