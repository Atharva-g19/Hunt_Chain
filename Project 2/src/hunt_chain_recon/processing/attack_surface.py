"""Attack Surface Model builder for Hunt_Chain Project 2.

This module assembles already-collected reconnaissance data into the
versioned Attack Surface Model V1.

The builder performs no:

    - DNS queries
    - HTTP requests
    - network requests
    - vulnerability scanning
    - exploitation
    - authorization decisions

It is responsible only for assembling and validating the central
machine-readable representation of a reconnaissance run.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from hunt_chain_recon.config.models import (
    AuthorizationConfig,
    ExecutionConfig,
    TargetConfig,
)
from hunt_chain_recon.models.assets import Asset
from hunt_chain_recon.models.attack_surface import AttackSurface
from hunt_chain_recon.models.dns import DNSObservation
from hunt_chain_recon.models.endpoints import Endpoint
from hunt_chain_recon.models.http import HTTPObservation
from hunt_chain_recon.models.indicators import Indicator
from hunt_chain_recon.models.relationships import Relationship
from hunt_chain_recon.models.run import ReconRun
from hunt_chain_recon.models.services import Service
from hunt_chain_recon.models.technology import (
    Technology,
    TechnologyEvidence,
)


class AttackSurfaceBuilderError(ValueError):
    """Raised when Attack Surface construction input is invalid."""


class AttackSurfaceBuilder:
    """Build a validated Attack Surface Model V1."""

    SCHEMA_VERSION = "v1"

    def build(
        self,
        *,
        run: ReconRun,
        target: TargetConfig,
        authorization: AuthorizationConfig,
        execution: ExecutionConfig,
        assets: Sequence[Asset] = (),
        dns_observations: Sequence[DNSObservation] = (),
        services: Sequence[Service] = (),
        endpoints: Sequence[Endpoint] = (),
        http_observations: Sequence[HTTPObservation] = (),
        technologies: Sequence[Technology] = (),
        technology_evidence: Sequence[TechnologyEvidence] = (),
        indicators: Sequence[Indicator] = (),
        relationships: Sequence[Relationship] = (),
        metadata: dict[str, Any] | None = None,
    ) -> AttackSurface:
        """Build and validate an Attack Surface Model V1.

        The supplied objects are copied into the resulting model so the
        AttackSurface owns its collection values.

        Args:
            run:
                Metadata describing the reconnaissance execution.
            target:
                Target configuration for the run.
            authorization:
                Authorization configuration used by the run.
            execution:
                Execution mode configuration.
            assets:
                Normalized discovered assets.
            dns_observations:
                Collected DNS observations.
            services:
                Observed services.
            endpoints:
                HTTP/HTTPS endpoints.
            http_observations:
                HTTP/HTTPS observations.
            technologies:
                Identified technologies.
            technology_evidence:
                Evidence supporting technology identification.
            indicators:
                Reconnaissance indicators.
            relationships:
                Correlated Attack Surface relationships.
            metadata:
                Additional non-vulnerability run metadata.

        Returns:
            A validated AttackSurface V1 instance.

        Raises:
            AttackSurfaceBuilderError:
                If any supplied value has an unexpected type.
            ValueError:
                If AttackSurface's own validation rejects the assembled
                model.
        """

        self._validate_model(
            "run",
            run,
            ReconRun,
        )

        self._validate_model(
            "target",
            target,
            TargetConfig,
        )

        self._validate_model(
            "authorization",
            authorization,
            AuthorizationConfig,
        )

        self._validate_model(
            "execution",
            execution,
            ExecutionConfig,
        )

        self._validate_sequence(
            "assets",
            assets,
            Asset,
        )

        self._validate_sequence(
            "dns_observations",
            dns_observations,
            DNSObservation,
        )

        self._validate_sequence(
            "services",
            services,
            Service,
        )

        self._validate_sequence(
            "endpoints",
            endpoints,
            Endpoint,
        )

        self._validate_sequence(
            "http_observations",
            http_observations,
            HTTPObservation,
        )

        self._validate_sequence(
            "technologies",
            technologies,
            Technology,
        )

        self._validate_sequence(
            "technology_evidence",
            technology_evidence,
            TechnologyEvidence,
        )

        self._validate_sequence(
            "indicators",
            indicators,
            Indicator,
        )

        self._validate_sequence(
            "relationships",
            relationships,
            Relationship,
        )

        if metadata is not None and not isinstance(
            metadata,
            dict,
        ):
            raise AttackSurfaceBuilderError(
                "metadata must be a dictionary."
            )

        return AttackSurface(
            schema_version=self.SCHEMA_VERSION,
            run=run,
            target=target,
            authorization=authorization,
            execution=execution,
            assets=list(assets),
            dns_observations=list(dns_observations),
            services=list(services),
            endpoints=list(endpoints),
            http_observations=list(http_observations),
            technologies=list(technologies),
            technology_evidence=list(technology_evidence),
            indicators=list(indicators),
            relationships=list(relationships),
            metadata=dict(metadata or {}),
        )

    @staticmethod
    def _validate_model(
        name: str,
        value: object,
        expected_type: type[object],
    ) -> None:
        """Validate one required model value."""

        if not isinstance(
            value,
            expected_type,
        ):
            raise AttackSurfaceBuilderError(
                f"{name} must be "
                f"{expected_type.__name__}, got "
                f"{type(value).__name__}"
            )

    @staticmethod
    def _validate_sequence(
        name: str,
        values: Sequence[object],
        expected_type: type[object],
    ) -> None:
        """Validate a collection of expected model instances."""

        if not isinstance(
            values,
            Sequence,
        ):
            raise AttackSurfaceBuilderError(
                f"{name} must be a sequence."
            )

        for index, value in enumerate(values):
            if not isinstance(
                value,
                expected_type,
            ):
                raise AttackSurfaceBuilderError(
                    f"{name}[{index}] must be "
                    f"{expected_type.__name__}, got "
                    f"{type(value).__name__}"
                )