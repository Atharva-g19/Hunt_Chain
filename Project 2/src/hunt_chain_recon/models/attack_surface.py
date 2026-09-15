"""Attack Surface Model V1 for Hunt_Chain Project 2.

This module defines the central machine-readable representation of a
reconnaissance run.

The AttackSurface model combines observations, technologies, indicators,
and relationships into a versioned attack-surface representation.

It does not perform reconnaissance, network requests, vulnerability
testing, exploitation, or authorization decisions.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_serializer,
    model_validator,
)

from hunt_chain_recon.config.models import (
    AuthorizationConfig,
    ExecutionConfig,
    TargetConfig,
)
from hunt_chain_recon.models.assets import Asset
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


class AttackSurface(BaseModel):
    """Central V1 representation of the discovered attack surface.

    The model is versioned explicitly through ``schema_version``.

    Project 3 and later components may consume this structure as a stable
    machine-readable contract. Breaking structural changes must therefore
    result in a new schema version rather than silently changing V1.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str = Field(
        default="v1",
        description="Version of the Attack Surface Model schema.",
    )

    run: ReconRun = Field(
        ...,
        description="Metadata describing the reconnaissance execution.",
    )

    target: TargetConfig = Field(
        ...,
        description="Authorized target definition for the run.",
    )

    authorization: AuthorizationConfig = Field(
        ...,
        description="Authorization configuration used for the run.",
    )

    execution: ExecutionConfig = Field(
        ...,
        description="Execution policy used by the run.",
    )

    assets: list[Asset] = Field(
        default_factory=list,
        description="Discovered and normalized assets.",
    )

    dns_observations: list[DNSObservation] = Field(
        default_factory=list,
        description="DNS observations collected during reconnaissance.",
    )

    services: list[Service] = Field(
        default_factory=list,
        description="Observed or associated network services.",
    )

    endpoints: list[Endpoint] = Field(
        default_factory=list,
        description="HTTP and HTTPS application endpoints.",
    )

    http_observations: list[HTTPObservation] = Field(
        default_factory=list,
        description="HTTP and HTTPS response observations.",
    )

    technologies: list[Technology] = Field(
        default_factory=list,
        description="Technologies identified from reconnaissance evidence.",
    )

    technology_evidence: list[TechnologyEvidence] = Field(
        default_factory=list,
        description="Evidence supporting technology observations.",
    )

    indicators: list[Indicator] = Field(
        default_factory=list,
        description="Reconnaissance indicators requiring attention.",
    )

    relationships: list[Relationship] = Field(
        default_factory=list,
        description="Relationships connecting attack-surface entities.",
    )

    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Additional run-level metadata. "
            "Must not contain vulnerability conclusions."
        ),
    )

    @field_serializer("authorization")
    def serialize_authorization(
        self,
        authorization: AuthorizationConfig,
    ) -> dict[str, str]:
        """Serialize only public authorization fields into V1 output.

        ``scope_file`` is an internal configuration detail used by the
        ScopeGuard adapter. It may contain a local filesystem path and is
        intentionally excluded from the versioned Attack Surface Model.
        """
        return {
            "provider": authorization.provider,
            "reference": authorization.reference,
        }

    @model_validator(mode="after")
    def validate_schema_version(self) -> AttackSurface:
        """Ensure that this model represents the supported V1 schema."""
        if self.schema_version != "v1":
            raise ValueError(
                "Unsupported Attack Surface Model schema version. "
                "Project 2 currently supports only 'v1'."
            )

        return self

    @model_validator(mode="after")
    def validate_run_target_consistency(self) -> AttackSurface:
        """Ensure the run and target refer to the same target value."""
        if (
            self.run.target
            != self.target.value.strip().lower().rstrip(".")
        ):
            raise ValueError(
                "Run target must match the normalized target "
                "configuration value."
            )

        return self

    @model_validator(mode="after")
    def validate_relationship_ids(self) -> AttackSurface:
        """Validate that relationship references point to known entities.

        This performs local reference-integrity validation for entities
        already contained in the AttackSurface model.

        Evidence references are intentionally validated separately because
        they may refer to observation models rather than graph entities.
        """
        known_entity_ids: set[UUID] = set()

        for asset in self.assets:
            known_entity_ids.add(asset.id)

        for service in self.services:
            known_entity_ids.add(service.id)

        for endpoint in self.endpoints:
            known_entity_ids.add(endpoint.id)

        for technology in self.technologies:
            known_entity_ids.add(technology.id)

        for indicator in self.indicators:
            known_entity_ids.add(indicator.id)

        for relationship in self.relationships:
            if relationship.source_id not in known_entity_ids:
                raise ValueError(
                    "Relationship source_id does not reference an entity "
                    "contained in the attack surface: "
                    f"{relationship.source_id}"
                )

            if relationship.target_id not in known_entity_ids:
                raise ValueError(
                    "Relationship target_id does not reference an entity "
                    "contained in the attack surface: "
                    f"{relationship.target_id}"
                )

        return self