"""Correlation engine for Hunt_Chain Project 2.

This module converts already-collected reconnaissance observations into
relationships forming the Attack Surface Model.

The correlation engine performs no network activity.

V1 responsibilities:

    - hostname -> resolved IP
    - hostname -> CNAME target
    - hostname -> observed service
    - service -> endpoint
    - endpoint -> technology
    - asset -> indicator
    - shared IP -> hostnames

V1 explicitly does not:

    - perform DNS lookups
    - perform HTTP requests
    - perform port scans
    - perform vulnerability scanning
    - confirm vulnerabilities
    - exploit targets

Correlation is interpretation of collected observations, not collection.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any
from uuid import UUID

from hunt_chain_recon.models.assets import Asset, AssetType
from hunt_chain_recon.models.dns import (
    DNSObservation,
    DNSRecordType,
    DNSResolutionStatus,
)
from hunt_chain_recon.models.endpoints import Endpoint
from hunt_chain_recon.models.http import HTTPObservation
from hunt_chain_recon.models.indicators import Indicator
from hunt_chain_recon.models.relationships import (
    Relationship,
    RelationshipType,
)
from hunt_chain_recon.models.services import Service
from hunt_chain_recon.models.technology import (
    Technology,
    TechnologyEvidence,
)


class CorrelationError(ValueError):
    """Raised when correlation input is invalid."""


class CorrelationEngine:
    """Build deterministic relationships from reconnaissance observations."""

    def correlate(
        self,
        *,
        assets: Sequence[Asset] = (),
        dns_observations: Sequence[DNSObservation] = (),
        services: Sequence[Service] = (),
        endpoints: Sequence[Endpoint] = (),
        http_observations: Sequence[HTTPObservation] = (),
        technologies: Sequence[Technology] = (),
        technology_evidence: Sequence[TechnologyEvidence] = (),
        indicators: Sequence[Indicator] = (),
    ) -> list[Relationship]:
        """Correlate supplied observations into Attack Surface relationships.

        All inputs are already-collected observations. This method performs
        no network operations.
        """

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

        asset_by_id = {
            asset.id: asset
            for asset in assets
        }

        service_by_id = {
            service.id: service
            for service in services
        }

        endpoint_by_id = {
            endpoint.id: endpoint
            for endpoint in endpoints
        }

        technology_by_id = {
            technology.id: technology
            for technology in technologies
        }

        http_observation_by_id = {
            observation.id: observation
            for observation in http_observations
        }

        relationships: dict[
            tuple[RelationshipType, UUID, UUID],
            Relationship,
        ] = {}

        self._correlate_dns(
            asset_by_id=asset_by_id,
            dns_observations=dns_observations,
            relationships=relationships,
        )

        self._correlate_services(
            asset_by_id=asset_by_id,
            services=services,
            relationships=relationships,
        )

        self._correlate_endpoints(
            service_by_id=service_by_id,
            endpoints=endpoints,
            relationships=relationships,
        )

        self._correlate_technologies(
            endpoint_by_id=endpoint_by_id,
            technology_by_id=technology_by_id,
            http_observation_by_id=http_observation_by_id,
            technology_evidence=technology_evidence,
            relationships=relationships,
        )

        self._correlate_indicators(
            asset_by_id=asset_by_id,
            indicators=indicators,
            relationships=relationships,
        )

        self._correlate_shared_ips(
            asset_by_id=asset_by_id,
            dns_observations=dns_observations,
            relationships=relationships,
        )

        return self._sorted_relationships(
            relationships
        )

    @staticmethod
    def _validate_sequence(
        name: str,
        values: Sequence[Any],
        expected_type: type[Any],
    ) -> None:
        """Validate that an input is a sequence of the expected model."""

        if not isinstance(values, Sequence):
            raise CorrelationError(
                f"{name} must be a sequence"
            )

        for index, value in enumerate(values):
            if not isinstance(value, expected_type):
                raise CorrelationError(
                    f"{name}[{index}] must be "
                    f"{expected_type.__name__}, got "
                    f"{type(value).__name__}"
                )

    @staticmethod
    def _correlate_dns(
        *,
        asset_by_id: dict[UUID, Asset],
        dns_observations: Sequence[DNSObservation],
        relationships: dict[
            tuple[RelationshipType, UUID, UUID],
            Relationship,
        ],
    ) -> None:
        """Correlate DNS records with known hostname and IP assets."""

        hostname_assets = {
            asset.normalized_value: asset
            for asset in asset_by_id.values()
            if asset.type == AssetType.HOSTNAME
        }

        ip_assets = {
            asset.normalized_value: asset
            for asset in asset_by_id.values()
            if asset.type == AssetType.IP_ADDRESS
        }

        for observation in dns_observations:
            if observation.status != DNSResolutionStatus.RESOLVED:
                continue

            hostname_value = (
                observation.hostname
                .lower()
                .rstrip(".")
            )

            hostname_asset = hostname_assets.get(
                hostname_value
            )

            if hostname_asset is None:
                continue

            for record in observation.records:
                if record.record_type in {
                    DNSRecordType.A,
                    DNSRecordType.AAAA,
                }:
                    ip_value = record.value

                    ip_asset = ip_assets.get(
                        ip_value
                    )

                    if ip_asset is None:
                        continue

                    CorrelationEngine._add_relationship(
                        relationships=relationships,
                        relationship_type=(
                            RelationshipType.HOSTNAME_RESOLVES_TO_IP
                        ),
                        source_id=hostname_asset.id,
                        target_id=ip_asset.id,
                        evidence_ids=[observation.id],
                    )

                elif record.record_type == DNSRecordType.CNAME:
                    cname_target = (
                        record.value
                        .lower()
                        .rstrip(".")
                    )

                    target_asset = hostname_assets.get(
                        cname_target
                    )

                    if target_asset is None:
                        continue

                    CorrelationEngine._add_relationship(
                        relationships=relationships,
                        relationship_type=(
                            RelationshipType.HOSTNAME_USES_CNAME
                        ),
                        source_id=hostname_asset.id,
                        target_id=target_asset.id,
                        evidence_ids=[observation.id],
                    )

    @staticmethod
    def _correlate_services(
        *,
        asset_by_id: dict[UUID, Asset],
        services: Sequence[Service],
        relationships: dict[
            tuple[RelationshipType, UUID, UUID],
            Relationship,
        ],
    ) -> None:
        """Correlate services with their associated assets."""

        for service in services:
            asset = asset_by_id.get(
                service.asset_id
            )

            if asset is None:
                continue

            if asset.type != AssetType.HOSTNAME:
                continue

            CorrelationEngine._add_relationship(
                relationships=relationships,
                relationship_type=(
                    RelationshipType.HOSTNAME_EXPOSES_SERVICE
                ),
                source_id=asset.id,
                target_id=service.id,
                evidence_ids=[],
            )

    @staticmethod
    def _correlate_endpoints(
        *,
        service_by_id: dict[UUID, Service],
        endpoints: Sequence[Endpoint],
        relationships: dict[
            tuple[RelationshipType, UUID, UUID],
            Relationship,
        ],
    ) -> None:
        """Correlate endpoints with their observed services."""

        for endpoint in endpoints:
            if endpoint.service_id is None:
                continue

            service = service_by_id.get(
                endpoint.service_id
            )

            if service is None:
                continue

            CorrelationEngine._add_relationship(
                relationships=relationships,
                relationship_type=(
                    RelationshipType.SERVICE_SERVES_ENDPOINT
                ),
                source_id=service.id,
                target_id=endpoint.id,
                evidence_ids=[],
            )

    @staticmethod
    def _correlate_technologies(
        *,
        endpoint_by_id: dict[UUID, Endpoint],
        technology_by_id: dict[UUID, Technology],
        http_observation_by_id: dict[
            UUID,
            HTTPObservation,
        ],
        technology_evidence: Sequence[TechnologyEvidence],
        relationships: dict[
            tuple[RelationshipType, UUID, UUID],
            Relationship,
        ],
    ) -> None:
        """Correlate technology evidence with endpoints.

        TechnologyEvidence.source_id is expected to reference an
        HTTPObservation in the V1 model. The HTTP observation then provides
        the endpoint relationship.
        """

        for evidence in technology_evidence:
            if evidence.technology_id not in technology_by_id:
                continue

            if evidence.source_id is None:
                continue

            http_observation = http_observation_by_id.get(
                evidence.source_id
            )

            if http_observation is None:
                continue

            endpoint = endpoint_by_id.get(
                http_observation.endpoint_id
            )

            if endpoint is None:
                continue

            CorrelationEngine._add_relationship(
                relationships=relationships,
                relationship_type=(
                    RelationshipType.ENDPOINT_INDICATES_TECHNOLOGY
                ),
                source_id=endpoint.id,
                target_id=evidence.technology_id,
                evidence_ids=[evidence.id],
            )

    @staticmethod
    def _correlate_indicators(
        *,
        asset_by_id: dict[UUID, Asset],
        indicators: Sequence[Indicator],
        relationships: dict[
            tuple[RelationshipType, UUID, UUID],
            Relationship,
        ],
    ) -> None:
        """Correlate indicators with their associated assets."""

        for indicator in indicators:
            asset = asset_by_id.get(
                indicator.asset_id
            )

            if asset is None:
                continue

            CorrelationEngine._add_relationship(
                relationships=relationships,
                relationship_type=(
                    RelationshipType.ASSET_HAS_INDICATOR
                ),
                source_id=asset.id,
                target_id=indicator.id,
                evidence_ids=list(
                    indicator.source_ids
                ),
            )

    @staticmethod
    def _correlate_shared_ips(
        *,
        asset_by_id: dict[UUID, Asset],
        dns_observations: Sequence[DNSObservation],
        relationships: dict[
            tuple[RelationshipType, UUID, UUID],
            Relationship,
        ],
    ) -> None:
        """Create one shared-IP edge for each hostname using the IP.

        Example:

            IP
            ├──> hostname-a
            └──> hostname-b

        A shared IP relationship is only emitted when at least two known
        hostnames resolve to the same known IP asset.
        """

        hostname_assets = {
            asset.normalized_value: asset
            for asset in asset_by_id.values()
            if asset.type == AssetType.HOSTNAME
        }

        ip_assets = {
            asset.normalized_value: asset
            for asset in asset_by_id.values()
            if asset.type == AssetType.IP_ADDRESS
        }

        ip_to_hostnames: dict[
            str,
            dict[UUID, list[UUID]],
        ] = {}

        for observation in dns_observations:
            if observation.status != DNSResolutionStatus.RESOLVED:
                continue

            hostname_value = (
                observation.hostname
                .lower()
                .rstrip(".")
            )

            hostname_asset = hostname_assets.get(
                hostname_value
            )

            if hostname_asset is None:
                continue

            for record in observation.records:
                if record.record_type not in {
                    DNSRecordType.A,
                    DNSRecordType.AAAA,
                }:
                    continue

                ip_value = record.value

                if ip_value not in ip_assets:
                    continue

                hostname_entries = ip_to_hostnames.setdefault(
                    ip_value,
                    {},
                )

                evidence_ids = hostname_entries.setdefault(
                    hostname_asset.id,
                    [],
                )

                if observation.id not in evidence_ids:
                    evidence_ids.append(
                        observation.id
                    )

        for ip_value, hostname_entries in ip_to_hostnames.items():
            if len(hostname_entries) < 2:
                continue

            ip_asset = ip_assets.get(
                ip_value
            )

            if ip_asset is None:
                continue

            for hostname_id, evidence_ids in hostname_entries.items():
                CorrelationEngine._add_relationship(
                    relationships=relationships,
                    relationship_type=(
                        RelationshipType.IP_SHARED_BY_HOSTNAMES
                    ),
                    source_id=ip_asset.id,
                    target_id=hostname_id,
                    evidence_ids=evidence_ids,
                )

    @staticmethod
    def _add_relationship(
        *,
        relationships: dict[
            tuple[RelationshipType, UUID, UUID],
            Relationship,
        ],
        relationship_type: RelationshipType,
        source_id: UUID,
        target_id: UUID,
        evidence_ids: Sequence[UUID],
    ) -> None:
        """Add a relationship or merge evidence into an existing one.

        Relationships are deduplicated by:

            relationship type
            source ID
            target ID

        Evidence ordering is intentionally preserved.
        """

        key = (
            relationship_type,
            source_id,
            target_id,
        )

        existing = relationships.get(
            key
        )

        if existing is None:
            relationships[key] = Relationship(
                type=relationship_type,
                source_id=source_id,
                target_id=target_id,
                evidence_ids=list(
                    evidence_ids
                ),
            )
            return

        merged_evidence = list(
            existing.evidence_ids
        )

        for evidence_id in evidence_ids:
            if evidence_id not in merged_evidence:
                merged_evidence.append(
                    evidence_id
                )

        existing.evidence_ids = merged_evidence

    @staticmethod
    def _sorted_relationships(
        relationships: dict[
            tuple[RelationshipType, UUID, UUID],
            Relationship,
        ],
    ) -> list[Relationship]:
        """Return relationships in deterministic order.

        Relationship ordering is deterministic.

        Evidence ordering is deliberately NOT sorted because the order in
        which observations were correlated is meaningful for deterministic
        evidence preservation and is required by the V1 tests.
        """

        result = list(
            relationships.values()
        )

        result.sort(
            key=lambda relationship: (
                relationship.type.value,
                str(relationship.source_id),
                str(relationship.target_id),
            )
        )

        return result