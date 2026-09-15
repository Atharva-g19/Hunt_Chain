"""Integration tests for the Hunt_Chain Project 2 domain models."""

from uuid import uuid4

import pytest
from pydantic import ValidationError

from hunt_chain_recon.config.models import (
    AuthorizationConfig,
    ExecutionConfig,
    TargetConfig,
)
from hunt_chain_recon.models import (
    Asset,
    AttackSurface,
    DNSObservation,
    DNSRecord,
    Endpoint,
    HTTPObservation,
    Indicator,
    Relationship,
    ReconRun,
    Service,
    Technology,
    TechnologyEvidence,
)


def build_base_attack_surface() -> AttackSurface:
    """Build a minimal valid AttackSurface for integration testing."""
    target = TargetConfig(
        value="example.com",
        type="DOMAIN",
    )

    authorization = AuthorizationConfig(
        provider="scopeguard",
        reference="test-reference",
    )

    execution = ExecutionConfig(
        mode="active",
    )

    run = ReconRun(
        target="example.com",
        execution_mode="active",
    )

    return AttackSurface(
        run=run,
        target=target,
        authorization=authorization,
        execution=execution,
    )


def test_all_domain_models_import_together() -> None:
    """Verify that the complete domain-model package imports successfully."""
    attack_surface = build_base_attack_surface()

    assert attack_surface.schema_version == "v1"
    assert attack_surface.run.target == "example.com"
    assert attack_surface.target.value == "example.com"
    assert attack_surface.assets == []
    assert attack_surface.dns_observations == []
    assert attack_surface.services == []
    assert attack_surface.endpoints == []
    assert attack_surface.http_observations == []
    assert attack_surface.technologies == []
    assert attack_surface.technology_evidence == []
    assert attack_surface.indicators == []
    assert attack_surface.relationships == []


def test_attack_surface_can_contain_related_entities() -> None:
    """Verify that domain entities can be assembled into one attack surface."""
    attack_surface = build_base_attack_surface()

    hostname = Asset(
        value="www.example.com",
        type="HOSTNAME",
    )

    ip_address = Asset(
        value="203.0.113.10",
        type="IP_ADDRESS",
    )

    dns_observation = DNSObservation(
        hostname="www.example.com",
        asset_id=hostname.id,
        state="RESOLVED",
        records=[
            DNSRecord(
                type="A",
                value="203.0.113.10",
                ttl=300,
            )
        ],
    )

    service = Service(
        asset_id=hostname.id,
        state="OBSERVED",
        port=443,
        transport="TCP",
        source_reference="test-http-provider",
    )

    endpoint = Endpoint(
        asset_id=hostname.id,
        service_id=service.id,
        scheme="https",
        hostname="www.example.com",
        port=443,
        url="https://www.example.com/",
    )

    http_observation = HTTPObservation(
        endpoint_id=endpoint.id,
        state="SUCCESS",
        status_code=200,
        headers={
            "server": "example-server",
            "content-type": "text/html",
        },
        content_type="text/html",
        body_length=128,
        body_hash="a" * 64,
    )

    technology = Technology(
        name="Example Server",
        category="WEB_SERVER",
        version="1.0",
    )

    technology_evidence = TechnologyEvidence(
        technology_id=technology.id,
        evidence_type="HTTP_HEADER",
        source_id=http_observation.id,
        observation="Server header identified Example Server.",
        rule="HTTP header: server",
        confidence="HIGH",
    )

    indicator = Indicator(
        asset_id=hostname.id,
        type="POTENTIAL_DANGLING_CNAME",
        confidence="LOW",
        title="Potential dangling CNAME",
        description="Test indicator for model integration.",
        evidence=[
            "CNAME observation exists.",
        ],
        source_ids=[
            dns_observation.id,
        ],
    )

    relationships = [
        Relationship(
            type="HOSTNAME_RESOLVES_TO_IP",
            source_id=hostname.id,
            target_id=ip_address.id,
            evidence_ids=[dns_observation.id],
        ),
        Relationship(
            type="HOSTNAME_EXPOSES_SERVICE",
            source_id=hostname.id,
            target_id=service.id,
            evidence_ids=[dns_observation.id],
        ),
        Relationship(
            type="SERVICE_SERVES_ENDPOINT",
            source_id=service.id,
            target_id=endpoint.id,
            evidence_ids=[http_observation.id],
        ),
        Relationship(
            type="ENDPOINT_INDICATES_TECHNOLOGY",
            source_id=endpoint.id,
            target_id=technology.id,
            evidence_ids=[technology_evidence.id],
        ),
        Relationship(
            type="ASSET_HAS_INDICATOR",
            source_id=hostname.id,
            target_id=indicator.id,
            evidence_ids=[dns_observation.id],
        ),
    ]

    attack_surface = AttackSurface(
        run=attack_surface.run,
        target=attack_surface.target,
        authorization=attack_surface.authorization,
        execution=attack_surface.execution,
        assets=[
            hostname,
            ip_address,
        ],
        dns_observations=[
            dns_observation,
        ],
        services=[
            service,
        ],
        endpoints=[
            endpoint,
        ],
        http_observations=[
            http_observation,
        ],
        technologies=[
            technology,
        ],
        technology_evidence=[
            technology_evidence,
        ],
        indicators=[
            indicator,
        ],
        relationships=relationships,
    )

    assert len(attack_surface.assets) == 2
    assert len(attack_surface.dns_observations) == 1
    assert len(attack_surface.services) == 1
    assert len(attack_surface.endpoints) == 1
    assert len(attack_surface.http_observations) == 1
    assert len(attack_surface.technologies) == 1
    assert len(attack_surface.technology_evidence) == 1
    assert len(attack_surface.indicators) == 1
    assert len(attack_surface.relationships) == 5


def test_invalid_relationship_reference_is_rejected() -> None:
    """Verify that unknown relationship entity IDs are rejected."""
    attack_surface = build_base_attack_surface()

    hostname = Asset(
        value="www.example.com",
        type="HOSTNAME",
    )

    invalid_relationship = Relationship(
        type="HOSTNAME_RESOLVES_TO_IP",
        source_id=hostname.id,
        target_id=uuid4(),
    )

    with pytest.raises(ValidationError):
        AttackSurface(
            run=attack_surface.run,
            target=attack_surface.target,
            authorization=attack_surface.authorization,
            execution=attack_surface.execution,
            assets=[
                hostname,
            ],
            relationships=[
                invalid_relationship,
            ],
        )


def test_mismatched_run_and_target_are_rejected() -> None:
    """Verify that run and target cannot describe different targets."""
    target = TargetConfig(
        value="example.com",
        type="DOMAIN",
    )

    authorization = AuthorizationConfig(
        provider="scopeguard",
        reference="test-reference",
    )

    execution = ExecutionConfig(
        mode="active",
    )

    run = ReconRun(
        target="different.example.com",
        execution_mode="active",
    )

    with pytest.raises(ValidationError):
        AttackSurface(
            run=run,
            target=target,
            authorization=authorization,
            execution=execution,
        )


def test_only_v1_schema_is_supported() -> None:
    """Verify that unsupported Attack Surface schema versions are rejected."""
    target = TargetConfig(
        value="example.com",
        type="DOMAIN",
    )

    authorization = AuthorizationConfig(
        provider="scopeguard",
        reference="test-reference",
    )

    execution = ExecutionConfig(
        mode="active",
    )

    run = ReconRun(
        target="example.com",
        execution_mode="active",
    )

    with pytest.raises(ValidationError):
        AttackSurface(
            schema_version="v2",
            run=run,
            target=target,
            authorization=authorization,
            execution=execution,
        )