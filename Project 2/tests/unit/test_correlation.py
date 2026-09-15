"""Unit tests for the Project 2 correlation engine."""

from __future__ import annotations

from uuid import uuid4

from hunt_chain_recon.models.assets import Asset, AssetType
from hunt_chain_recon.models.dns import (
    DNSObservation,
    DNSRecord,
    DNSRecordType,
    DNSResolutionStatus,
)
from hunt_chain_recon.models.endpoints import (
    Endpoint,
    EndpointScheme,
)
from hunt_chain_recon.models.http import (
    HTTPObservation,
    HTTPObservationState,
)
from hunt_chain_recon.models.indicators import (
    Indicator,
    IndicatorConfidence,
    IndicatorStatus,
    IndicatorType,
)
from hunt_chain_recon.models.relationships import (
    RelationshipType,
)
from hunt_chain_recon.models.services import (
    Service,
    ServiceState,
    TransportProtocol,
)
from hunt_chain_recon.models.technology import (
    Technology,
    TechnologyCategory,
    TechnologyConfidence,
    TechnologyEvidence,
    TechnologyEvidenceType,
)
from hunt_chain_recon.processing.correlation import (
    CorrelationEngine,
)


def make_asset(
    value: str,
    asset_type: AssetType,
) -> Asset:
    """Create a deterministic test asset."""
    return Asset(
        value=value,
        normalized_value=value.lower().rstrip("."),
        type=asset_type,
        sources=["test"],
    )


def make_dns(
    asset_id,
    record_type: DNSRecordType,
    value: str,
) -> DNSObservation:
    """Create a resolved DNS observation."""
    return DNSObservation(
        asset_id=asset_id,
        hostname="www.example.com",
        status=DNSResolutionStatus.RESOLVED,
        records=[
            DNSRecord(
                record_type=record_type,
                value=value,
            )
        ],
    )


def make_service(
    asset_id,
) -> Service:
    """Create an observed TCP service."""
    return Service(
        asset_id=asset_id,
        state=ServiceState.OBSERVED,
        port=443,
        transport=TransportProtocol.TCP,
        source_reference="test",
    )


def make_endpoint(
    asset_id,
    service_id,
) -> Endpoint:
    """Create an HTTPS endpoint."""
    return Endpoint(
        asset_id=asset_id,
        service_id=service_id,
        scheme=EndpointScheme.HTTPS,
        hostname="www.example.com",
        port=443,
        url="https://www.example.com/",
    )


def make_http(
    endpoint_id,
) -> HTTPObservation:
    """Create a successful HTTP observation."""
    return HTTPObservation(
        endpoint_id=endpoint_id,
        state=HTTPObservationState.SUCCESS,
        status_code=200,
        headers={
            "server": "nginx",
        },
    )


def make_technology() -> Technology:
    """Create a test technology."""
    return Technology(
        name="Nginx",
        category=TechnologyCategory.WEB_SERVER,
        version="1.24",
    )


def make_evidence(
    technology_id,
    source_id,
) -> TechnologyEvidence:
    """Create technology evidence."""
    return TechnologyEvidence(
        technology_id=technology_id,
        evidence_type=TechnologyEvidenceType.HTTP_HEADER,
        source_id=source_id,
        observation="Server header identifies nginx.",
        rule="server_header_nginx",
        confidence=TechnologyConfidence.HIGH,
    )


def make_indicator(
    asset_id,
    source_id,
) -> Indicator:
    """Create a potential dangling CNAME indicator."""
    return Indicator(
        asset_id=asset_id,
        type=IndicatorType.POTENTIAL_DANGLING_CNAME,
        status=IndicatorStatus.NEEDS_REVIEW,
        confidence=IndicatorConfidence.MEDIUM,
        title="Potential dangling CNAME",
        description="CNAME target was unresolved.",
        evidence=["CNAME target unresolved."],
        source_ids=[source_id],
    )


def test_correlates_hostname_to_ip() -> None:
    """A and AAAA DNS records create hostname-to-IP relationships."""

    hostname = make_asset(
        "www.example.com",
        AssetType.HOSTNAME,
    )
    ip = make_asset(
        "192.0.2.10",
        AssetType.IP_ADDRESS,
    )

    dns = make_dns(
        hostname.id,
        DNSRecordType.A,
        "192.0.2.10",
    )

    relationships = CorrelationEngine().correlate(
        assets=[hostname, ip],
        dns_observations=[dns],
    )

    assert len(relationships) == 1
    assert relationships[0].type == (
        RelationshipType.HOSTNAME_RESOLVES_TO_IP
    )
    assert relationships[0].source_id == hostname.id
    assert relationships[0].target_id == ip.id
    assert dns.id in relationships[0].evidence_ids


def test_does_not_create_hostname_to_missing_ip_relationship() -> None:
    """DNS records without a matching IP asset are not emitted as edges."""

    hostname = make_asset(
        "www.example.com",
        AssetType.HOSTNAME,
    )

    dns = make_dns(
        hostname.id,
        DNSRecordType.A,
        "192.0.2.10",
    )

    relationships = CorrelationEngine().correlate(
        assets=[hostname],
        dns_observations=[dns],
    )

    assert relationships == []


def test_correlates_hostname_to_cname_target() -> None:
    """A CNAME record creates a hostname-to-hostname relationship."""

    hostname = make_asset(
        "www.example.com",
        AssetType.HOSTNAME,
    )
    target = make_asset(
        "app.example.net",
        AssetType.HOSTNAME,
    )

    dns = DNSObservation(
        asset_id=hostname.id,
        hostname="www.example.com",
        status=DNSResolutionStatus.RESOLVED,
        records=[
            DNSRecord(
                record_type=DNSRecordType.CNAME,
                value="app.example.net",
            )
        ],
    )

    relationships = CorrelationEngine().correlate(
        assets=[hostname, target],
        dns_observations=[dns],
    )

    assert len(relationships) == 1
    assert relationships[0].type == (
        RelationshipType.HOSTNAME_USES_CNAME
    )
    assert relationships[0].source_id == hostname.id
    assert relationships[0].target_id == target.id


def test_correlates_hostname_to_service() -> None:
    """A service associated with a hostname creates a service edge."""

    hostname = make_asset(
        "www.example.com",
        AssetType.HOSTNAME,
    )
    service = make_service(hostname.id)

    relationships = CorrelationEngine().correlate(
        assets=[hostname],
        services=[service],
    )

    assert len(relationships) == 1
    assert relationships[0].type == (
        RelationshipType.HOSTNAME_EXPOSES_SERVICE
    )
    assert relationships[0].source_id == hostname.id
    assert relationships[0].target_id == service.id


def test_correlates_service_to_endpoint() -> None:
    """An endpoint associated with a service creates a service edge."""

    hostname = make_asset(
        "www.example.com",
        AssetType.HOSTNAME,
    )
    service = make_service(hostname.id)
    endpoint = make_endpoint(
        hostname.id,
        service.id,
    )

    relationships = CorrelationEngine().correlate(
        assets=[hostname],
        services=[service],
        endpoints=[endpoint],
    )

    service_edges = [
        relationship
        for relationship in relationships
        if relationship.type
        == RelationshipType.SERVICE_SERVES_ENDPOINT
    ]

    assert len(service_edges) == 1
    assert service_edges[0].source_id == service.id
    assert service_edges[0].target_id == endpoint.id


def test_does_not_create_service_endpoint_edge_when_service_missing() -> None:
    """An endpoint with no known service does not create a false edge."""

    hostname = make_asset(
        "www.example.com",
        AssetType.HOSTNAME,
    )
    missing_service_id = uuid4()

    endpoint = make_endpoint(
        hostname.id,
        missing_service_id,
    )

    relationships = CorrelationEngine().correlate(
        assets=[hostname],
        endpoints=[endpoint],
    )

    assert relationships == []


def test_correlates_endpoint_to_technology_evidence() -> None:
    """Technology evidence links an endpoint observation to technology."""

    hostname = make_asset(
        "www.example.com",
        AssetType.HOSTNAME,
    )
    service = make_service(hostname.id)
    endpoint = make_endpoint(
        hostname.id,
        service.id,
    )
    http = make_http(endpoint.id)
    technology = make_technology()
    evidence = make_evidence(
        technology.id,
        http.id,
    )

    relationships = CorrelationEngine().correlate(
        assets=[hostname],
        services=[service],
        endpoints=[endpoint],
        http_observations=[http],
        technologies=[technology],
        technology_evidence=[evidence],
    )

    technology_edges = [
        relationship
        for relationship in relationships
        if relationship.type
        == RelationshipType.ENDPOINT_INDICATES_TECHNOLOGY
    ]

    assert len(technology_edges) == 1
    assert technology_edges[0].source_id == endpoint.id
    assert technology_edges[0].target_id == technology.id
    assert evidence.id in technology_edges[0].evidence_ids


def test_correlates_asset_to_indicator() -> None:
    """Indicators create asset-to-indicator relationships."""

    hostname = make_asset(
        "www.example.com",
        AssetType.HOSTNAME,
    )
    dns = make_dns(
        hostname.id,
        DNSRecordType.CNAME,
        "unused.example.net",
    )

    indicator = make_indicator(
        hostname.id,
        dns.id,
    )

    relationships = CorrelationEngine().correlate(
        assets=[hostname],
        dns_observations=[dns],
        indicators=[indicator],
    )

    assert len(relationships) == 1
    assert relationships[0].type == (
        RelationshipType.ASSET_HAS_INDICATOR
    )
    assert relationships[0].source_id == hostname.id
    assert relationships[0].target_id == indicator.id
    assert dns.id in relationships[0].evidence_ids


def test_correlates_shared_ip_between_hostnames() -> None:
    """Multiple hostnames resolving to one IP create shared-IP edges."""

    first = make_asset(
        "one.example.com",
        AssetType.HOSTNAME,
    )
    second = make_asset(
        "two.example.com",
        AssetType.HOSTNAME,
    )
    ip = make_asset(
        "192.0.2.20",
        AssetType.IP_ADDRESS,
    )

    first_dns = DNSObservation(
        asset_id=first.id,
        hostname="one.example.com",
        status=DNSResolutionStatus.RESOLVED,
        records=[
            DNSRecord(
                record_type=DNSRecordType.A,
                value="192.0.2.20",
            )
        ],
    )

    second_dns = DNSObservation(
        asset_id=second.id,
        hostname="two.example.com",
        status=DNSResolutionStatus.RESOLVED,
        records=[
            DNSRecord(
                record_type=DNSRecordType.A,
                value="192.0.2.20",
            )
        ],
    )

    relationships = CorrelationEngine().correlate(
        assets=[first, second, ip],
        dns_observations=[
            first_dns,
            second_dns,
        ],
    )

    shared_edges = [
        relationship
        for relationship in relationships
        if relationship.type
        == RelationshipType.IP_SHARED_BY_HOSTNAMES
    ]

    assert len(shared_edges) == 2

    assert {
        relationship.target_id
        for relationship in shared_edges
    } == {
        first.id,
        second.id,
    }

    assert all(
        relationship.source_id == ip.id
        for relationship in shared_edges
    )


def test_deduplicates_identical_relationships() -> None:
    """Duplicate observations do not create duplicate relationship edges."""

    hostname = make_asset(
        "www.example.com",
        AssetType.HOSTNAME,
    )
    ip = make_asset(
        "192.0.2.30",
        AssetType.IP_ADDRESS,
    )

    dns_one = make_dns(
        hostname.id,
        DNSRecordType.A,
        "192.0.2.30",
    )
    dns_two = make_dns(
        hostname.id,
        DNSRecordType.A,
        "192.0.2.30",
    )

    relationships = CorrelationEngine().correlate(
        assets=[hostname, ip],
        dns_observations=[
            dns_one,
            dns_two,
        ],
    )

    assert len(relationships) == 1
    assert relationships[0].evidence_ids == [
        dns_one.id,
        dns_two.id,
    ]


def test_correlation_is_deterministically_ordered() -> None:
    """Relationship output is stable regardless of input order."""

    hostname = make_asset(
        "www.example.com",
        AssetType.HOSTNAME,
    )
    ip = make_asset(
        "192.0.2.40",
        AssetType.IP_ADDRESS,
    )

    dns = make_dns(
        hostname.id,
        DNSRecordType.A,
        "192.0.2.40",
    )

    engine = CorrelationEngine()

    first = engine.correlate(
        assets=[hostname, ip],
        dns_observations=[dns],
    )

    second = engine.correlate(
        assets=[ip, hostname],
        dns_observations=[dns],
    )

    assert [
        (
            relationship.type,
            relationship.source_id,
            relationship.target_id,
        )
        for relationship in first
    ] == [
        (
            relationship.type,
            relationship.source_id,
            relationship.target_id,
        )
        for relationship in second
    ]


def test_correlation_does_not_make_network_requests() -> None:
    """Correlation only consumes supplied observations."""

    hostname = make_asset(
        "www.example.com",
        AssetType.HOSTNAME,
    )

    engine = CorrelationEngine()

    relationships = engine.correlate(
        assets=[hostname],
    )

    assert relationships == []