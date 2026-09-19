"""Regression tests for conservative default endpoint generation."""

from __future__ import annotations

from uuid import uuid4

from hunt_chain_recon.models.assets import Asset
from hunt_chain_recon.pipeline.endpoints import EndpointStage


def test_default_web_endpoints_do_not_cross_scheme_and_port() -> None:
    asset = Asset(
        id=uuid4(),
        value="example.com",
        normalized_value="example.com",
        type="DOMAIN",
    )

    endpoints = EndpointStage._generate_endpoints(
        assets=[asset],
        schemes=["http", "https"],
        ports=[80, 443],
    )

    assert [(endpoint.scheme.value, endpoint.port, endpoint.url) for endpoint in endpoints] == [
        ("http", 80, "http://example.com"),
        ("https", 443, "https://example.com"),
    ]


def test_non_default_ports_are_not_inferred_without_service_evidence() -> None:
    asset = Asset(
        id=uuid4(),
        value="example.com",
        normalized_value="example.com",
        type="DOMAIN",
    )

    endpoints = EndpointStage._generate_endpoints(
        assets=[asset],
        schemes=["http", "https"],
        ports=[80, 443, 8080],
    )

    assert {endpoint.url for endpoint in endpoints} == {
        "http://example.com",
        "https://example.com",
    }
