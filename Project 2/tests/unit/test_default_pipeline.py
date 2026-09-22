"""Tests for the default Project 2 pipeline registration."""

from __future__ import annotations

from hunt_chain_recon.authorization.models import (
    AuthorizationDecision,
    AuthorizationResult,
)
from hunt_chain_recon.config.models import ReconConfig
from hunt_chain_recon.models.run import ReconRun
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.pipeline.engine import PipelineEngine
from hunt_chain_recon.policy.execution import ExecutionPolicy
from hunt_chain_recon.policy.politeness import PolitenessController


def make_context() -> PipelineContext:
    """Create an authorized context for default-pipeline tests."""

    config = ReconConfig(
        target={
            "value": "example.com",
            "type": "DOMAIN",
        },
        authorization={
            "provider": "scopeguard",
            "reference": "TEST_AUTHORIZED",
        },
    )

    authorization = AuthorizationResult(
        target=config.target.value,
        decision=AuthorizationDecision.IN_SCOPE,
        provider=config.authorization.provider,
        reference=config.authorization.reference,
    )

    run = ReconRun.create(
        target=config.target.value,
        execution_mode=config.execution.mode,
    )

    politeness = PolitenessController(
        config.politeness
    )

    return PipelineContext(
        config=config,
        authorization=authorization,
        execution_policy=ExecutionPolicy(
            config.execution
        ),
        politeness=politeness,
        run=run,
    )


def test_default_pipeline_contains_dns_analysis_after_dns() -> None:
    """DNS analysis is registered after DNS resolution."""

    context = make_context()

    engine = PipelineEngine(
        context,
        include_default_stages=True,
    )

    names = [stage.name for stage in engine.stages]

    assert names == [
        "target",
        "discovery",
        "asset_processing",
        "asset_merge",
        "dns",
        "dns_analysis",
        "endpoints",
        "http",
        "http_response_discovery",
        "http_endpoint_merge",
        "http_reprobe",
        "fingerprinting",
        "infrastructure",
        "attack_surface",
    ]

    assert names.index("dns_analysis") > names.index("dns")
    assert names.index("asset_merge") > names.index("asset_processing")
    assert names.index("dns") > names.index("asset_merge")
    assert names.index("endpoints") > names.index("dns_analysis")
    assert names.index("http") > names.index("endpoints")
    assert names.index("attack_surface") > names.index("http")


def test_default_pipeline_preserves_stage_activities() -> None:
    """Built-in stages retain their intended execution activities."""

    context = make_context()

    engine = PipelineEngine(
        context,
        include_default_stages=True,
    )

    names = [stage.name for stage in engine.stages]

    activities = [
        stage.activity.value
        for stage in engine.stages
    ]

    assert activities == [
        "PASSIVE_DISCOVERY",
        "PASSIVE_DISCOVERY",
        "PASSIVE_DISCOVERY",
        "PASSIVE_DISCOVERY",
        "DNS_RESOLUTION",
        "DNS_RESOLUTION",
        "PASSIVE_DISCOVERY",
        "HTTP_PROBING",
        "PASSIVE_DISCOVERY",
        "PASSIVE_DISCOVERY",
        "HTTP_PROBING",
        "PASSIVE_DISCOVERY",
        "INFRASTRUCTURE_LOOKUP",
        "PASSIVE_DISCOVERY",
    ]

    assert len(names) == len(set(names))


def test_default_pipeline_registration_is_deterministic() -> None:
    """Repeated default registration produces the same stage order."""

    context = make_context()

    first_engine = PipelineEngine(
        context,
        include_default_stages=True,
    )

    second_engine = PipelineEngine(
        context,
        include_default_stages=True,
    )

    first_names = [
        stage.name
        for stage in first_engine.stages
    ]

    second_names = [
        stage.name
        for stage in second_engine.stages
    ]

    assert first_names == second_names