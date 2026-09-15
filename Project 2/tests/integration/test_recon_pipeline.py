"""End-to-end tests for the Hunt_Chain Project 2 reconnaissance pipeline."""

from __future__ import annotations

from pathlib import Path

from hunt_chain_recon.authorization.models import AuthorizationResult
from hunt_chain_recon.config.loader import load_config
from hunt_chain_recon.models.run import ReconRun
from hunt_chain_recon.pipeline import (
    ASSETS_STATE_KEY,
    DISCOVERY_RESULTS_STATE_KEY,
    AssetProcessingStage,
    DiscoveryStage,
    PipelineContext,
    PipelineEngine,
)
from hunt_chain_recon.pipeline.asset_processing import (
    AssetProcessingStageResult,
)
from hunt_chain_recon.pipeline.discovery import (
    DiscoveryStageResult,
)
from hunt_chain_recon.pipeline.engine import PipelineStage
from hunt_chain_recon.policy.execution import ExecutionPolicy
from hunt_chain_recon.policy.politeness import PolitenessController
from tests.fixtures.discovery_provider import FixtureDiscoveryProvider


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "default.yaml"


def make_context() -> PipelineContext:
    """Create an authorized pipeline context."""
    config = load_config(DEFAULT_CONFIG_PATH)

    authorization = AuthorizationResult(
        decision="IN_SCOPE",
        provider="test",
        reference="test-authorization",
        target="example.com",
    )

    return PipelineContext(
        config=config,
        authorization=authorization,
        execution_policy=ExecutionPolicy(
            config.execution
        ),
        politeness=PolitenessController(
            config.politeness
        ),
        run=ReconRun.create(
            target="example.com",
        ),
    )


def make_engine(
    context: PipelineContext,
    observations: list[dict],
) -> PipelineEngine:
    """Create a pipeline using the deterministic fixture provider."""
    fixture_provider = FixtureDiscoveryProvider(
        observations=observations,
    )

    discovery_stage = DiscoveryStage()

    discovery_stage.registry.register(
        "fixture_discovery",
        lambda: fixture_provider,
    )

    asset_processing_stage = AssetProcessingStage()

    engine = PipelineEngine(context)

    engine.add_stage(
        PipelineStage(
            name=discovery_stage.name,
            activity=discovery_stage.activity,
            handler=discovery_stage.execute,
        )
    )

    engine.add_stage(
        PipelineStage(
            name=asset_processing_stage.name,
            activity=asset_processing_stage.activity,
            handler=asset_processing_stage.execute,
        )
    )

    return engine


def test_complete_pipeline_discovers_and_processes_assets():
    """Discovery observations reach canonical unique Assets."""
    context = make_context()

    observations = [
        {
            "value": "WWW.Example.COM.",
            "type": "HOSTNAME",
            "source": "certificate_transparency",
        },
        {
            "value": "www.example.com",
            "type": "HOSTNAME",
            "source": "dns",
        },
        {
            "value": "api.example.com",
            "type": "HOSTNAME",
            "source": "certificate_transparency",
        },
    ]

    engine = make_engine(
        context,
        observations,
    )

    result = engine.run()

    assert result.completed is True
    assert result.blocked is False
    assert result.failed_stage is None
    assert result.error is None

    assert list(result.stage_results) == [
        "discovery",
        "asset_processing",
    ]

    discovery_result = result.stage_results[
        "discovery"
    ]

    assert isinstance(
        discovery_result,
        DiscoveryStageResult,
    )

    processing_result = result.stage_results[
        "asset_processing"
    ]

    assert isinstance(
        processing_result,
        AssetProcessingStageResult,
    )

    assert processing_result.observations_processed == 3
    assert processing_result.assets_before_deduplication == 3
    assert processing_result.assets_after_deduplication == 2

    assets = processing_result.assets

    assert [
        asset.normalized_value
        for asset in assets
    ] == [
        "www.example.com",
        "api.example.com",
    ]

    assert assets[0].sources == [
        "certificate_transparency",
        "dns",
    ]


def test_complete_pipeline_stores_discovery_results():
    """Discovery results remain available in pipeline state."""
    context = make_context()

    engine = make_engine(
        context,
        [
            {
                "value": "api.example.com",
                "type": "HOSTNAME",
                "source": "fixture",
            }
        ],
    )

    result = engine.run()

    assert result.completed is True

    discovery_state = context.get_state(
        DISCOVERY_RESULTS_STATE_KEY
    )

    assert isinstance(
        discovery_state,
        DiscoveryStageResult,
    )


def test_complete_pipeline_stores_canonical_assets():
    """Canonical assets are available for subsequent stages."""
    context = make_context()

    engine = make_engine(
        context,
        [
            {
                "value": "API.Example.COM.",
                "type": "HOSTNAME",
                "source": "fixture",
            }
        ],
    )

    result = engine.run()

    assert result.completed is True

    assets = context.get_state(
        ASSETS_STATE_KEY
    )

    assert isinstance(assets, list)
    assert len(assets) == 1
    assert assets[0].normalized_value == "api.example.com"


def test_complete_pipeline_preserves_asset_identity():
    """The first canonical Asset identity is preserved after deduplication."""
    context = make_context()

    engine = make_engine(
        context,
        [
            {
                "value": "WWW.Example.COM",
                "type": "HOSTNAME",
                "source": "source_a",
            },
            {
                "value": "www.example.com.",
                "type": "HOSTNAME",
                "source": "source_b",
            },
        ],
    )

    result = engine.run()

    assert result.completed is True

    processing_result = result.stage_results[
        "asset_processing"
    ]

    asset = processing_result.assets[0]

    assert asset.value == "WWW.Example.COM"
    assert asset.normalized_value == "www.example.com"
    assert asset.sources == [
        "source_a",
        "source_b",
    ]


def test_complete_pipeline_empty_discovery_produces_empty_assets():
    """An empty discovery source completes without creating assets."""
    context = make_context()

    engine = make_engine(
        context,
        [],
    )

    result = engine.run()

    assert result.completed is True

    processing_result = result.stage_results[
        "asset_processing"
    ]

    assert processing_result.observations_processed == 0
    assert processing_result.assets_before_deduplication == 0
    assert processing_result.assets_after_deduplication == 0
    assert processing_result.assets == []


def test_complete_pipeline_never_requires_external_network():
    """The integration pipeline uses only deterministic fixture data."""
    context = make_context()

    engine = make_engine(
        context,
        [
            {
                "value": "lab.example.com",
                "type": "HOSTNAME",
                "source": "fixture",
            }
        ],
    )

    result = engine.run()

    assert result.completed is True

    asset = result.stage_results[
        "asset_processing"
    ].assets[0]

    assert asset.normalized_value == "lab.example.com"