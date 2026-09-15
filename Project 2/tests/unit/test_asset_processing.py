"""Tests for the Hunt_Chain Project 2 asset-processing pipeline stage."""

from __future__ import annotations

from pathlib import Path

import pytest

from hunt_chain_recon.authorization.models import AuthorizationResult
from hunt_chain_recon.config.loader import load_config
from hunt_chain_recon.models.run import ReconRun
from hunt_chain_recon.pipeline.asset_processing import (
    ASSETS_STATE_KEY,
    AssetProcessingStage,
    AssetProcessingStageError,
)
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.pipeline.discovery import (
    DISCOVERY_RESULTS_STATE_KEY,
    DiscoveryStageResult,
)
from hunt_chain_recon.policy.execution import ExecutionPolicy
from hunt_chain_recon.policy.politeness import PolitenessController
from hunt_chain_recon.providers.base import ProviderResult


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "default.yaml"


def make_context(
    *,
    authorized: bool = True,
) -> PipelineContext:
    """Create a pipeline context for asset-processing tests."""
    config = load_config(DEFAULT_CONFIG_PATH)

    authorization = AuthorizationResult(
        decision="IN_SCOPE" if authorized else "OUT_OF_SCOPE",
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


def make_provider_result(
    observations: list[dict] | None = None,
    *,
    status: str = "SUCCESS",
    provider: str = "test_provider",
) -> ProviderResult:
    """Create a deterministic ProviderResult."""
    return ProviderResult(
        status=status,
        observations=observations or [],
        errors=[],
        provider=provider,
        version="1.0.0",
        metadata={},
    )


def make_discovery_result(
    provider_results: dict[str, ProviderResult],
) -> DiscoveryStageResult:
    """Create a DiscoveryStageResult from provider results."""
    return DiscoveryStageResult(
        provider_results=provider_results,
    )


def test_asset_processing_normalizes_discovery_observations():
    """Raw discovery observations become canonical Assets."""
    context = make_context()

    context.set_state(
        DISCOVERY_RESULTS_STATE_KEY,
        make_discovery_result(
            {
                "test_provider": make_provider_result(
                    [
                        {
                            "value": "WWW.Example.COM.",
                            "type": "HOSTNAME",
                            "source": "ct",
                        }
                    ]
                )
            }
        ),
    )

    result = AssetProcessingStage().execute(
        context
    )

    assert result.observations_processed == 1
    assert result.assets_before_deduplication == 1
    assert result.assets_after_deduplication == 1

    assert result.assets[0].value == "WWW.Example.COM."
    assert result.assets[0].normalized_value == "www.example.com"


def test_asset_processing_deduplicates_assets():
    """Equivalent discovery observations produce one canonical Asset."""
    context = make_context()

    context.set_state(
        DISCOVERY_RESULTS_STATE_KEY,
        make_discovery_result(
            {
                "test_provider": make_provider_result(
                    [
                        {
                            "value": "WWW.Example.COM",
                            "type": "HOSTNAME",
                            "source": "ct",
                        },
                        {
                            "value": "www.example.com.",
                            "type": "HOSTNAME",
                            "source": "dns",
                        },
                    ]
                )
            }
        ),
    )

    result = AssetProcessingStage().execute(
        context
    )

    assert result.observations_processed == 2
    assert result.assets_before_deduplication == 2
    assert result.assets_after_deduplication == 1

    assert result.assets[0].normalized_value == "www.example.com"
    assert result.assets[0].sources == [
        "ct",
        "dns",
    ]


def test_asset_processing_preserves_different_asset_types():
    """Different semantic asset types remain separate."""
    context = make_context()

    context.set_state(
        DISCOVERY_RESULTS_STATE_KEY,
        make_discovery_result(
            {
                "test_provider": make_provider_result(
                    [
                        {
                            "value": "example.com",
                            "type": "DOMAIN",
                            "source": "manual",
                        },
                        {
                            "value": "example.com",
                            "type": "HOSTNAME",
                            "source": "ct",
                        },
                    ]
                )
            }
        ),
    )

    result = AssetProcessingStage().execute(
        context
    )

    assert result.assets_after_deduplication == 2
    assert result.assets[0].type == "DOMAIN"
    assert result.assets[1].type == "HOSTNAME"


def test_asset_processing_uses_provider_name_as_default_source():
    """Provider name becomes provenance when observation has no source."""
    context = make_context()

    context.set_state(
        DISCOVERY_RESULTS_STATE_KEY,
        make_discovery_result(
            {
                "certificate_transparency": make_provider_result(
                    [
                        {
                            "value": "api.example.com",
                            "type": "HOSTNAME",
                        }
                    ],
                    provider="certificate-transparency",
                )
            }
        ),
    )

    result = AssetProcessingStage().execute(
        context
    )

    assert result.assets[0].sources == [
        "certificate_transparency",
    ]


def test_asset_processing_preserves_explicit_source():
    """An explicit observation source is not overwritten."""
    context = make_context()

    context.set_state(
        DISCOVERY_RESULTS_STATE_KEY,
        make_discovery_result(
            {
                "certificate_transparency": make_provider_result(
                    [
                        {
                            "value": "api.example.com",
                            "type": "HOSTNAME",
                            "source": "custom_source",
                        }
                    ],
                    provider="certificate-transparency",
                )
            }
        ),
    )

    result = AssetProcessingStage().execute(
        context
    )

    assert result.assets[0].sources == [
        "custom_source",
    ]


def test_asset_processing_stores_assets_in_pipeline_state():
    """Processed Assets are made available to later pipeline stages."""
    context = make_context()

    context.set_state(
        DISCOVERY_RESULTS_STATE_KEY,
        make_discovery_result(
            {
                "test_provider": make_provider_result(
                    [
                        {
                            "value": "api.example.com",
                            "type": "HOSTNAME",
                            "source": "ct",
                        }
                    ]
                )
            }
        ),
    )

    result = AssetProcessingStage().execute(
        context
    )

    stored_assets = context.get_state(
        ASSETS_STATE_KEY
    )

    assert stored_assets == result.assets


def test_asset_processing_requires_discovery_results():
    """The stage fails when DiscoveryStage has not executed."""
    context = make_context()

    with pytest.raises(
        AssetProcessingStageError,
        match="Discovery results are not available",
    ):
        AssetProcessingStage().execute(context)


def test_asset_processing_rejects_invalid_discovery_state():
    """Invalid discovery state is rejected."""
    context = make_context()

    context.set_state(
        DISCOVERY_RESULTS_STATE_KEY,
        {"invalid": "state"},
    )

    with pytest.raises(
        AssetProcessingStageError,
        match="invalid discovery result",
    ):
        AssetProcessingStage().execute(context)


def test_asset_processing_rejects_unauthorized_context():
    """Asset processing cannot run without ScopeGuard authorization."""
    context = make_context(
        authorized=False,
    )

    with pytest.raises(
        PermissionError,
        match="not authorized by ScopeGuard",
    ):
        AssetProcessingStage().execute(context)


def test_asset_processing_respects_passive_discovery_policy():
    """Asset processing is classified as passive discovery."""
    assert (
        AssetProcessingStage.activity.value
        == "PASSIVE_DISCOVERY"
    )


def test_asset_processing_handles_multiple_providers():
    """Observations from multiple providers are processed together."""
    context = make_context()

    context.set_state(
        DISCOVERY_RESULTS_STATE_KEY,
        make_discovery_result(
            {
                "certificate_transparency": make_provider_result(
                    [
                        {
                            "value": "www.example.com",
                            "type": "HOSTNAME",
                            "source": "ct",
                        }
                    ],
                    provider="certificate-transparency",
                ),
                "dns": make_provider_result(
                    [
                        {
                            "value": "api.example.com",
                            "type": "HOSTNAME",
                            "source": "dns",
                        }
                    ],
                    provider="dns",
                ),
            }
        ),
    )

    result = AssetProcessingStage().execute(
        context
    )

    assert result.observations_processed == 2
    assert result.assets_after_deduplication == 2

    assert [
        asset.normalized_value
        for asset in result.assets
    ] == [
        "www.example.com",
        "api.example.com",
    ]


def test_asset_processing_handles_empty_discovery_results():
    """An empty discovery result produces no assets."""
    context = make_context()

    context.set_state(
        DISCOVERY_RESULTS_STATE_KEY,
        make_discovery_result(
            {
                "test_provider": make_provider_result(
                    []
                )
            }
        ),
    )

    result = AssetProcessingStage().execute(
        context
    )

    assert result.observations_processed == 0
    assert result.assets_before_deduplication == 0
    assert result.assets_after_deduplication == 0
    assert result.assets == []


def test_asset_processing_rejects_non_dictionary_observation():
    """Invalid provider observations are rejected."""
    context = make_context()

    provider_result = ProviderResult(
        status="SUCCESS",
        observations=[
            "www.example.com"
        ],
        errors=[],
        provider="test_provider",
        version="1.0.0",
        metadata={},
    )

    context.set_state(
        DISCOVERY_RESULTS_STATE_KEY,
        make_discovery_result(
            {
                "test_provider": provider_result
            }
        ),
    )

    with pytest.raises(
        AssetProcessingStageError,
        match="non-dictionary observation",
    ):
        AssetProcessingStage().execute(context)


def test_asset_processing_wraps_normalization_errors():
    """Normalization failures are exposed as stage-level errors."""
    context = make_context()

    context.set_state(
        DISCOVERY_RESULTS_STATE_KEY,
        make_discovery_result(
            {
                "test_provider": make_provider_result(
                    [
                        {
                            "value": "999.999.999.999",
                            "type": "IP_ADDRESS",
                            "source": "test",
                        }
                    ]
                )
            }
        ),
    )

    with pytest.raises(
        AssetProcessingStageError,
        match="Asset processing failed",
    ):
        AssetProcessingStage().execute(context)


def test_asset_processing_result_is_immutable():
    """Stage results are represented as immutable dataclasses."""
    context = make_context()

    context.set_state(
        DISCOVERY_RESULTS_STATE_KEY,
        make_discovery_result(
            {
                "test_provider": make_provider_result(
                    [
                        {
                            "value": "example.com",
                            "type": "DOMAIN",
                            "source": "test",
                        }
                    ]
                )
            }
        ),
    )

    result = AssetProcessingStage().execute(
        context
    )

    with pytest.raises(AttributeError):
        result.assets = []


def test_asset_processing_stage_has_expected_identity():
    """The stage exposes its stable pipeline identity."""
    assert AssetProcessingStage.name == "asset_processing"
    assert (
        AssetProcessingStage.activity.value
        == "PASSIVE_DISCOVERY"
    )


def test_partial_provider_observations_are_processed():
    """Useful observations from a PARTIAL provider are retained."""
    context = make_context()

    context.set_state(
        DISCOVERY_RESULTS_STATE_KEY,
        make_discovery_result(
            {
                "partial_provider": make_provider_result(
                    [
                        {
                            "value": "api.example.com",
                            "type": "HOSTNAME",
                            "source": "partial-provider",
                        },
                        {
                            "value": "admin.example.com",
                            "type": "HOSTNAME",
                            "source": "partial-provider",
                        },
                    ],
                    status="PARTIAL",
                    provider="partial-provider",
                )
            }
        ),
    )

    result = AssetProcessingStage().execute(
        context
    )

    assert result.observations_processed == 2
    assert result.assets_after_deduplication == 2

    assert [
        asset.normalized_value
        for asset in result.assets
    ] == [
        "api.example.com",
        "admin.example.com",
    ]


def test_failed_provider_observations_are_not_discarded():
    """Observations supplied alongside FAILED status remain processable."""
    context = make_context()

    context.set_state(
        DISCOVERY_RESULTS_STATE_KEY,
        make_discovery_result(
            {
                "failed_provider": make_provider_result(
                    [
                        {
                            "value": "partial.example.com",
                            "type": "HOSTNAME",
                            "source": "failed-provider",
                        }
                    ],
                    status="FAILED",
                    provider="failed-provider",
                )
            }
        ),
    )

    result = AssetProcessingStage().execute(
        context
    )

    assert result.observations_processed == 1
    assert result.assets_after_deduplication == 1
    assert result.assets[0].normalized_value == (
        "partial.example.com"
    )


def test_skipped_provider_with_no_observations_produces_no_assets():
    """A SKIPPED provider with no observations contributes no assets."""
    context = make_context()

    context.set_state(
        DISCOVERY_RESULTS_STATE_KEY,
        make_discovery_result(
            {
                "skipped_provider": make_provider_result(
                    [],
                    status="SKIPPED",
                    provider="skipped-provider",
                )
            }
        ),
    )

    result = AssetProcessingStage().execute(
        context
    )

    assert result.observations_processed == 0
    assert result.assets == []