"""Tests for the canonical asset merge stage."""

from __future__ import annotations

from hunt_chain_recon.authorization.models import (
    AuthorizationDecision,
    AuthorizationResult,
)
from hunt_chain_recon.config.models import ReconConfig
from hunt_chain_recon.models.assets import Asset
from hunt_chain_recon.models.run import ReconRun
from hunt_chain_recon.pipeline.asset_merge import (
    AssetMergeStage,
    AssetMergeStageError,
)
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.policy.execution import ExecutionPolicy
from hunt_chain_recon.policy.politeness import PolitenessController


def make_context() -> PipelineContext:
    """Create an authorized test context."""

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

    return PipelineContext(
        config=config,
        authorization=authorization,
        execution_policy=ExecutionPolicy(
            config.execution
        ),
        politeness=PolitenessController(
            config.politeness
        ),
        run=run,
    )


def make_asset(
    value: str,
    asset_type: str,
    source: str,
) -> Asset:
    """Create a canonical asset suitable for deduplication tests."""

    return Asset(
        value=value,
        normalized_value=value.lower().rstrip("."),
        type=asset_type,
        sources=[source],
    )


def test_merge_includes_target_when_no_discovery_assets_exist() -> None:
    """The configured target remains available when discovery is empty."""

    context = make_context()

    target_asset = make_asset(
        "example.com",
        "DOMAIN",
        "configured_target",
    )

    context.set_state(
        "target_asset",
        target_asset,
    )

    stage = AssetMergeStage()

    result = stage.execute(context)

    assert result.assets == [target_asset]
    assert result.target_assets == 1
    assert result.discovered_assets == 0
    assert result.assets_before_deduplication == 1
    assert result.assets_after_deduplication == 1

    assert context.get_state("assets") == [
        target_asset
    ]


def test_merge_combines_target_and_discovered_assets() -> None:
    """Target and discovered assets are combined."""

    context = make_context()

    target_asset = make_asset(
        "example.com",
        "DOMAIN",
        "configured_target",
    )

    discovered_asset = make_asset(
        "api.example.com",
        "HOSTNAME",
        "certificate_transparency",
    )

    context.set_state(
        "target_asset",
        target_asset,
    )

    context.set_state(
        "assets",
        [discovered_asset],
    )

    stage = AssetMergeStage()

    result = stage.execute(context)

    assert result.target_assets == 1
    assert result.discovered_assets == 1
    assert result.assets_before_deduplication == 2
    assert result.assets_after_deduplication == 2

    assert target_asset in result.assets
    assert discovered_asset in result.assets

    assert context.get_state("assets") == result.assets


def test_merge_deduplicates_target_when_discovery_returns_same_asset() -> None:
    """A discovered copy of the target does not create a duplicate."""

    context = make_context()

    target_asset = make_asset(
        "example.com",
        "DOMAIN",
        "configured_target",
    )

    discovered_copy = make_asset(
        "example.com",
        "DOMAIN",
        "certificate_transparency",
    )

    context.set_state(
        "target_asset",
        target_asset,
    )

    context.set_state(
        "assets",
        [discovered_copy],
    )

    stage = AssetMergeStage()

    result = stage.execute(context)

    assert result.assets_before_deduplication == 2
    assert result.assets_after_deduplication == 1
    assert len(result.assets) == 1
    assert result.assets[0].normalized_value == "example.com"


def test_merge_allows_missing_discovery_assets() -> None:
    """Missing discovery asset state is treated as an empty discovery set."""

    context = make_context()

    target_asset = make_asset(
        "127.0.0.1",
        "IP_ADDRESS",
        "configured_target",
    )

    context.set_state(
        "target_asset",
        target_asset,
    )

    context.set_state(
        "assets",
        None,
    )

    stage = AssetMergeStage()

    result = stage.execute(context)

    assert result.assets == [target_asset]
    assert result.discovered_assets == 0


def test_merge_rejects_missing_target_asset() -> None:
    """The merge stage requires the explicitly configured target asset."""

    context = make_context()

    stage = AssetMergeStage()

    try:
        stage.execute(context)
    except AssetMergeStageError as exc:
        assert "target asset" in str(exc).lower()
    else:
        raise AssertionError(
            "Expected AssetMergeStageError."
        )


def test_merge_rejects_invalid_target_asset() -> None:
    """Invalid target state is rejected."""

    context = make_context()

    context.set_state(
        "target_asset",
        {"value": "example.com"},
    )

    stage = AssetMergeStage()

    try:
        stage.execute(context)
    except AssetMergeStageError as exc:
        assert "target asset" in str(exc).lower()
    else:
        raise AssertionError(
            "Expected AssetMergeStageError."
        )


def test_merge_rejects_invalid_discovered_asset_list() -> None:
    """Invalid discovered asset state is rejected."""

    context = make_context()

    target_asset = make_asset(
        "example.com",
        "DOMAIN",
        "configured_target",
    )

    context.set_state(
        "target_asset",
        target_asset,
    )

    context.set_state(
        "assets",
        ["not-an-asset"],
    )

    stage = AssetMergeStage()

    try:
        stage.execute(context)
    except AssetMergeStageError as exc:
        assert "invalid asset" in str(exc).lower()
    else:
        raise AssertionError(
            "Expected AssetMergeStageError."
        )


def test_merge_requires_authorization() -> None:
    """Unauthorized execution is rejected."""

    context = make_context()

    context.authorization = AuthorizationResult(
        target=context.config.target.value,
        decision=AuthorizationDecision.OUT_OF_SCOPE,
        provider=context.config.authorization.provider,
        reference=context.config.authorization.reference,
    )

    target_asset = make_asset(
        "example.com",
        "DOMAIN",
        "configured_target",
    )

    context.set_state(
        "target_asset",
        target_asset,
    )

    stage = AssetMergeStage()

    try:
        stage.execute(context)
    except Exception as exc:
        assert "authorized" in str(exc).lower()
    else:
        raise AssertionError(
            "Expected authorization failure."
        )


def test_merge_performs_no_network_activity() -> None:
    """Merge metadata explicitly records that no network activity occurs."""

    context = make_context()

    target_asset = make_asset(
        "127.0.0.1",
        "IP_ADDRESS",
        "configured_target",
    )

    context.set_state(
        "target_asset",
        target_asset,
    )

    result = AssetMergeStage().execute(
        context
    )

    assert result.metadata["network_activity"] is False
    assert result.metadata["target_always_included"] is True