"""Safety tests for the Hunt_Chain Project 2 pipeline engine.

These tests verify that:

- unauthorized targets never execute pipeline stages,
- passive-only mode blocks active activities,
- active mode permits allowed activities,
- stages execute in their registered order,
- duplicate stage names are rejected,
- stage failures are reported correctly.

No network activity is performed.
"""

from __future__ import annotations

from typing import Any

import pytest

from hunt_chain_recon.authorization import AuthorizationResult
from hunt_chain_recon.config.loader import load_config
from hunt_chain_recon.config.models import ExecutionConfig
from hunt_chain_recon.models import ReconRun
from hunt_chain_recon.pipeline import (
    PipelineEngine,
    PipelineStage,
)
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.policy import (
    ExecutionActivity,
    ExecutionPolicy,
    PolitenessController,
)


def build_context(
    decision: str = "IN_SCOPE",
    mode: str = "active",
) -> PipelineContext:
    """Build a deterministic pipeline context for testing."""
    config = load_config("config/default.yaml")

    execution_config = ExecutionConfig(mode=mode)

    authorization = AuthorizationResult(
        target=config.target.value,
        decision=decision,
        provider="scopeguard",
        reference="test-reference",
    )

    run = ReconRun(
        target=config.target.value,
        execution_mode=execution_config.mode,
    )

    return PipelineContext(
        config=config,
        authorization=authorization,
        execution_policy=ExecutionPolicy(execution_config),
        politeness=PolitenessController(config.politeness),
        run=run,
    )


def test_unauthorized_target_blocks_all_stages() -> None:
    """Verify that a non-authorized target executes zero stages."""
    context = build_context(
        decision="OUT_OF_SCOPE",
        mode="active",
    )

    executed: list[str] = []

    def stage_handler(_: PipelineContext) -> str:
        executed.append("executed")
        return "should-not-run"

    engine = PipelineEngine(context)

    engine.add_stage(
        PipelineStage(
            name="test-stage",
            activity=ExecutionActivity.PASSIVE_DISCOVERY,
            handler=stage_handler,
        )
    )

    result = engine.run()

    assert result.completed is False
    assert result.blocked is True
    assert result.stage_results == {}
    assert executed == []


def test_unknown_authorization_blocks_all_stages() -> None:
    """Verify that UNKNOWN authorization fails closed."""
    context = build_context(
        decision="UNKNOWN",
        mode="active",
    )

    executed: list[str] = []

    def stage_handler(_: PipelineContext) -> None:
        executed.append("executed")

    engine = PipelineEngine(context)

    engine.add_stage(
        PipelineStage(
            name="test-stage",
            activity=ExecutionActivity.PASSIVE_DISCOVERY,
            handler=stage_handler,
        )
    )

    result = engine.run()

    assert result.completed is False
    assert result.blocked is True
    assert executed == []


def test_passive_only_blocks_http_probing() -> None:
    """Verify that passive-only mode blocks HTTP probing."""
    context = build_context(
        decision="IN_SCOPE",
        mode="passive_only",
    )

    executed: list[str] = []

    def http_stage(_: PipelineContext) -> str:
        executed.append("http")
        return "should-not-run"

    engine = PipelineEngine(context)

    engine.add_stage(
        PipelineStage(
            name="http-probe",
            activity=ExecutionActivity.HTTP_PROBING,
            handler=http_stage,
        )
    )

    result = engine.run()

    assert result.completed is False
    assert result.blocked is True
    assert result.failed_stage == "http-probe"
    assert executed == []


def test_passive_only_allows_passive_discovery() -> None:
    """Verify that passive-only mode permits passive discovery."""
    context = build_context(
        decision="IN_SCOPE",
        mode="passive_only",
    )

    executed: list[str] = []

    def discovery_stage(_: PipelineContext) -> str:
        executed.append("discovery")
        return "discovery-complete"

    engine = PipelineEngine(context)

    engine.add_stage(
        PipelineStage(
            name="passive-discovery",
            activity=ExecutionActivity.PASSIVE_DISCOVERY,
            handler=discovery_stage,
        )
    )

    result = engine.run()

    assert result.completed is True
    assert result.blocked is False
    assert result.stage_results == {
        "passive-discovery": "discovery-complete",
    }
    assert executed == ["discovery"]


def test_active_mode_allows_allowed_activity() -> None:
    """Verify that active mode permits HTTP probing."""
    context = build_context(
        decision="IN_SCOPE",
        mode="active",
    )

    executed: list[str] = []

    def http_stage(_: PipelineContext) -> str:
        executed.append("http")
        return "http-complete"

    engine = PipelineEngine(context)

    engine.add_stage(
        PipelineStage(
            name="http-probe",
            activity=ExecutionActivity.HTTP_PROBING,
            handler=http_stage,
        )
    )

    result = engine.run()

    assert result.completed is True
    assert result.blocked is False
    assert result.stage_results == {
        "http-probe": "http-complete",
    }
    assert executed == ["http"]


def test_stages_execute_in_registered_order() -> None:
    """Verify that stages execute in the order they were registered."""
    context = build_context(
        decision="IN_SCOPE",
        mode="active",
    )

    execution_order: list[str] = []

    def first_stage(_: PipelineContext) -> str:
        execution_order.append("first")
        return "first-result"

    def second_stage(_: PipelineContext) -> str:
        execution_order.append("second")
        return "second-result"

    engine = PipelineEngine(context)

    engine.add_stage(
        PipelineStage(
            name="first",
            activity=ExecutionActivity.PASSIVE_DISCOVERY,
            handler=first_stage,
        )
    )

    engine.add_stage(
        PipelineStage(
            name="second",
            activity=ExecutionActivity.DNS_RESOLUTION,
            handler=second_stage,
        )
    )

    result = engine.run()

    assert result.completed is True
    assert execution_order == [
        "first",
        "second",
    ]
    assert result.stage_results == {
        "first": "first-result",
        "second": "second-result",
    }


def test_duplicate_stage_names_are_rejected() -> None:
    """Verify that stage names must be unique."""
    context = build_context()

    engine = PipelineEngine(context)

    stage = PipelineStage(
        name="duplicate",
        activity=ExecutionActivity.PASSIVE_DISCOVERY,
        handler=lambda _: None,
    )

    engine.add_stage(stage)

    with pytest.raises(ValueError):
        engine.add_stage(stage)


def test_stage_exception_is_reported_without_claiming_completion() -> None:
    """Verify that an unexpected stage exception fails the pipeline."""
    context = build_context()

    def failing_stage(_: PipelineContext) -> Any:
        raise RuntimeError("simulated stage failure")

    engine = PipelineEngine(context)

    engine.add_stage(
        PipelineStage(
            name="failing-stage",
            activity=ExecutionActivity.PASSIVE_DISCOVERY,
            handler=failing_stage,
        )
    )

    result = engine.run()

    assert result.completed is False
    assert result.blocked is False
    assert result.failed_stage == "failing-stage"
    assert "simulated stage failure" in (result.error or "")