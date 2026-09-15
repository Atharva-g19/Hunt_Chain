"""Unit tests for the Attack Surface pipeline stage."""

from __future__ import annotations

from hunt_chain_recon.authorization.models import (
    AuthorizationDecision,
    AuthorizationResult,
)
from hunt_chain_recon.config.models import (
    AuthorizationConfig,
    ExecutionConfig,
    ReconConfig,
    TargetConfig,
)
from hunt_chain_recon.models.assets import (
    Asset,
    AssetType,
)
from hunt_chain_recon.models.dns import (
    DNSObservation,
    DNSRecord,
    DNSRecordType,
    DNSResolutionStatus,
)
from hunt_chain_recon.models.run import (
    ExecutionMode,
    ReconRun,
)
from hunt_chain_recon.pipeline.attack_surface import (
    ATTACK_SURFACE_STATE_KEY,
    AttackSurfaceStage,
    AttackSurfaceStageError,
)
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.policy.execution import ExecutionPolicy
from hunt_chain_recon.policy.politeness import PolitenessController
from hunt_chain_recon.pipeline.dns import (
    DNSStageResult,
)
from hunt_chain_recon.pipeline.dns_analysis import (
    DNSAnalysisStageResult,
)
from hunt_chain_recon.providers.base import ProviderResult


def make_config(
    *,
    execution_mode: str = "active",
) -> ReconConfig:
    """Create a minimal valid Project 2 configuration."""

    return ReconConfig(
        target=TargetConfig(
            value="example.com",
            type="DOMAIN",
        ),
        authorization=AuthorizationConfig(
            provider="scopeguard",
            reference="test-reference",
        ),
        execution=ExecutionConfig(
            mode=execution_mode,
        ),
    )


def make_authorization() -> AuthorizationResult:
    """Create an authorized ScopeGuard result."""

    return AuthorizationResult(
        target="example.com",
        decision=AuthorizationDecision.IN_SCOPE,
        provider="scopeguard",
        reference="test-reference",
    )


def make_unauthorized_authorization() -> AuthorizationResult:
    """Create an unauthorized ScopeGuard result."""

    return AuthorizationResult(
        target="example.com",
        decision=AuthorizationDecision.OUT_OF_SCOPE,
        provider="scopeguard",
        reference="test-reference",
    )


def make_context(
    *,
    execution_mode: str = "active",
) -> PipelineContext:
    """Create a valid authorized pipeline context."""

    config = make_config(
        execution_mode=execution_mode,
    )

    run = ReconRun.create(
        target="example.com",
        execution_mode=ExecutionMode(
            execution_mode
        ),
    )

    return PipelineContext(
        config=config,
        authorization=make_authorization(),
        execution_policy=ExecutionPolicy(
            config.execution
        ),
        politeness=PolitenessController(
            config.politeness
        ),
        run=run,
    )


def make_hostname() -> Asset:
    """Create a canonical hostname asset."""

    return Asset(
        value="www.example.com",
        normalized_value="www.example.com",
        type=AssetType.HOSTNAME,
        sources=["test"],
    )


def make_ip() -> Asset:
    """Create a canonical IP asset."""

    return Asset(
        value="192.0.2.10",
        normalized_value="192.0.2.10",
        type=AssetType.IP_ADDRESS,
        sources=["test"],
    )


def make_dns(
    hostname: str = "www.example.com",
    value: str = "192.0.2.10",
) -> DNSObservation:
    """Create a resolved A record observation."""

    return DNSObservation(
        hostname=hostname,
        status=DNSResolutionStatus.RESOLVED,
        records=[
            DNSRecord(
                record_type=DNSRecordType.A,
                value=value,
            )
        ],
    )


def make_dns_stage_result(
    observations: list[DNSObservation],
) -> DNSStageResult:
    """Create a DNS stage result."""

    return DNSStageResult(
        provider_result=ProviderResult(
            status="SUCCESS",
            observations=observations,
            errors=[],
            provider="test",
            version="1.0.0",
            metadata={},
        ),
        hostnames_processed=len(
            observations
        ),
    )


def make_dns_analysis_result() -> DNSAnalysisStageResult:
    """Create an empty DNS analysis result."""

    return DNSAnalysisStageResult(
        indicators=[],
        cname_targets_processed=0,
        target_observations=[],
        metadata={},
    )


def test_builds_attack_surface_from_pipeline_state() -> None:
    """Stage builds an Attack Surface from canonical pipeline state."""

    context = make_context()

    hostname = make_hostname()
    ip = make_ip()
    dns = make_dns()

    context.set_state(
        "assets",
        [
            hostname,
            ip,
        ],
    )

    context.set_state(
        "dns_results",
        make_dns_stage_result(
            [dns]
        ),
    )

    context.set_state(
        "dns_analysis_results",
        make_dns_analysis_result(),
    )

    result = AttackSurfaceStage().execute(
        context
    )

    assert result.attack_surface.schema_version == "v1"

    assert result.assets_included == 2
    assert result.indicators_included == 0
    assert result.relationships_created == 1

    assert len(
        result.attack_surface.assets
    ) == 2

    assert len(
        result.attack_surface.dns_observations
    ) == 1

    assert len(
        result.attack_surface.relationships
    ) == 1

    assert context.get_state(
        ATTACK_SURFACE_STATE_KEY
    ) is result


def test_builds_attack_surface_without_dns_state() -> None:
    """Attack Surface assembly can proceed when DNS is disabled."""

    context = make_context()

    hostname = make_hostname()

    context.set_state(
        "assets",
        [hostname],
    )

    result = AttackSurfaceStage().execute(
        context
    )

    assert result.attack_surface.schema_version == "v1"

    assert result.attack_surface.assets == [
        hostname
    ]

    assert result.attack_surface.dns_observations == []
    assert result.attack_surface.indicators == []
    assert result.attack_surface.relationships == []


def test_requires_authorization() -> None:
    """Unauthorized execution is rejected."""

    context = make_context()

    context.authorization = make_unauthorized_authorization()

    context.set_state(
        "assets",
        [make_hostname()],
    )

    try:
        AttackSurfaceStage().execute(
            context
        )
    except PermissionError:
        pass
    else:
        raise AssertionError(
            "Expected PermissionError"
        )


def test_requires_assets() -> None:
    """Canonical assets are required."""

    context = make_context()

    try:
        AttackSurfaceStage().execute(
            context
        )
    except AttackSurfaceStageError as exc:
        assert (
            "requires canonical assets"
            in str(exc)
        )
    else:
        raise AssertionError(
            "Expected AttackSurfaceStageError"
        )


def test_rejects_invalid_assets_state() -> None:
    """Invalid asset state is rejected."""

    context = make_context()

    context.set_state(
        "assets",
        ["invalid"],
    )

    try:
        AttackSurfaceStage().execute(
            context
        )
    except AttackSurfaceStageError as exc:
        assert (
            "contains an invalid Asset"
            in str(exc)
        )
    else:
        raise AssertionError(
            "Expected AttackSurfaceStageError"
        )


def test_rejects_invalid_dns_state() -> None:
    """Invalid DNS stage state is rejected."""

    context = make_context()

    context.set_state(
        "assets",
        [make_hostname()],
    )

    context.set_state(
        "dns_results",
        "invalid",
    )

    try:
        AttackSurfaceStage().execute(
            context
        )
    except AttackSurfaceStageError as exc:
        assert (
            "dns_results"
            in str(exc)
        )
    else:
        raise AssertionError(
            "Expected AttackSurfaceStageError"
        )


def test_rejects_invalid_dns_analysis_state() -> None:
    """Invalid DNS analysis state is rejected."""

    context = make_context()

    context.set_state(
        "assets",
        [make_hostname()],
    )

    context.set_state(
        "dns_analysis_results",
        "invalid",
    )

    try:
        AttackSurfaceStage().execute(
            context
        )
    except AttackSurfaceStageError as exc:
        assert (
            "dns_analysis_results"
            in str(exc)
        )
    else:
        raise AssertionError(
            "Expected AttackSurfaceStageError"
        )


def test_passive_only_mode_allows_attack_surface_assembly() -> None:
    """Deterministic assembly is permitted in passive-only mode."""

    context = make_context(
        execution_mode="passive_only",
    )

    context.set_state(
        "assets",
        [make_hostname()],
    )

    result = AttackSurfaceStage().execute(
        context
    )

    assert result.attack_surface.schema_version == "v1"


def test_stage_makes_no_network_requests() -> None:
    """The stage only consumes existing pipeline state."""

    context = make_context()

    context.set_state(
        "assets",
        [make_hostname()],
    )

    result = AttackSurfaceStage().execute(
        context
    )

    assert result.attack_surface.schema_version == "v1"