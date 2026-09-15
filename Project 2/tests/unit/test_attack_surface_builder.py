"""Unit tests for the Attack Surface Model builder."""

from __future__ import annotations

from hunt_chain_recon.authorization.models import AuthorizationResult
from hunt_chain_recon.config.models import (
    AuthorizationConfig,
    ExecutionConfig,
    TargetConfig,
)
from hunt_chain_recon.models.attack_surface import AttackSurface
from hunt_chain_recon.models.run import (
    ExecutionMode,
    ReconRun,
)
from hunt_chain_recon.processing.attack_surface import (
    AttackSurfaceBuilder,
    AttackSurfaceBuilderError,
)


def make_target() -> TargetConfig:
    """Create a test target configuration."""

    return TargetConfig(
        value="Example.COM",
        type="DOMAIN",
    )


def make_authorization() -> AuthorizationConfig:
    """Create a test authorization configuration."""

    return AuthorizationConfig(
        provider="scopeguard",
        reference="test-reference",
    )


def make_execution() -> ExecutionConfig:
    """Create a test execution configuration."""

    return ExecutionConfig(
        mode="active",
    )


def make_run() -> ReconRun:
    """Create test reconnaissance metadata."""

    return ReconRun.create(
        target="example.com",
        execution_mode=ExecutionMode.ACTIVE,
    )


def test_builds_empty_attack_surface() -> None:
    """The builder can create a valid empty Attack Surface V1."""

    attack_surface = AttackSurfaceBuilder().build(
        run=make_run(),
        target=make_target(),
        authorization=make_authorization(),
        execution=make_execution(),
    )

    assert isinstance(
        attack_surface,
        AttackSurface,
    )

    assert attack_surface.schema_version == "v1"
    assert attack_surface.run.target == "example.com"
    assert attack_surface.target.value == "Example.COM"

    assert attack_surface.assets == []
    assert attack_surface.dns_observations == []
    assert attack_surface.services == []
    assert attack_surface.endpoints == []
    assert attack_surface.http_observations == []
    assert attack_surface.technologies == []
    assert attack_surface.technology_evidence == []
    assert attack_surface.indicators == []
    assert attack_surface.relationships == []


def test_builds_attack_surface_with_metadata() -> None:
    """Builder preserves run-level metadata."""

    attack_surface = AttackSurfaceBuilder().build(
        run=make_run(),
        target=make_target(),
        authorization=make_authorization(),
        execution=make_execution(),
        metadata={
            "provider_count": 2,
            "test_mode": True,
        },
    )

    assert attack_surface.metadata == {
        "provider_count": 2,
        "test_mode": True,
    }


def test_copies_collection_values() -> None:
    """Builder creates owned list values for collection fields."""

    assets: list = []
    relationships: list = []

    attack_surface = AttackSurfaceBuilder().build(
        run=make_run(),
        target=make_target(),
        authorization=make_authorization(),
        execution=make_execution(),
        assets=assets,
        relationships=relationships,
    )

    assert attack_surface.assets is not assets
    assert attack_surface.relationships is not relationships


def test_rejects_invalid_run() -> None:
    """Builder rejects a non-ReconRun value."""

    try:
        AttackSurfaceBuilder().build(
            run="invalid",  # type: ignore[arg-type]
            target=make_target(),
            authorization=make_authorization(),
            execution=make_execution(),
        )
    except AttackSurfaceBuilderError as exc:
        assert "run must be ReconRun" in str(exc)
    else:
        raise AssertionError(
            "Expected AttackSurfaceBuilderError"
        )


def test_rejects_invalid_target() -> None:
    """Builder rejects a non-TargetConfig value."""

    try:
        AttackSurfaceBuilder().build(
            run=make_run(),
            target="example.com",  # type: ignore[arg-type]
            authorization=make_authorization(),
            execution=make_execution(),
        )
    except AttackSurfaceBuilderError as exc:
        assert "target must be TargetConfig" in str(exc)
    else:
        raise AssertionError(
            "Expected AttackSurfaceBuilderError"
        )


def test_rejects_invalid_authorization() -> None:
    """Builder rejects a non-AuthorizationConfig value."""

    try:
        AttackSurfaceBuilder().build(
            run=make_run(),
            target=make_target(),
            authorization="invalid",  # type: ignore[arg-type]
            execution=make_execution(),
        )
    except AttackSurfaceBuilderError as exc:
        assert (
            "authorization must be AuthorizationConfig"
            in str(exc)
        )
    else:
        raise AssertionError(
            "Expected AttackSurfaceBuilderError"
        )


def test_rejects_invalid_execution() -> None:
    """Builder rejects a non-ExecutionConfig value."""

    try:
        AttackSurfaceBuilder().build(
            run=make_run(),
            target=make_target(),
            authorization=make_authorization(),
            execution="invalid",  # type: ignore[arg-type]
        )
    except AttackSurfaceBuilderError as exc:
        assert (
            "execution must be ExecutionConfig"
            in str(exc)
        )
    else:
        raise AssertionError(
            "Expected AttackSurfaceBuilderError"
        )


def test_rejects_invalid_collection_item() -> None:
    """Builder rejects invalid objects inside collection fields."""

    try:
        AttackSurfaceBuilder().build(
            run=make_run(),
            target=make_target(),
            authorization=make_authorization(),
            execution=make_execution(),
            assets=["invalid"],  # type: ignore[list-item]
        )
    except AttackSurfaceBuilderError as exc:
        assert (
            "assets[0] must be Asset"
            in str(exc)
        )
    else:
        raise AssertionError(
            "Expected AttackSurfaceBuilderError"
        )


def test_rejects_invalid_metadata() -> None:
    """Builder rejects metadata that is not a dictionary."""

    try:
        AttackSurfaceBuilder().build(
            run=make_run(),
            target=make_target(),
            authorization=make_authorization(),
            execution=make_execution(),
            metadata=["invalid"],  # type: ignore[arg-type]
        )
    except AttackSurfaceBuilderError as exc:
        assert "metadata must be a dictionary" in str(exc)
    else:
        raise AssertionError(
            "Expected AttackSurfaceBuilderError"
        )


def test_attack_surface_validation_is_preserved() -> None:
    """Builder does not bypass AttackSurface's own validation."""

    invalid_run = ReconRun.create(
        target="different.example.com",
        execution_mode=ExecutionMode.ACTIVE,
    )

    try:
        AttackSurfaceBuilder().build(
            run=invalid_run,
            target=make_target(),
            authorization=make_authorization(),
            execution=make_execution(),
        )
    except ValueError as exc:
        assert (
            "Run target must match"
            in str(exc)
        )
    else:
        raise AssertionError(
            "Expected AttackSurface validation failure"
        )


def test_builder_does_not_make_network_requests() -> None:
    """Building an Attack Surface requires no network operations."""

    attack_surface = AttackSurfaceBuilder().build(
        run=make_run(),
        target=make_target(),
        authorization=make_authorization(),
        execution=make_execution(),
    )

    assert attack_surface.schema_version == "v1"


def test_execution_mode_is_preserved() -> None:
    """The configured execution mode is preserved in the model."""

    execution = ExecutionConfig(
        mode="passive_only",
    )

    attack_surface = AttackSurfaceBuilder().build(
        run=ReconRun.create(
            target="example.com",
            execution_mode=ExecutionMode.PASSIVE_ONLY,
        ),
        target=make_target(),
        authorization=make_authorization(),
        execution=execution,
    )

    assert attack_surface.execution.mode == "passive_only"
    assert attack_surface.run.execution_mode == (
        ExecutionMode.PASSIVE_ONLY
    )