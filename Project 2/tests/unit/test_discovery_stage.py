"""Tests for the Hunt_Chain Project 2 discovery pipeline stage."""

from __future__ import annotations

from pathlib import Path

import pytest

from hunt_chain_recon.authorization.models import AuthorizationResult
from hunt_chain_recon.config.loader import load_config
from hunt_chain_recon.models.run import ReconRun
from hunt_chain_recon.pipeline.discovery import (
    DISCOVERY_RESULTS_STATE_KEY,
    DiscoveryStage,
    DiscoveryStageError,
    DiscoveryStageResult,
)
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.policy.execution import ExecutionPolicy
from hunt_chain_recon.policy.politeness import PolitenessController
from hunt_chain_recon.providers.base import (
    ProviderError,
    ProviderResult,
)
from hunt_chain_recon.providers.discovery.registry import (
    DiscoveryProviderRegistry,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_CONFIG_PATH = PROJECT_ROOT / "config" / "default.yaml"


class FakeDiscoveryProvider:
    """Minimal provider fixture for discovery-stage tests."""

    def __init__(
        self,
        *,
        result: ProviderResult,
    ) -> None:
        self._result = result

    @property
    def name(self) -> str:
        return "fake-discovery"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> tuple[str, ...]:
        return (
            "passive_discovery",
            "hostname_discovery",
        )

    def discover(
        self,
        target: str,
    ) -> ProviderResult:
        return self._result


class FailingDiscoveryProvider:
    """Provider fixture that returns a controlled FAILED result."""

    @property
    def name(self) -> str:
        return "failing-discovery"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> tuple[str, ...]:
        return (
            "passive_discovery",
        )

    def discover(
        self,
        target: str,
    ) -> ProviderResult:
        return ProviderResult(
            status="FAILED",
            observations=[],
            errors=[],
            provider=self.name,
            version=self.version,
            metadata={},
        )


class InvalidResultProvider:
    """Provider fixture that violates the ProviderResult contract."""

    @property
    def name(self) -> str:
        return "invalid-discovery"

    @property
    def version(self) -> str:
        return "1.0.0"

    @property
    def capabilities(self) -> tuple[str, ...]:
        return (
            "passive_discovery",
        )

    def discover(
        self,
        target: str,
    ):
        return {
            "observations": [],
        }


def build_context(
    provider_name: str = "fake_discovery",
    *,
    authorized: bool = True,
) -> PipelineContext:
    """Build a pipeline context for discovery tests."""
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


def configure_provider(
    context: PipelineContext,
    provider_name: str,
) -> None:
    """Enable only the requested discovery provider in test config."""
    context.config.discovery.providers.__dict__


def register_provider(
    registry: DiscoveryProviderRegistry,
    name: str,
    provider_factory,
) -> None:
    """Register a provider fixture."""
    registry.register(
        name,
        provider_factory,
    )


def make_result(
    *,
    status: str = "SUCCESS",
    provider: str = "fake-discovery",
    observations: list[dict] | None = None,
    errors: list[ProviderError] | None = None,
) -> ProviderResult:
    """Create a ProviderResult fixture."""
    return ProviderResult(
        status=status,
        observations=observations or [],
        errors=errors or [],
        provider=provider,
        version="1.0.0",
        metadata={},
    )


def make_config_with_provider(
    provider_name: str,
):
    """Return a config whose enabled provider matches the test registry."""
    config = load_config(DEFAULT_CONFIG_PATH)

    provider_data = {
        provider_name: {
            "enabled": True,
        }
    }

    config.discovery.providers = (
        type(config.discovery.providers).model_validate(
            provider_data
        )
    )

    return config


def make_context_with_config(
    config,
    *,
    authorized: bool = True,
) -> PipelineContext:
    """Build a context from a supplied configuration."""
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


def test_discovery_stage_executes_enabled_provider():
    """Enabled discovery providers are executed."""
    config = make_config_with_provider(
        "fake_discovery"
    )

    context = make_context_with_config(config)

    registry = DiscoveryProviderRegistry()

    result = make_result(
        observations=[
            {
                "value": "www.example.com",
                "type": "HOSTNAME",
                "source": "fake-discovery",
            }
        ]
    )

    register_provider(
        registry,
        "fake_discovery",
        lambda: FakeDiscoveryProvider(
            result=result
        ),
    )

    stage = DiscoveryStage(registry)

    stage_result = stage.execute(context)

    assert isinstance(
        stage_result,
        DiscoveryStageResult,
    )

    assert "fake_discovery" in (
        stage_result.provider_results
    )

    assert (
        stage_result.provider_results[
            "fake_discovery"
        ].observations
        == [
            {
                "value": "www.example.com",
                "type": "HOSTNAME",
                "source": "fake-discovery",
            }
        ]
    )


def test_discovery_stage_stores_result_in_pipeline_state():
    """Discovery results are stored in pipeline state."""
    config = make_config_with_provider(
        "fake_discovery"
    )

    context = make_context_with_config(config)

    registry = DiscoveryProviderRegistry()

    result = make_result()

    register_provider(
        registry,
        "fake_discovery",
        lambda: FakeDiscoveryProvider(
            result=result
        ),
    )

    stage = DiscoveryStage(registry)

    stage_result = stage.execute(context)

    stored_result = context.get_state(
        DISCOVERY_RESULTS_STATE_KEY
    )

    assert stored_result == stage_result


def test_discovery_stage_preserves_provider_failure_result():
    """Provider failures remain provider results, not stage failures."""
    config = make_config_with_provider(
        "failing_discovery"
    )

    context = make_context_with_config(config)

    registry = DiscoveryProviderRegistry()

    register_provider(
        registry,
        "failing_discovery",
        FailingDiscoveryProvider,
    )

    stage = DiscoveryStage(registry)

    result = stage.execute(context)

    assert result.has_failures is True
    assert result.failed_providers == (
        "failing_discovery",
    )

    provider_result = result.provider_results[
        "failing_discovery"
    ]

    assert provider_result.status.value == "FAILED"
    assert provider_result.provider == "failing-discovery"


def test_discovery_stage_classifies_successful_provider():
    """SUCCESS provider results are classified correctly."""
    config = make_config_with_provider(
        "fake_discovery"
    )

    context = make_context_with_config(config)

    registry = DiscoveryProviderRegistry()

    register_provider(
        registry,
        "fake_discovery",
        lambda: FakeDiscoveryProvider(
            result=make_result(
                status="SUCCESS",
                provider="fake-discovery",
            )
        ),
    )

    result = DiscoveryStage(registry).execute(
        context
    )

    assert result.successful_providers == (
        "fake_discovery",
    )
    assert result.partial_providers == ()
    assert result.failed_providers == ()
    assert result.skipped_providers == ()
    assert result.has_failures is False


def test_discovery_stage_classifies_partial_provider():
    """PARTIAL provider results are classified correctly."""
    config = make_config_with_provider(
        "fake_discovery"
    )

    context = make_context_with_config(config)

    registry = DiscoveryProviderRegistry()

    register_provider(
        registry,
        "fake_discovery",
        lambda: FakeDiscoveryProvider(
            result=make_result(
                status="PARTIAL",
                provider="fake-discovery",
            )
        ),
    )

    result = DiscoveryStage(registry).execute(
        context
    )

    assert result.successful_providers == ()
    assert result.partial_providers == (
        "fake_discovery",
    )
    assert result.failed_providers == ()
    assert result.skipped_providers == ()


def test_discovery_stage_classifies_failed_provider():
    """FAILED provider results are classified correctly."""
    config = make_config_with_provider(
        "failing_discovery"
    )

    context = make_context_with_config(config)

    registry = DiscoveryProviderRegistry()

    register_provider(
        registry,
        "failing_discovery",
        FailingDiscoveryProvider,
    )

    result = DiscoveryStage(registry).execute(
        context
    )

    assert result.failed_providers == (
        "failing_discovery",
    )
    assert result.has_failures is True


def test_discovery_stage_classifies_skipped_provider():
    """SKIPPED provider results are classified correctly."""
    config = make_config_with_provider(
        "fake_discovery"
    )

    context = make_context_with_config(config)

    registry = DiscoveryProviderRegistry()

    register_provider(
        registry,
        "fake_discovery",
        lambda: FakeDiscoveryProvider(
            result=make_result(
                status="SKIPPED",
                provider="fake-discovery",
            )
        ),
    )

    result = DiscoveryStage(registry).execute(
        context
    )

    assert result.successful_providers == ()
    assert result.partial_providers == ()
    assert result.failed_providers == ()
    assert result.skipped_providers == (
        "fake_discovery",
    )
    assert result.has_failures is False


def test_discovery_stage_accepts_provider_name_difference():
    """Registry and provider-reported names may differ."""
    config = make_config_with_provider(
        "fake_discovery"
    )

    context = make_context_with_config(config)

    registry = DiscoveryProviderRegistry()

    register_provider(
        registry,
        "fake_discovery",
        lambda: FakeDiscoveryProvider(
            result=make_result(
                provider="fake-discovery"
            )
        ),
    )

    result = DiscoveryStage(registry).execute(
        context
    )

    assert result.provider_results[
        "fake_discovery"
    ].provider == "fake-discovery"


def test_discovery_stage_rejects_invalid_provider_result():
    """Providers that violate the common result contract are rejected."""
    config = make_config_with_provider(
        "invalid_discovery"
    )

    context = make_context_with_config(config)

    registry = DiscoveryProviderRegistry()

    register_provider(
        registry,
        "invalid_discovery",
        InvalidResultProvider,
    )

    stage = DiscoveryStage(registry)

    with pytest.raises(
        DiscoveryStageError,
        match="invalid ProviderResult",
    ):
        stage.execute(context)


def test_discovery_stage_requires_authorization():
    """Discovery cannot execute outside ScopeGuard authorization."""
    config = make_config_with_provider(
        "fake_discovery"
    )

    context = make_context_with_config(
        config,
        authorized=False,
    )

    registry = DiscoveryProviderRegistry()

    register_provider(
        registry,
        "fake_discovery",
        lambda: FakeDiscoveryProvider(
            result=make_result()
        ),
    )

    stage = DiscoveryStage(registry)

    with pytest.raises(
        PermissionError,
        match="not authorized by ScopeGuard",
    ):
        stage.execute(context)


def test_discovery_stage_respects_execution_policy():
    """Discovery requires passive-discovery permission."""
    config = make_config_with_provider(
        "fake_discovery"
    )

    config.execution.mode = "passive_only"

    context = make_context_with_config(config)

    registry = DiscoveryProviderRegistry()

    register_provider(
        registry,
        "fake_discovery",
        lambda: FakeDiscoveryProvider(
            result=make_result()
        ),
    )

    stage = DiscoveryStage(registry)

    result = stage.execute(context)

    assert isinstance(
        result,
        DiscoveryStageResult,
    )


def test_discovery_stage_rejects_unknown_provider():
    """An unknown configured provider is rejected."""
    config = make_config_with_provider(
        "unknown_provider"
    )

    context = make_context_with_config(config)

    stage = DiscoveryStage(
        DiscoveryProviderRegistry()
    )

    with pytest.raises(
        DiscoveryStageError,
        match="Unable to initialize discovery provider",
    ):
        stage.execute(context)


def test_discovery_stage_uses_default_registry():
    """The stage creates the built-in registry when none is supplied."""
    config = make_config_with_provider(
        "certificate_transparency"
    )

    context = make_context_with_config(config)

    stage = DiscoveryStage()

    result = stage.execute(context)

    assert isinstance(
        result,
        DiscoveryStageResult,
    )

    assert "certificate_transparency" in (
        result.provider_results
    )

    provider_result = result.provider_results[
        "certificate_transparency"
    ]

    assert provider_result.status.value == "FAILED"


def test_discovery_stage_skips_disabled_provider():
    """Disabled discovery providers are not executed."""
    config = load_config(DEFAULT_CONFIG_PATH)

    config.discovery.providers.certificate_transparency.enabled = False

    context = make_context_with_config(config)

    stage = DiscoveryStage()

    result = stage.execute(context)

    assert result.provider_results == {}


def test_discovery_stage_preserves_observations():
    """Provider observations are preserved without transformation."""
    config = make_config_with_provider(
        "fake_discovery"
    )

    context = make_context_with_config(config)

    observations = [
        {
            "value": "WWW.Example.COM.",
            "type": "HOSTNAME",
            "source": "certificate_transparency",
        },
        {
            "value": "api.example.com",
            "type": "HOSTNAME",
            "source": "certificate_transparency",
        },
    ]

    registry = DiscoveryProviderRegistry()

    register_provider(
        registry,
        "fake_discovery",
        lambda: FakeDiscoveryProvider(
            result=make_result(
                observations=observations
            )
        ),
    )

    result = DiscoveryStage(registry).execute(
        context
    )

    assert result.provider_results[
        "fake_discovery"
    ].observations == observations