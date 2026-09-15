"""Unit tests for the HTTP pipeline stage."""

from __future__ import annotations

from unittest.mock import MagicMock, Mock, patch
from uuid import uuid4

import pytest

from hunt_chain_recon.authorization.models import (
    AuthorizationDecision,
    AuthorizationResult,
)
from hunt_chain_recon.config.models import ReconConfig
from hunt_chain_recon.models.endpoints import Endpoint, EndpointScheme
from hunt_chain_recon.models.http import (
    HTTPObservation,
    HTTPObservationState,
)
from hunt_chain_recon.models.run import ReconRun
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.pipeline.http import (
    ENDPOINTS_STATE_KEY,
    HTTP_RESULTS_STATE_KEY,
    HTTPStage,
    HTTPStageResult,
)
from hunt_chain_recon.policy.execution import ExecutionPolicy
from hunt_chain_recon.providers.base import (
    ProviderResult,
    ProviderStatus,
)


def make_config(
    *,
    enabled: bool = True,
) -> ReconConfig:
    """Create a minimal authorized HTTP configuration."""

    return ReconConfig(
        target={
            "value": "127.0.0.1",
            "type": "IP_ADDRESS",
        },
        authorization={
            "provider": "scopeguard",
            "reference": "TEST_AUTHORIZED",
        },
        http={
            "enabled": enabled,
            "schemes": ["http", "https"],
            "ports": [8000],
            "timeout_seconds": 5,
            "follow_redirects": True,
            "max_redirects": 3,
            "verify_tls": True,
            "response": {
                "collect_headers": True,
                "collect_body_hash": True,
            },
        },
    )


def make_context(
    *,
    config: ReconConfig | None = None,
) -> PipelineContext:
    """Create an authorized pipeline context."""

    config = config or make_config()

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

    politeness = MagicMock()

    operation = MagicMock()
    operation.__enter__.return_value = None
    operation.__exit__.return_value = None

    politeness.operation.return_value = operation

    return PipelineContext(
        config=config,
        authorization=authorization,
        execution_policy=ExecutionPolicy(config.execution),
        run=run,
        politeness=politeness,
    )


def make_endpoint() -> Endpoint:
    """Create a representative HTTP endpoint."""

    return Endpoint(
        asset_id=uuid4(),
        scheme=EndpointScheme.HTTP,
        hostname="127.0.0.1",
        port=8000,
        url="http://127.0.0.1:8000",
    )


def make_observation(
    endpoint: Endpoint,
) -> HTTPObservation:
    """Create a successful HTTP observation."""

    return HTTPObservation(
        endpoint_id=endpoint.id,
        state=HTTPObservationState.SUCCESS,
        status_code=200,
        headers={
            "content-type": "text/html",
        },
        content_type="text/html",
        body_length=42,
        body_hash="abc123",
    )


def make_provider_result(
    *,
    status: ProviderStatus,
    observations: list[HTTPObservation] | None = None,
) -> ProviderResult[HTTPObservation]:
    """Create a real provider result for stage tests."""

    return ProviderResult(
        status=status,
        observations=observations or [],
        errors=[],
        provider="http-observer",
        version="1.0.0",
        metadata={},
    )


def test_stage_metadata():
    """The stage exposes the expected pipeline metadata."""

    stage = HTTPStage()

    assert stage.name == "http"
    assert stage.activity.value == "HTTP_PROBING"


def test_stage_result_defaults_to_skipped():
    """An empty stage result represents skipped work."""

    result = HTTPStageResult()

    assert result.status == ProviderStatus.SKIPPED
    assert result.provider_results == []
    assert result.observations == []


def test_stage_result_success():
    """A successful provider result produces SUCCESS."""

    endpoint = make_endpoint()

    provider_result = make_provider_result(
        status=ProviderStatus.SUCCESS,
        observations=[make_observation(endpoint)],
    )

    result = HTTPStageResult(
        provider_results=[provider_result],
        observations=provider_result.observations,
    )

    assert result.status == ProviderStatus.SUCCESS


def test_stage_result_partial():
    """A partial provider result produces PARTIAL."""

    provider_result = make_provider_result(
        status=ProviderStatus.PARTIAL,
    )

    result = HTTPStageResult(
        provider_results=[provider_result],
    )

    assert result.status == ProviderStatus.PARTIAL


def test_stage_result_failed_without_observations():
    """A failed-only provider result produces FAILED."""

    provider_result = make_provider_result(
        status=ProviderStatus.FAILED,
    )

    result = HTTPStageResult(
        provider_results=[provider_result],
    )

    assert result.status == ProviderStatus.FAILED


def test_disabled_http_is_skipped():
    """Disabled HTTP probing produces a SKIPPED provider result."""

    context = make_context(
        config=make_config(enabled=False),
    )

    stage = HTTPStage()

    result = stage.run(context)

    assert result.status == ProviderStatus.SKIPPED
    assert result.metadata["enabled"] is False
    assert result.metadata["endpoint_count"] == 0

    stored = context.get_state(HTTP_RESULTS_STATE_KEY)

    assert stored is result


def test_no_endpoints_does_not_call_provider():
    """HTTP probing does nothing when no endpoints exist."""

    context = make_context()
    stage = HTTPStage()

    with patch(
        "hunt_chain_recon.pipeline.http.HTTPObservationProvider"
    ) as provider_class:
        result = stage.run(context)

    provider_class.assert_not_called()

    assert result.status == ProviderStatus.SKIPPED
    assert result.metadata["endpoint_count"] == 0
    assert result.observations == []


def test_endpoints_are_read_from_pipeline_state():
    """The stage accepts a list of Endpoint objects from state."""

    context = make_context()
    endpoint = make_endpoint()

    context.set_state(
        ENDPOINTS_STATE_KEY,
        [endpoint],
    )

    observation = make_observation(endpoint)

    provider_result = make_provider_result(
        status=ProviderStatus.SUCCESS,
        observations=[observation],
    )

    provider_instance = Mock()
    provider_instance.name = "http-observer"
    provider_instance.version = "1.0.0"
    provider_instance.probe.return_value = provider_result

    with patch(
        "hunt_chain_recon.pipeline.http.HTTPObservationProvider",
        return_value=provider_instance,
    ) as provider_class:
        result = HTTPStage().run(context)

    provider_class.assert_called_once()

    provider_instance.probe.assert_called_once_with(
        [endpoint]
    )

    assert result.observations == [observation]
    assert result.metadata["endpoint_count"] == 1
    assert result.metadata["observation_count"] == 1


def test_provider_result_is_stored_in_pipeline_state():
    """The stage stores its complete result in pipeline state."""

    context = make_context()
    endpoint = make_endpoint()

    context.set_state(
        ENDPOINTS_STATE_KEY,
        [endpoint],
    )

    observation = make_observation(endpoint)

    provider_result = make_provider_result(
        status=ProviderStatus.SUCCESS,
        observations=[observation],
    )

    provider_instance = Mock()
    provider_instance.name = "http-observer"
    provider_instance.version = "1.0.0"
    provider_instance.probe.return_value = provider_result

    with patch(
        "hunt_chain_recon.pipeline.http.HTTPObservationProvider",
        return_value=provider_instance,
    ):
        result = HTTPStage().run(context)

    stored = context.get_state(HTTP_RESULTS_STATE_KEY)

    assert stored is result
    assert stored.provider_results == [provider_result]
    assert stored.observations == [observation]


def test_politeness_operation_wraps_provider_call():
    """HTTP probing executes inside the politeness controller."""

    context = make_context()
    endpoint = make_endpoint()

    context.set_state(
        ENDPOINTS_STATE_KEY,
        [endpoint],
    )

    observation = make_observation(endpoint)

    provider_result = make_provider_result(
        status=ProviderStatus.SUCCESS,
        observations=[observation],
    )

    provider_instance = Mock()
    provider_instance.name = "http-observer"
    provider_instance.version = "1.0.0"
    provider_instance.probe.return_value = provider_result

    with patch(
        "hunt_chain_recon.pipeline.http.HTTPObservationProvider",
        return_value=provider_instance,
    ):
        HTTPStage().run(context)

    context.politeness.operation.assert_called_once()

    operation = context.politeness.operation.return_value

    operation.__enter__.assert_called_once()
    operation.__exit__.assert_called_once()


def test_invalid_endpoint_state_is_rejected():
    """Pipeline state containing non-Endpoint values is rejected."""

    context = make_context()

    context.set_state(
        ENDPOINTS_STATE_KEY,
        ["not-an-endpoint"],
    )

    with pytest.raises(TypeError):
        HTTPStage().run(context)


def test_endpoint_container_is_supported():
    """The stage supports an object exposing an endpoints attribute."""

    context = make_context()
    endpoint = make_endpoint()

    container = Mock()
    container.endpoints = [endpoint]

    context.set_state(
        ENDPOINTS_STATE_KEY,
        container,
    )

    observation = make_observation(endpoint)

    provider_result = make_provider_result(
        status=ProviderStatus.SUCCESS,
        observations=[observation],
    )

    provider_instance = Mock()
    provider_instance.name = "http-observer"
    provider_instance.version = "1.0.0"
    provider_instance.probe.return_value = provider_result

    with patch(
        "hunt_chain_recon.pipeline.http.HTTPObservationProvider",
        return_value=provider_instance,
    ):
        result = HTTPStage().run(context)

    assert result.observations == [observation]


def test_empty_endpoint_container_is_skipped():
    """An empty endpoint container results in skipped work."""

    context = make_context()

    container = Mock()
    container.endpoints = []

    context.set_state(
        ENDPOINTS_STATE_KEY,
        container,
    )

    result = HTTPStage().run(context)

    assert result.status == ProviderStatus.SKIPPED
    assert result.metadata["endpoint_count"] == 0


def test_provider_configuration_receives_http_settings():
    """The stage passes configured HTTP behavior to the provider."""

    context = make_context()
    endpoint = make_endpoint()

    context.set_state(
        ENDPOINTS_STATE_KEY,
        [endpoint],
    )

    provider_result = make_provider_result(
        status=ProviderStatus.SUCCESS,
    )

    provider_instance = Mock()
    provider_instance.name = "http-observer"
    provider_instance.version = "1.0.0"
    provider_instance.probe.return_value = provider_result

    with patch(
        "hunt_chain_recon.pipeline.http.HTTPObservationProvider",
        return_value=provider_instance,
    ) as provider_class:
        HTTPStage().run(context)

    provider_class.assert_called_once_with(
        timeout_seconds=5,
        follow_redirects=True,
        max_redirects=3,
        verify_tls=True,
        collect_headers=True,
        collect_body_hash=True,
    )


def test_provider_observations_are_preserved():
    """HTTP observations returned by the provider are preserved unchanged."""

    context = make_context()
    endpoint = make_endpoint()

    context.set_state(
        ENDPOINTS_STATE_KEY,
        [endpoint],
    )

    first = make_observation(endpoint)

    second = HTTPObservation(
        endpoint_id=endpoint.id,
        state=HTTPObservationState.SUCCESS,
        status_code=301,
        headers={
            "location": "https://127.0.0.1:8000",
        },
        content_type=None,
        body_length=0,
        body_hash=None,
    )

    provider_result = make_provider_result(
        status=ProviderStatus.SUCCESS,
        observations=[first, second],
    )

    provider_instance = Mock()
    provider_instance.name = "http-observer"
    provider_instance.version = "1.0.0"
    provider_instance.probe.return_value = provider_result

    with patch(
        "hunt_chain_recon.pipeline.http.HTTPObservationProvider",
        return_value=provider_instance,
    ):
        result = HTTPStage().run(context)

    assert result.observations == [first, second]
    assert result.metadata["observation_count"] == 2


def test_authorization_is_required():
    """Unauthorized execution is rejected before HTTP probing."""

    context = make_context()

    context.authorization = AuthorizationResult(
        target=context.config.target.value,
        decision=AuthorizationDecision.OUT_OF_SCOPE,
        provider="scopeguard",
        reference="TEST_UNAUTHORIZED",
    )

    context.set_state(
        ENDPOINTS_STATE_KEY,
        [make_endpoint()],
    )

    with patch(
        "hunt_chain_recon.pipeline.http.HTTPObservationProvider"
    ) as provider_class:
        with pytest.raises(Exception):
            HTTPStage().run(context)

    provider_class.assert_not_called()