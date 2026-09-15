"""Unit tests for the V1 HTTP observation provider."""

from __future__ import annotations

import ssl
from io import BytesIO
from unittest.mock import Mock, patch
from urllib.error import HTTPError, URLError

import pytest

from hunt_chain_recon.models.endpoints import Endpoint, EndpointScheme
from hunt_chain_recon.models.http import (
    HTTPObservationState,
)
from hunt_chain_recon.providers.base import (
    ProviderErrorType,
    ProviderStatus,
)
from hunt_chain_recon.providers.http.client import (
    HTTPObservationProvider,
)


def make_endpoint(
    *,
    url: str = "http://example.com",
    scheme: EndpointScheme = EndpointScheme.HTTP,
    hostname: str = "example.com",
    port: int = 80,
) -> Endpoint:
    """Create a deterministic endpoint for provider tests."""

    return Endpoint(
        asset_id=__import__(
            "uuid"
        ).uuid4(),
        scheme=scheme,
        hostname=hostname,
        port=port,
        url=url,
    )


def make_response(
    *,
    status: int = 200,
    body: bytes = b"hello world",
    headers: dict[str, str] | None = None,
    url: str = "http://example.com",
) -> Mock:
    """Create a mocked HTTP response."""

    response = Mock()
    response.status = status
    response.headers = Mock()

    header_values = headers or {
        "Content-Type": "text/plain",
        "Server": "test-server",
    }

    response.headers.items.return_value = list(
        header_values.items()
    )

    response.headers.get.side_effect = (
        lambda name, default=None: header_values.get(
            name,
            default,
        )
    )

    response.read.return_value = body
    response.geturl.return_value = url
    response.fp = None

    return response


def test_provider_metadata():
    """Provider exposes stable metadata and capabilities."""

    provider = HTTPObservationProvider()

    assert provider.name == "http-observer"
    assert provider.version == "1.0.0"

    assert provider.capabilities == (
        "http_probing",
        "https_probing",
        "response_headers",
        "response_body_length",
        "response_body_hash",
        "redirect_observation",
        "tls_observation",
    )


def test_successful_http_response_is_observed():
    """A successful response produces a SUCCESS observation."""

    endpoint = make_endpoint()

    response = make_response(
        status=200,
        body=b"hello world",
    )

    provider = HTTPObservationProvider()

    with patch.object(
        provider,
        "_build_opener",
    ) as build_opener:
        opener = Mock()
        opener.open.return_value = response
        build_opener.return_value = opener

        result = provider.probe(
            [endpoint]
        )

    assert result.status == ProviderStatus.SUCCESS
    assert len(result.observations) == 1
    assert result.errors == []

    observation = result.observations[0]

    assert observation.endpoint_id == endpoint.id
    assert observation.state == HTTPObservationState.SUCCESS
    assert observation.status_code == 200
    assert observation.body_length == 11
    assert observation.body_hash == (
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    )
    assert observation.headers["content-type"] == "text/plain"
    assert observation.headers["server"] == "test-server"


def test_response_hashing_can_be_disabled():
    """Body hashing is omitted when disabled."""

    endpoint = make_endpoint()

    response = make_response(
        body=b"hello",
    )

    provider = HTTPObservationProvider(
        collect_body_hash=False,
    )

    with patch.object(
        provider,
        "_build_opener",
    ) as build_opener:
        opener = Mock()
        opener.open.return_value = response
        build_opener.return_value = opener

        result = provider.probe(
            [endpoint]
        )

    observation = result.observations[0]

    assert observation.body_length == 5
    assert observation.body_hash is None


def test_response_headers_can_be_disabled():
    """Response headers are omitted when disabled."""

    endpoint = make_endpoint()

    response = make_response()

    provider = HTTPObservationProvider(
        collect_headers=False,
    )

    with patch.object(
        provider,
        "_build_opener",
    ) as build_opener:
        opener = Mock()
        opener.open.return_value = response
        build_opener.return_value = opener

        result = provider.probe(
            [endpoint]
        )

    observation = result.observations[0]

    assert observation.headers == {}
    assert observation.status_code == 200


def test_http_error_response_is_preserved_as_observation():
    """HTTP error status codes remain valid HTTP observations."""

    endpoint = make_endpoint()

    error = HTTPError(
        endpoint.url,
        404,
        "Not Found",
        {
            "Content-Type": "text/plain",
        },
        BytesIO(
            b"not found"
        ),
    )

    provider = HTTPObservationProvider()

    with patch.object(
        provider,
        "_build_opener",
    ) as build_opener:
        opener = Mock()
        opener.open.side_effect = error
        build_opener.return_value = opener

        result = provider.probe(
            [endpoint]
        )

    assert result.status == ProviderStatus.SUCCESS
    assert len(result.observations) == 1
    assert result.errors == []

    observation = result.observations[0]

    assert observation.state == HTTPObservationState.SUCCESS
    assert observation.status_code == 404
    assert observation.body_length == 9


def test_timeout_produces_timeout_observation():
    """A socket timeout becomes an explicit TIMEOUT observation."""

    endpoint = make_endpoint()

    provider = HTTPObservationProvider()

    with patch.object(
        provider,
        "_build_opener",
    ) as build_opener:
        opener = Mock()
        opener.open.side_effect = TimeoutError(
            "timed out"
        )
        build_opener.return_value = opener

        result = provider.probe(
            [endpoint]
        )

    assert result.status == ProviderStatus.PARTIAL

    observation = result.observations[0]

    assert observation.state == HTTPObservationState.TIMEOUT
    assert "timed out" in observation.error_message


def test_url_error_produces_connection_error():
    """A URL error becomes an explicit connection error."""

    endpoint = make_endpoint()

    provider = HTTPObservationProvider()

    with patch.object(
        provider,
        "_build_opener",
    ) as build_opener:
        opener = Mock()
        opener.open.side_effect = URLError(
            "connection refused"
        )
        build_opener.return_value = opener

        result = provider.probe(
            [endpoint]
        )

    assert result.status == ProviderStatus.PARTIAL

    observation = result.observations[0]

    assert observation.state == HTTPObservationState.CONNECTION_ERROR
    assert "connection refused" in observation.error_message


def test_tls_error_produces_tls_error_observation():
    """TLS failures become explicit TLS_ERROR observations."""

    endpoint = make_endpoint(
        url="https://example.com",
        scheme=EndpointScheme.HTTPS,
        port=443,
    )

    provider = HTTPObservationProvider()

    with patch.object(
        provider,
        "_build_opener",
    ) as build_opener:
        opener = Mock()
        opener.open.side_effect = ssl.SSLError(
            "certificate verification failed"
        )
        build_opener.return_value = opener

        result = provider.probe(
            [endpoint]
        )

    assert result.status == ProviderStatus.PARTIAL

    observation = result.observations[0]

    assert observation.state == HTTPObservationState.TLS_ERROR
    assert "certificate verification failed" in (
        observation.error_message
    )


def test_multiple_endpoints_are_processed():
    """Each supplied endpoint receives its own observation."""

    endpoint_one = make_endpoint(
        url="http://one.example.com",
        hostname="one.example.com",
    )

    endpoint_two = make_endpoint(
        url="http://two.example.com",
        hostname="two.example.com",
    )

    response_one = make_response(
        url=endpoint_one.url,
    )

    response_two = make_response(
        url=endpoint_two.url,
    )

    provider = HTTPObservationProvider()

    with patch.object(
        provider,
        "_build_opener",
    ) as build_opener:
        opener = Mock()
        opener.open.side_effect = [
            response_one,
            response_two,
        ]
        build_opener.return_value = opener

        result = provider.probe(
            [
                endpoint_one,
                endpoint_two,
            ]
        )

    assert result.status == ProviderStatus.SUCCESS
    assert len(result.observations) == 2

    observed_ids = {
        observation.endpoint_id
        for observation in result.observations
    }

    assert observed_ids == {
        endpoint_one.id,
        endpoint_two.id,
    }


def test_invalid_endpoint_is_reported_as_configuration_error():
    """Invalid provider input is represented as a provider error."""

    provider = HTTPObservationProvider()

    result = provider.probe(
        ["not-an-endpoint"]
    )

    assert result.status == ProviderStatus.FAILED
    assert result.observations == []
    assert len(result.errors) == 1
    assert result.errors[0].type == (
        ProviderErrorType.CONFIGURATION_ERROR
    )


def test_provider_configuration_validation():
    """Invalid provider configuration is rejected immediately."""

    with pytest.raises(
        ValueError,
        match="timeout_seconds",
    ):
        HTTPObservationProvider(
            timeout_seconds=0,
        )

    with pytest.raises(
        ValueError,
        match="max_redirects",
    ):
        HTTPObservationProvider(
            max_redirects=-1,
        )

    with pytest.raises(
        ValueError,
        match="SHA-256",
    ):
        HTTPObservationProvider(
            hash_algorithm="md5",
        )