"""HTTP observation provider for Hunt_Chain Project 2.

This module implements the V1 HTTP/HTTPS observation provider.

The provider collects:

- HTTP status codes
- response headers
- Content-Type
- response body length
- optional SHA-256 response body hash
- redirect locations
- lightweight TLS metadata
- explicit connection, timeout, and TLS errors

The provider additionally retains raw response bodies internally so that
downstream deterministic processing stages, such as technology
fingerprinting, can inspect already-collected response content without
performing another network request.

Raw response bodies are runtime processing data. They are not included in
HTTPObservation or the public Attack Surface Model.

The provider does not perform:

- vulnerability scanning
- exploitation
- authentication attacks
- technology conclusions
- response similarity interpretation
- authorization decisions

Authorization and execution policy are enforced by the pipeline.
"""

from __future__ import annotations

import hashlib
import socket
import ssl
from datetime import datetime, timezone
from http.client import HTTPResponse
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
    build_opener,
)

from uuid import UUID

from hunt_chain_recon.models.endpoints import Endpoint, EndpointScheme
from hunt_chain_recon.models.http import (
    HTTPObservation,
    HTTPObservationState,
    TLSObservation,
)
from hunt_chain_recon.providers.base import (
    ProviderError,
    ProviderErrorType,
    ProviderResult,
    ProviderStatus,
)
from hunt_chain_recon.providers.http import HTTPProvider


class HTTPObservationProvider(HTTPProvider):
    """Collect lightweight HTTP/HTTPS observations."""

    DEFAULT_TIMEOUT_SECONDS = 10.0
    DEFAULT_MAX_REDIRECTS = 5

    def __init__(
        self,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        follow_redirects: bool = True,
        max_redirects: int = DEFAULT_MAX_REDIRECTS,
        verify_tls: bool = True,
        collect_headers: bool = True,
        collect_body_hash: bool = True,
        hash_algorithm: str = "sha256",
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError(
                "timeout_seconds must be greater than zero."
            )

        if max_redirects < 0:
            raise ValueError(
                "max_redirects must not be negative."
            )

        normalized_algorithm = hash_algorithm.strip().lower()

        if collect_body_hash and normalized_algorithm != "sha256":
            raise ValueError(
                "V1 response hashing supports only SHA-256."
            )

        self._timeout_seconds = float(
            timeout_seconds
        )

        self._follow_redirects = bool(
            follow_redirects
        )

        self._max_redirects = int(
            max_redirects
        )

        self._verify_tls = bool(
            verify_tls
        )

        self._collect_headers = bool(
            collect_headers
        )

        self._collect_body_hash = bool(
            collect_body_hash
        )

        self._hash_algorithm = normalized_algorithm

        self._raw_bodies: dict[UUID, bytes] = {}

    @property
    def name(self) -> str:
        """Return the stable provider name."""
        return "http-observer"

    @property
    def version(self) -> str:
        """Return the provider version."""
        return "1.0.0"

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Return supported HTTP observation capabilities."""
        return (
            "http_probing",
            "https_probing",
            "response_headers",
            "response_body_length",
            "response_body_hash",
            "redirect_observation",
            "tls_observation",
        )

    @property
    def timeout_seconds(self) -> float:
        """Return the configured request timeout."""
        return self._timeout_seconds

    @property
    def follow_redirects(self) -> bool:
        """Return whether redirects are followed."""
        return self._follow_redirects

    @property
    def max_redirects(self) -> int:
        """Return the configured redirect limit."""
        return self._max_redirects

    @property
    def verify_tls(self) -> bool:
        """Return whether TLS certificates are verified."""
        return self._verify_tls

    @property
    def raw_bodies(self) -> dict[UUID, bytes]:
        """Return raw response bodies keyed by observation ID.

        The returned mapping is a copy so callers cannot mutate the
        provider's internal storage accidentally.
        """

        return dict(
            self._raw_bodies
        )

    def get_raw_body(
        self,
        observation_id: UUID,
    ) -> bytes | None:
        """Return a raw response body for an observation, if available."""

        if not isinstance(
            observation_id,
            UUID,
        ):
            raise TypeError(
                "observation_id must be a UUID."
            )

        body = self._raw_bodies.get(
            observation_id
        )

        if body is None:
            return None

        return bytes(body)

    def probe(
        self,
        endpoints: list[Endpoint],
    ) -> ProviderResult[HTTPObservation]:
        """Probe each supplied endpoint and collect observations."""

        if isinstance(
            endpoints,
            Endpoint,
        ):
            endpoints = [endpoints]

        self._raw_bodies.clear()

        observations: list[HTTPObservation] = []
        errors: list[ProviderError] = []

        for endpoint in endpoints:
            if not isinstance(
                endpoint,
                Endpoint,
            ):
                errors.append(
                    ProviderError(
                        type=ProviderErrorType.CONFIGURATION_ERROR,
                        message=(
                            "HTTP provider received an invalid endpoint."
                        ),
                    )
                )
                continue

            try:
                observation = self._probe_endpoint(
                    endpoint
                )

            except Exception as exc:
                observation = HTTPObservation(
                    endpoint_id=endpoint.id,
                    state=HTTPObservationState.ERROR,
                    error_message=str(exc),
                    metadata={
                        "provider": self.name,
                        "unexpected_error": True,
                    },
                )

                errors.append(
                    ProviderError(
                        type=ProviderErrorType.EXECUTION_ERROR,
                        message=(
                            f"Unexpected HTTP provider error for "
                            f"{endpoint.url}: {exc}"
                        ),
                    )
                )

            observations.append(
                observation
            )

        status = self._provider_status(
            observations,
            errors,
        )

        return ProviderResult(
            status=status,
            observations=observations,
            errors=errors,
            provider=self.name,
            version=self.version,
            metadata={
                "timeout_seconds": self.timeout_seconds,
                "follow_redirects": self.follow_redirects,
                "max_redirects": self.max_redirects,
                "verify_tls": self.verify_tls,
                "collect_headers": self._collect_headers,
                "collect_body_hash": self._collect_body_hash,
                "hash_algorithm": (
                    self._hash_algorithm
                    if self._collect_body_hash
                    else None
                ),
                "raw_body_observation_count": len(
                    self._raw_bodies
                ),
            },
        )

    def _probe_endpoint(
        self,
        endpoint: Endpoint,
    ) -> HTTPObservation:
        """Perform one HTTP/HTTPS observation."""

        request = Request(
            endpoint.url,
            method="GET",
            headers={
                "User-Agent": "Hunt-Chain-Recon/2.0",
                "Accept": "*/*",
                "Connection": "close",
            },
        )

        opener = self._build_opener()

        observed_at = datetime.now(
            timezone.utc
        )

        try:
            response = opener.open(
                request,
                timeout=self._timeout_seconds,
            )

        except HTTPError as exc:
            return self._observation_from_http_error(
                endpoint=endpoint,
                error=exc,
                observed_at=observed_at,
            )

        except socket.timeout as exc:
            return HTTPObservation(
                endpoint_id=endpoint.id,
                state=HTTPObservationState.TIMEOUT,
                observed_at=observed_at,
                error_message=str(exc) or "HTTP request timed out.",
            )

        except TimeoutError as exc:
            return HTTPObservation(
                endpoint_id=endpoint.id,
                state=HTTPObservationState.TIMEOUT,
                observed_at=observed_at,
                error_message=str(exc) or "HTTP request timed out.",
            )

        except ssl.SSLError as exc:
            return HTTPObservation(
                endpoint_id=endpoint.id,
                state=HTTPObservationState.TLS_ERROR,
                observed_at=observed_at,
                error_message=str(exc),
            )

        except URLError as exc:
            return self._observation_from_url_error(
                endpoint=endpoint,
                error=exc,
                observed_at=observed_at,
            )

        except OSError as exc:
            return HTTPObservation(
                endpoint_id=endpoint.id,
                state=HTTPObservationState.CONNECTION_ERROR,
                observed_at=observed_at,
                error_message=str(exc),
            )

        return self._observation_from_response(
            endpoint=endpoint,
            response=response,
            observed_at=observed_at,
        )

    def _observation_from_response(
        self,
        *,
        endpoint: Endpoint,
        response: HTTPResponse,
        observed_at: datetime,
    ) -> HTTPObservation:
        """Convert a successful HTTP response into an observation."""

        status_code = getattr(
            response,
            "status",
            None,
        )

        headers = {}

        if self._collect_headers:
            headers = {
                str(name).strip().lower(): str(value).strip()
                for name, value in response.headers.items()
            }

        content_type = response.headers.get(
            "Content-Type"
        )

        body = response.read()

        body_length = len(
            body
        )

        body_hash = None

        if self._collect_body_hash:
            body_hash = hashlib.sha256(
                body
            ).hexdigest()

        redirect_chain = []

        final_url = getattr(
            response,
            "geturl",
            lambda: endpoint.url,
        )()

        if final_url != endpoint.url:
            redirect_chain.append(
                final_url
            )

        tls_observation = self._extract_tls_observation(
            response
        )

        state = HTTPObservationState.SUCCESS

        if redirect_chain:
            state = HTTPObservationState.REDIRECT

        observation = HTTPObservation(
            endpoint_id=endpoint.id,
            state=state,
            status_code=status_code,
            headers=headers,
            content_type=content_type,
            body_length=body_length,
            body_hash=body_hash,
            redirect_chain=redirect_chain,
            tls=tls_observation,
            observed_at=observed_at,
            metadata={
                "final_url": final_url,
                "scheme": endpoint.scheme.value,
            },
        )

        self._raw_bodies[
            observation.id
        ] = bytes(body)

        return observation

    def _observation_from_http_error(
        self,
        *,
        endpoint: Endpoint,
        error: HTTPError,
        observed_at: datetime,
    ) -> HTTPObservation:
        """Convert an HTTP error response into an observation."""

        headers = {}

        if self._collect_headers:
            headers = {
                str(name).strip().lower(): str(value).strip()
                for name, value in error.headers.items()
            }

        body = error.read()

        body_length = len(
            body
        )

        body_hash = None

        if self._collect_body_hash:
            body_hash = hashlib.sha256(
                body
            ).hexdigest()

        content_type = error.headers.get(
            "Content-Type"
        )

        tls_observation = self._extract_tls_observation(
            error
        )

        observation = HTTPObservation(
            endpoint_id=endpoint.id,
            state=HTTPObservationState.SUCCESS,
            status_code=error.code,
            headers=headers,
            content_type=content_type,
            body_length=body_length,
            body_hash=body_hash,
            tls=tls_observation,
            observed_at=observed_at,
            metadata={
                "http_error_response": True,
                "reason": error.reason,
            },
        )

        self._raw_bodies[
            observation.id
        ] = bytes(body)

        return observation

    @staticmethod
    def _observation_from_url_error(
        *,
        endpoint: Endpoint,
        error: URLError,
        observed_at: datetime,
    ) -> HTTPObservation:
        """Convert a URL error into an explicit observation state."""

        reason = error.reason

        if isinstance(
            reason,
            socket.timeout,
        ):
            state = HTTPObservationState.TIMEOUT

        elif isinstance(
            reason,
            ssl.SSLError,
        ):
            state = HTTPObservationState.TLS_ERROR

        else:
            state = HTTPObservationState.CONNECTION_ERROR

        return HTTPObservation(
            endpoint_id=endpoint.id,
            state=state,
            observed_at=observed_at,
            error_message=str(reason),
        )

    def _build_opener(self):
        """Build a urllib opener according to redirect/TLS configuration."""

        handlers = []

        if self._follow_redirects:
            handlers.append(
                _LimitedRedirectHandler(
                    max_redirects=self._max_redirects
                )
            )

        else:
            handlers.append(
                _NoRedirectHandler()
            )

        if not self._verify_tls:
            handlers.append(
                HTTPSHandler(
                    context=ssl._create_unverified_context()
                )
            )

        return build_opener(
            *handlers
        )

    @staticmethod
    def _extract_tls_observation(
        response: Any,
    ) -> TLSObservation | None:
        """Extract lightweight TLS metadata when available."""

        raw_socket = None

        try:
            connection = getattr(
                response,
                "fp",
                None,
            )

            if connection is None:
                return None

            raw_socket = getattr(
                connection,
                "raw",
                None,
            )

            if raw_socket is None:
                return None

            socket_object = getattr(
                raw_socket,
                "_sock",
                None,
            )

            if socket_object is None:
                return None

            version = None
            cipher = None

            if hasattr(
                socket_object,
                "version",
            ):
                version = socket_object.version()

            if hasattr(
                socket_object,
                "cipher",
            ):
                cipher_info = socket_object.cipher()

                if cipher_info:
                    cipher = cipher_info[0]

            certificate_subject = None
            certificate_issuer = None

            certificate = socket_object.getpeercert()

            if certificate:
                subject = certificate.get(
                    "subject",
                    (),
                )

                issuer = certificate.get(
                    "issuer",
                    (),
                )

                certificate_subject = (
                    _certificate_name(subject)
                )

                certificate_issuer = (
                    _certificate_name(issuer)
                )

            return TLSObservation(
                version=version,
                cipher=cipher,
                certificate_subject=certificate_subject,
                certificate_issuer=certificate_issuer,
            )

        except (
            AttributeError,
            OSError,
            ValueError,
        ):
            return None

    @staticmethod
    def _provider_status(
        observations: list[HTTPObservation],
        errors: list[ProviderError],
    ) -> ProviderStatus:
        """Determine the overall provider status."""

        if not observations:
            return ProviderStatus.FAILED

        if errors:
            return ProviderStatus.PARTIAL

        if any(
            observation.state
            in {
                HTTPObservationState.CONNECTION_ERROR,
                HTTPObservationState.TIMEOUT,
                HTTPObservationState.TLS_ERROR,
                HTTPObservationState.ERROR,
            }
            for observation in observations
        ):
            return ProviderStatus.PARTIAL

        return ProviderStatus.SUCCESS


class _LimitedRedirectHandler(HTTPRedirectHandler):
    """Redirect handler enforcing the configured redirect limit."""

    def __init__(
        self,
        *,
        max_redirects: int,
    ) -> None:
        super().__init__()
        self._max_redirects = max_redirects
        self._redirect_count = 0

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        if self._redirect_count >= self._max_redirects:
            raise HTTPError(
                req.full_url,
                code,
                "Maximum redirect limit reached.",
                headers,
                fp,
            )

        self._redirect_count += 1

        return super().redirect_request(
            req,
            fp,
            code,
            msg,
            headers,
            newurl,
        )


class _NoRedirectHandler(HTTPRedirectHandler):
    """Redirect handler that records the redirect response without following."""

    def redirect_request(
        self,
        req,
        fp,
        code,
        msg,
        headers,
        newurl,
    ):
        return None


def _certificate_name(
    value: Any,
) -> str | None:
    """Convert a certificate subject/issuer tuple into readable text."""

    if not value:
        return None

    parts: list[str] = []

    for relative_name in value:
        for key, item in relative_name:
            parts.append(
                f"{key}={item}"
            )

    if not parts:
        return None

    return ", ".join(
        parts
    )