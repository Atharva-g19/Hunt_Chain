"""Certificate Transparency discovery provider for Hunt_Chain Project 2.

This provider discovers candidate hostnames from Certificate Transparency
data for an authorized domain.

V1 responsibilities:

- query a CT source,
- extract DNS names from returned certificate records,
- return raw discovery observations,
- preserve provider metadata,
- report provider errors explicitly.

V1 does not:

- perform DNS resolution,
- perform HTTP probing,
- scan ports,
- perform vulnerability testing,
- confirm dangling DNS,
- confirm DNS takeover,
- perform exploitation.

The provider produces observations. Normalization, deduplication, and
correlation are handled by later Project 2 processing stages.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote
from urllib.request import Request, urlopen

from hunt_chain_recon.providers.base import (
    ProviderError,
    ProviderResult,
)
from hunt_chain_recon.providers.discovery.base import DiscoveryProvider


class CertificateTransparencyProvider(DiscoveryProvider):
    """Discover candidate hostnames from Certificate Transparency data.

    The actual CT source interaction is isolated behind ``_query_source``.
    This keeps source-specific transport details separate from observation
    extraction.

    V1 uses a conservative source interaction model and does not attempt
    to bypass source restrictions or rate limits.
    """

    name = "certificate-transparency"
    version = "1.0.0"
    SOURCE_URL = "https://crt.sh/?q=%25.{domain}&output=json"
    DEFAULT_TIMEOUT_SECONDS = 10.0

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Return the capabilities exposed by this provider."""
        return (
            "passive_discovery",
            "certificate_transparency",
            "hostname_discovery",
        )

    def discover(self, target: Any) -> ProviderResult[dict[str, Any]]:
        """Discover candidate hostnames for the supplied target.

        Args:
            target: Authorized target domain.

        Returns:
            ProviderResult containing raw hostname observations.

        The method expects a domain-like string and does not perform any
        authorization decision itself.
        """
        domain = self._normalize_domain(target)

        if domain is None:
            return ProviderResult(
                status="FAILED",
                errors=[
                    ProviderError(
                        type="CONFIGURATION_ERROR",
                        message="CT discovery requires a valid domain target.",
                        retryable=False,
                    )
                ],
                provider=self.name,
                version=self.version,
            )

        try:
            records = self._query_source(domain)
        except TimeoutError as exc:
            return ProviderResult(
                status="FAILED",
                errors=[
                    ProviderError(
                        type="TIMEOUT",
                        message=str(exc),
                        retryable=True,
                    )
                ],
                provider=self.name,
                version=self.version,
            )
        except OSError as exc:
            return ProviderResult(
                status="FAILED",
                errors=[
                    ProviderError(
                        type="NETWORK_ERROR",
                        message=str(exc),
                        retryable=True,
                    )
                ],
                provider=self.name,
                version=self.version,
            )
        except Exception as exc:
            return ProviderResult(
                status="FAILED",
                errors=[
                    ProviderError(
                        type="EXECUTION_ERROR",
                        message=str(exc),
                        retryable=False,
                    )
                ],
                provider=self.name,
                version=self.version,
            )

        observations = self._extract_observations(
            records,
            domain,
        )

        return ProviderResult(
            status="SUCCESS",
            observations=observations,
            provider=self.name,
            version=self.version,
            metadata={
                "source": "certificate_transparency",
                "target": domain,
                "record_count": len(records),
            },
        )

    def _normalize_domain(self, target: Any) -> str | None:
        """Normalize a domain target for CT querying."""
        if not isinstance(target, str):
            return None

        domain = target.strip().lower().rstrip(".")

        if not domain:
            return None

        return domain

    def _query_source(self, domain: str) -> list[dict[str, Any]]:
        """Query the configured CT source.

        This method is intentionally isolated so the source transport can
        be replaced or mocked in tests.

        The source request is made only through DiscoveryStage, which
        enforces the shared authorization and politeness boundaries.
        Tests replace this method, so no test needs Internet access.
        """
        encoded_domain = quote(domain, safe="")
        url = self.SOURCE_URL.format(domain=encoded_domain)
        request = Request(
            url,
            headers={
                "Accept": "application/json",
                "User-Agent": "Hunt-Chain-Recon/0.1",
            },
        )

        with urlopen(
            request,
            timeout=self.DEFAULT_TIMEOUT_SECONDS,
        ) as response:
            payload = response.read()

        try:
            decoded = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(
                "Certificate Transparency source returned invalid JSON."
            ) from exc

        if not isinstance(decoded, list):
            raise ValueError(
                "Certificate Transparency source returned a non-list payload."
            )

        return [
            record
            for record in decoded
            if isinstance(record, dict)
        ]

    def _extract_observations(
        self,
        records: list[dict[str, Any]],
        domain: str,
    ) -> list[dict[str, Any]]:
        """Extract raw hostname observations from CT records.

        Expected CT records may contain a ``name_value`` field containing
        one or more newline-separated DNS names.

        Only names belonging to the requested domain are retained.

        This method does not normalize or deduplicate the final asset set.
        Those responsibilities belong to processing stages.
        """
        observations: list[dict[str, Any]] = []

        suffix = f".{domain}"

        for record in records:
            name_value = record.get("name_value")

            if not isinstance(name_value, str):
                continue

            for raw_name in name_value.splitlines():
                hostname = raw_name.strip().lower()

                if not hostname:
                    continue

                if hostname.startswith("*."):
                    hostname = hostname[2:]

                if hostname == domain or hostname.endswith(suffix):
                    observations.append(
                        {
                            "value": hostname,
                            "type": "HOSTNAME",
                            "source": self.name,
                        }
                    )

        return observations
