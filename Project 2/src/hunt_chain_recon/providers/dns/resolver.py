"""DNS resolver provider for Hunt_Chain Project 2.

This module implements the V1 active DNS provider using dnspython.

The resolver collects observations for:

    A
    AAAA
    CNAME

DNS failures are represented explicitly:

    UNRESOLVED
    TIMEOUT
    ERROR

A failed lookup does not cause the hostname to be discarded.

This provider performs observation collection only. It does not:

- determine whether a hostname is vulnerable,
- confirm DNS takeover,
- exploit dangling CNAMEs,
- perform wildcard interpretation,
- perform brute-force hostname discovery,
- perform HTTP requests,
- make authorization decisions.

Authorization is enforced by the Project 2 pipeline.

Politeness is supplied separately by the pipeline/provider execution
layer and is not hidden inside the DNS observation models.
"""

from __future__ import annotations

from collections.abc import Sequence

import dns.exception
import dns.resolver

from hunt_chain_recon.models.dns import (
    DNSObservation,
    DNSRecord,
    DNSRecordType,
    DNSResolutionStatus,
)
from hunt_chain_recon.providers.base import ProviderResult
from hunt_chain_recon.providers.dns.base import DNSProvider


class DNSResolverProvider(DNSProvider):
    """Resolve DNS records using dnspython."""

    DEFAULT_TIMEOUT_SECONDS = 5.0

    SUPPORTED_RECORD_TYPES = (
        DNSRecordType.A,
        DNSRecordType.AAAA,
        DNSRecordType.CNAME,
    )

    def __init__(
        self,
        *,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        resolver: dns.resolver.Resolver | None = None,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError(
                "timeout_seconds must be greater than zero."
            )

        self._timeout_seconds = float(timeout_seconds)
        self._resolver = resolver or dns.resolver.Resolver()

    @property
    def name(self) -> str:
        """Return the stable provider name."""
        return "dns-resolver"

    @property
    def version(self) -> str:
        """Return the provider version."""
        return "1.0.0"

    @property
    def capabilities(self) -> tuple[str, ...]:
        """Return supported DNS capabilities."""
        return (
            "dns_resolution",
            "a_records",
            "aaaa_records",
            "cname_records",
        )

    @property
    def timeout_seconds(self) -> float:
        """Return the configured DNS timeout."""
        return self._timeout_seconds

    def resolve(
        self,
        hostnames: Sequence[str],
    ) -> ProviderResult[DNSObservation]:
        """Resolve configured DNS record types for each hostname."""
        if isinstance(hostnames, str):
            hostnames = [hostnames]

        observations: list[DNSObservation] = []
        errors: list[dict[str, str]] = []

        for hostname in hostnames:
            if not isinstance(hostname, str):
                errors.append(
                    {
                        "type": "CONFIGURATION_ERROR",
                        "message": (
                            "DNS hostname must be a string."
                        ),
                    }
                )
                continue

            normalized_hostname = hostname.strip()

            if not normalized_hostname:
                errors.append(
                    {
                        "type": "CONFIGURATION_ERROR",
                        "message": (
                            "DNS hostname must not be empty."
                        ),
                    }
                )
                continue

            observation = self._resolve_hostname(
                normalized_hostname
            )

            observations.append(observation)

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
                "record_types": [
                    record_type.value
                    for record_type in self.SUPPORTED_RECORD_TYPES
                ],
            },
        )

    def _resolve_hostname(
        self,
        hostname: str,
    ) -> DNSObservation:
        """Resolve all supported record types for one hostname."""
        records: list[DNSRecord] = []
        timeout_seen = False
        error_messages: list[str] = []

        for record_type in self.SUPPORTED_RECORD_TYPES:
            try:
                answer = self._resolver.resolve(
                    hostname,
                    record_type.value,
                    lifetime=self._timeout_seconds,
                )

            except (
                dns.resolver.NXDOMAIN,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
            ):
                continue

            except (
                dns.resolver.LifetimeTimeout,
                dns.exception.Timeout,
            ):
                timeout_seen = True
                continue

            except Exception as exc:
                error_messages.append(
                    f"{record_type.value}: {exc}"
                )
                continue

            records.extend(
                self._records_from_answer(
                    record_type,
                    answer,
                )
            )

        if records:
            return DNSObservation(
                hostname=hostname,
                status=DNSResolutionStatus.RESOLVED,
                records=records,
                error=(
                    "; ".join(error_messages)
                    if error_messages
                    else None
                ),
            )

        if timeout_seen:
            return DNSObservation(
                hostname=hostname,
                status=DNSResolutionStatus.TIMEOUT,
                records=[],
                error=(
                    "; ".join(error_messages)
                    if error_messages
                    else "DNS resolution timed out."
                ),
            )

        if error_messages:
            return DNSObservation(
                hostname=hostname,
                status=DNSResolutionStatus.ERROR,
                records=[],
                error="; ".join(error_messages),
            )

        return DNSObservation(
            hostname=hostname,
            status=DNSResolutionStatus.UNRESOLVED,
            records=[],
        )

    @staticmethod
    def _records_from_answer(
        record_type: DNSRecordType,
        answer: object,
    ) -> list[DNSRecord]:
        """Convert a dnspython answer into normalized DNS records."""
        records: list[DNSRecord] = []

        ttl = getattr(answer, "rrset", None)

        if ttl is not None:
            ttl_value = getattr(ttl, "ttl", None)
        else:
            ttl_value = None

        if ttl_value is not None:
            try:
                ttl_value = int(ttl_value)
            except (TypeError, ValueError):
                ttl_value = None

        for item in answer:
            value = DNSResolverProvider._record_value(
                record_type,
                item,
            )

            if not value:
                continue

            records.append(
                DNSRecord(
                    record_type=record_type,
                    value=value,
                    ttl=ttl_value,
                )
            )

        return records

    @staticmethod
    def _record_value(
        record_type: DNSRecordType,
        record: object,
    ) -> str | None:
        """Extract a canonical string value from a DNS record."""
        if record_type is DNSRecordType.CNAME:
            target = getattr(record, "target", None)

            if target is None:
                return None

            return str(target).rstrip(".")

        value = getattr(record, "address", None)

        if value is None:
            return None

        return str(value)

    @staticmethod
    def _provider_status(
        observations: list[DNSObservation],
        errors: list[dict[str, str]],
    ) -> str:
        """Determine the common provider result status."""
        if not observations:
            return "FAILED"

        if errors:
            return "PARTIAL"

        if any(
            observation.status
            in {
                DNSResolutionStatus.TIMEOUT,
                DNSResolutionStatus.ERROR,
            }
            for observation in observations
        ):
            return "PARTIAL"

        return "SUCCESS"