"""Wildcard DNS analysis for Hunt_Chain Project 2.

This module analyzes DNS observations supplied by an upstream resolver.

Wildcard analysis is deliberately separate from DNS resolution.

It does not:
- perform DNS queries,
- perform network activity,
- modify DNS observations,
- remove assets from the attack surface,
- declare a vulnerability,
- confirm DNS takeover,
- perform exploitation.

The analyzer expects observations from controlled random-label DNS probes.
Consistent DNS answers across multiple independent random labels provide
evidence that wildcard DNS behavior may be present.

Wildcard detection is an observation about DNS behavior, not a vulnerability
finding.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


class WildcardAnalysisError(Exception):
    """Raised when wildcard analysis receives invalid input."""


@dataclass(frozen=True)
class WildcardProbe:
    """A DNS observation for a controlled random hostname.

    The probe represents an already-completed DNS lookup.

    No network activity is performed by this model.
    """

    hostname: str
    resolved_values: tuple[str, ...]

    def __init__(
        self,
        hostname: str,
        resolved_values: Iterable[str],
    ) -> None:
        if not isinstance(hostname, str):
            raise WildcardAnalysisError(
                "Wildcard probe hostname must be a string."
            )

        normalized_hostname = hostname.strip().lower().rstrip(".")

        if not normalized_hostname:
            raise WildcardAnalysisError(
                "Wildcard probe hostname must not be empty."
            )

        if isinstance(resolved_values, (str, bytes)):
            raise WildcardAnalysisError(
                "Wildcard probe resolved_values must be an iterable "
                "of strings."
            )

        try:
            values = list(resolved_values)
        except TypeError as exc:
            raise WildcardAnalysisError(
                "Wildcard probe resolved_values must be an iterable "
                "of strings."
            ) from exc

        normalized_values: list[str] = []

        for value in values:
            if not isinstance(value, str):
                raise WildcardAnalysisError(
                    "Wildcard probe DNS values must be strings."
                )

            normalized_value = value.strip().lower().rstrip(".")

            if not normalized_value:
                continue

            if normalized_value not in normalized_values:
                normalized_values.append(normalized_value)

        object.__setattr__(
            self,
            "hostname",
            normalized_hostname,
        )
        object.__setattr__(
            self,
            "resolved_values",
            tuple(sorted(normalized_values)),
        )


@dataclass(frozen=True)
class WildcardAnalysisResult:
    """Deterministic result of wildcard DNS analysis."""

    domain: str
    detected: bool
    confidence: str
    common_values: tuple[str, ...]
    probes_evaluated: int


class WildcardDNSAnalyzer:
    """Analyze controlled DNS probes for wildcard behavior.

    V1 uses a conservative deterministic rule:

    - At least two probes must be supplied.
    - Every evaluated probe must contain at least one DNS answer.
    - At least one DNS answer must be common to every probe.

    When these conditions are satisfied, wildcard behavior is reported as
    detected with HIGH confidence.

    Otherwise wildcard behavior is not established.

    This deliberately does not claim that the DNS behavior is a
    vulnerability.
    """

    MINIMUM_PROBES = 2

    def analyze(
        self,
        domain: str,
        probes: Iterable[WildcardProbe],
    ) -> WildcardAnalysisResult:
        """Analyze supplied random-label DNS probes.

        Args:
            domain: Base domain being evaluated.
            probes: DNS observations for controlled random labels.

        Returns:
            A deterministic wildcard-analysis result.

        Raises:
            WildcardAnalysisError: If the input is malformed.
        """
        normalized_domain = self._normalize_domain(domain)

        try:
            probe_list = list(probes)
        except TypeError as exc:
            raise WildcardAnalysisError(
                "Wildcard probes must be an iterable."
            ) from exc

        for probe in probe_list:
            if not isinstance(probe, WildcardProbe):
                raise WildcardAnalysisError(
                    "Wildcard analysis input must contain "
                    "WildcardProbe objects."
                )

        probes_evaluated = len(probe_list)

        if probes_evaluated < self.MINIMUM_PROBES:
            return WildcardAnalysisResult(
                domain=normalized_domain,
                detected=False,
                confidence="LOW",
                common_values=(),
                probes_evaluated=probes_evaluated,
            )

        if any(
            not probe.resolved_values
            for probe in probe_list
        ):
            return WildcardAnalysisResult(
                domain=normalized_domain,
                detected=False,
                confidence="LOW",
                common_values=(),
                probes_evaluated=probes_evaluated,
            )

        common_values = set(
            probe_list[0].resolved_values
        )

        for probe in probe_list[1:]:
            common_values.intersection_update(
                probe.resolved_values
            )

        normalized_common_values = tuple(
            sorted(common_values)
        )

        detected = bool(normalized_common_values)

        return WildcardAnalysisResult(
            domain=normalized_domain,
            detected=detected,
            confidence="HIGH" if detected else "LOW",
            common_values=normalized_common_values,
            probes_evaluated=probes_evaluated,
        )

    @staticmethod
    def _normalize_domain(domain: str) -> str:
        """Normalize and validate the analyzed base domain."""
        if not isinstance(domain, str):
            raise WildcardAnalysisError(
                "Wildcard analysis domain must be a string."
            )

        normalized_domain = domain.strip().lower().rstrip(".")

        if not normalized_domain:
            raise WildcardAnalysisError(
                "Wildcard analysis domain must not be empty."
            )

        return normalized_domain