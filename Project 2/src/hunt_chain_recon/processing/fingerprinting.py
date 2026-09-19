"""Deterministic technology fingerprinting for Hunt_Chain Project 2.

This module interprets already-collected HTTP observations and produces
technology observations with explainable evidence.

V1 fingerprinting is intentionally deterministic.

It may inspect:
- HTTP response headers
- HTML/response-body markers
- an already-computed response hash

It does not:
- perform network requests,
- perform vulnerability testing,
- exploit detected technologies,
- infer vulnerabilities from versions,
- use ML or LLM-based fingerprinting,
- claim that a technology is definitely present when evidence is absent.

Technology identification is an observation, not a security conclusion.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Mapping
from uuid import UUID

from hunt_chain_recon.models.endpoints import Endpoint
from hunt_chain_recon.models.technology import (
    Technology,
    TechnologyCategory,
    TechnologyConfidence,
    TechnologyEvidence,
    TechnologyEvidenceType,
)


class FingerprintingError(ValueError):
    """Raised when fingerprinting input is invalid."""


@dataclass
class FingerprintingResult:
    """Result produced by deterministic technology fingerprinting."""

    technologies: list[Technology] = field(default_factory=list)
    evidence: list[TechnologyEvidence] = field(default_factory=list)


@dataclass(frozen=True)
class _FingerprintMatch:
    """Internal deterministic fingerprint rule match."""

    name: str
    category: TechnologyCategory
    version: str | None
    evidence_type: TechnologyEvidenceType
    observation: str
    rule: str
    confidence: TechnologyConfidence


class TechnologyFingerprinter:
    """Perform deterministic technology identification."""

    _SERVER_RULES = (
        (
            re.compile(
                r"\bnginx(?:/|\s|$)"
                r"(?P<version>[0-9][0-9A-Za-z.\-_]*)?",
                re.IGNORECASE,
            ),
            "Nginx",
            TechnologyCategory.WEB_SERVER,
            "server_header_nginx",
        ),
        (
            re.compile(
                r"\bapache(?:/|\s|$)"
                r"(?P<version>[0-9][0-9A-Za-z.\-_]*)?",
                re.IGNORECASE,
            ),
            "Apache HTTP Server",
            TechnologyCategory.WEB_SERVER,
            "server_header_apache",
        ),
        (
            re.compile(
                r"\bmicrosoft-iis(?:/|\s|$)"
                r"(?P<version>[0-9][0-9A-Za-z.\-_]*)?",
                re.IGNORECASE,
            ),
            "Microsoft IIS",
            TechnologyCategory.WEB_SERVER,
            "server_header_iis",
        ),
        (
            re.compile(
                r"\bSimpleHTTP\b"
                r"(?:/[0-9][0-9A-Za-z.\-_]*)?"
                r".*?\bPython(?:/|\s|$)"
                r"(?P<version>[0-9][0-9A-Za-z.\-_]*)?",
                re.IGNORECASE,
            ),
            "Python",
            TechnologyCategory.PROGRAMMING_LANGUAGE,
            "server_header_python_simplehttp",
        ),
        (
            re.compile(r"\bcloudflare\b", re.IGNORECASE),
            "Cloudflare",
            TechnologyCategory.CDN,
            "server_header_cloudflare",
        ),
    )

    _POWERED_BY_RULES = (
        (
            re.compile(
                r"\bPHP(?:/|\s|$)"
                r"(?P<version>[0-9][0-9A-Za-z.\-_]*)?",
                re.IGNORECASE,
            ),
            "PHP",
            TechnologyCategory.PROGRAMMING_LANGUAGE,
            "powered_by_php",
        ),
        (
            re.compile(
                r"\bASP\.NET\b"
                r"(?:\s+(?P<version>[0-9][0-9A-Za-z.\-_]*))?",
                re.IGNORECASE,
            ),
            "ASP.NET",
            TechnologyCategory.WEB_FRAMEWORK,
            "powered_by_aspnet",
        ),
        (
            re.compile(
                r"\bExpress\b"
                r"(?:\s+(?:v)?"
                r"(?P<version>[0-9][0-9A-Za-z.\-_]*))?",
                re.IGNORECASE,
            ),
            "Express",
            TechnologyCategory.WEB_FRAMEWORK,
            "powered_by_express",
        ),
    )

    _HEADER_PRESENCE_RULES = (
        (
            "x-nextjs-cache",
            "Next.js",
            TechnologyCategory.WEB_FRAMEWORK,
            "header_x_nextjs_cache",
        ),
        (
            "x-nextjs-prerender",
            "Next.js",
            TechnologyCategory.WEB_FRAMEWORK,
            "header_x_nextjs_prerender",
        ),
        (
            "x-nextjs-stale-time",
            "Next.js",
            TechnologyCategory.WEB_FRAMEWORK,
            "header_x_nextjs_stale_time",
        ),
    )

    _BODY_RULES = (
        (
            re.compile(
                r'<meta[^>]+name=["\']generator["\'][^>]+'
                r'content=["\'][^"\']*\bWordPress\b'
                r'(?:\s+(?P<version>[0-9][0-9A-Za-z.\-_]*))?',
                re.IGNORECASE,
            ),
            "WordPress",
            TechnologyCategory.CMS,
            "html_generator_wordpress",
            TechnologyConfidence.HIGH,
        ),
        (
            re.compile(
                r"\bwp-content\b|\bwp-includes\b",
                re.IGNORECASE,
            ),
            "WordPress",
            TechnologyCategory.CMS,
            "html_wordpress_path",
            TechnologyConfidence.MEDIUM,
        ),
        (
            re.compile(
                r"\breact(?:\.production)?"
                r"(?:\.min)?\.js\b",
                re.IGNORECASE,
            ),
            "React",
            TechnologyCategory.JAVASCRIPT_FRAMEWORK,
            "html_react_script",
            TechnologyConfidence.MEDIUM,
        ),
        (
            re.compile(
                r"\b_vue(?:\.min)?\.js\b|"
                r"\bvue(?:\.runtime)?(?:\.global)?"
                r"(?:\.prod)?(?:\.min)?\.js\b",
                re.IGNORECASE,
            ),
            "Vue.js",
            TechnologyCategory.JAVASCRIPT_FRAMEWORK,
            "html_vue_script",
            TechnologyConfidence.MEDIUM,
        ),
        (
            re.compile(
                r"\bangular(?:\.min)?\.js\b",
                re.IGNORECASE,
            ),
            "AngularJS",
            TechnologyCategory.JAVASCRIPT_FRAMEWORK,
            "html_angular_script",
            TechnologyConfidence.MEDIUM,
        ),
    )

    def fingerprint(
        self,
        *,
        endpoint: Endpoint,
        headers: Mapping[str, str],
        body: bytes,
        response_hash: str | None = None,
    ) -> FingerprintingResult:
        """Fingerprint technologies from an already-observed response.

        No network activity is performed.
        """
        if not isinstance(endpoint, Endpoint):
            raise FingerprintingError(
                "endpoint must be an Endpoint."
            )

        if not isinstance(headers, Mapping):
            raise FingerprintingError(
                "headers must be a mapping."
            )

        if not isinstance(
            body,
            (bytes, bytearray, memoryview),
        ):
            raise FingerprintingError(
                "body must contain raw response bytes."
            )

        normalized_headers = self._normalize_headers(headers)

        matches: list[_FingerprintMatch] = []

        matches.extend(
            self._fingerprint_server_header(
                normalized_headers
            )
        )

        matches.extend(
            self._fingerprint_powered_by(
                normalized_headers
            )
        )

        matches.extend(
            self._fingerprint_header_presence(
                normalized_headers
            )
        )

        matches.extend(
            self._fingerprint_body(body)
        )

        technologies: list[Technology] = []
        evidence: list[TechnologyEvidence] = []

        technology_by_key: dict[
            tuple[str, TechnologyCategory],
            Technology,
        ] = {}

        evidence_keys: set[
            tuple[
                UUID,
                TechnologyEvidenceType,
                str,
            ]
        ] = set()

        for match in matches:
            key = (
                match.name.lower(),
                match.category,
            )

            technology = technology_by_key.get(key)

            if technology is None:
                technology = Technology(
                    name=match.name,
                    category=match.category,
                    version=match.version,
                )
                technology_by_key[key] = technology
                technologies.append(technology)

            elif (
                technology.version is None
                and match.version is not None
            ):
                technology.version = match.version

            evidence_key = (
                technology.id,
                match.evidence_type,
                match.rule,
            )

            if evidence_key in evidence_keys:
                continue

            evidence_keys.add(evidence_key)

            evidence.append(
                TechnologyEvidence(
                    technology_id=technology.id,
                    evidence_type=match.evidence_type,
                    source_id=endpoint.id,
                    observation=match.observation,
                    rule=match.rule,
                    confidence=match.confidence,
                )
            )

        if response_hash is not None:
            self._add_response_hash_evidence(
                endpoint=endpoint,
                response_hash=response_hash,
                technologies=technologies,
                evidence=evidence,
            )

        return FingerprintingResult(
            technologies=technologies,
            evidence=evidence,
        )

    @staticmethod
    def _normalize_headers(
        headers: Mapping[str, str],
    ) -> dict[str, str]:
        normalized: dict[str, str] = {}

        for name, value in headers.items():
            if not isinstance(name, str):
                raise FingerprintingError(
                    "HTTP header names must be strings."
                )

            if not isinstance(value, str):
                raise FingerprintingError(
                    "HTTP header values must be strings."
                )

            normalized[name.strip().lower()] = value.strip()

        return normalized

    @classmethod
    def _fingerprint_server_header(
        cls,
        headers: Mapping[str, str],
    ) -> list[_FingerprintMatch]:
        value = headers.get("server")

        if not value:
            return []

        matches: list[_FingerprintMatch] = []

        for (
            pattern,
            name,
            category,
            rule,
        ) in cls._SERVER_RULES:
            match = pattern.search(value)

            if match is None:
                continue

            version = cls._extract_version(match)

            observation = (
                f"HTTP Server header observed: {value}"
            )

            matches.append(
                _FingerprintMatch(
                    name=name,
                    category=category,
                    version=version,
                    evidence_type=(
                        TechnologyEvidenceType.HTTP_HEADER
                    ),
                    observation=observation,
                    rule=rule,
                    confidence=TechnologyConfidence.HIGH,
                )
            )

        return matches

    @classmethod
    def _fingerprint_powered_by(
        cls,
        headers: Mapping[str, str],
    ) -> list[_FingerprintMatch]:
        value = headers.get("x-powered-by")

        if not value:
            return []

        matches: list[_FingerprintMatch] = []

        for (
            pattern,
            name,
            category,
            rule,
        ) in cls._POWERED_BY_RULES:
            match = pattern.search(value)

            if match is None:
                continue

            version = cls._extract_version(match)

            matches.append(
                _FingerprintMatch(
                    name=name,
                    category=category,
                    version=version,
                    evidence_type=(
                        TechnologyEvidenceType.HTTP_HEADER
                    ),
                    observation=(
                        "HTTP X-Powered-By header observed: "
                        f"{value}"
                    ),
                    rule=rule,
                    confidence=TechnologyConfidence.HIGH,
                )
            )

        return matches

    @classmethod
    def _fingerprint_header_presence(
        cls,
        headers: Mapping[str, str],
    ) -> list[_FingerprintMatch]:
        """Identify technologies from generic framework header names."""
        matches: list[_FingerprintMatch] = []

        for header, name, category, rule in cls._HEADER_PRESENCE_RULES:
            if header not in headers:
                continue

            matches.append(
                _FingerprintMatch(
                    name=name,
                    category=category,
                    version=None,
                    evidence_type=TechnologyEvidenceType.HTTP_HEADER,
                    observation=(
                        f"HTTP header observed: {header}: "
                        f"{headers[header]}"
                    ),
                    rule=rule,
                    confidence=TechnologyConfidence.HIGH,
                )
            )

        return matches

    @classmethod
    def _fingerprint_body(
        cls,
        body: bytes | bytearray | memoryview,
    ) -> list[_FingerprintMatch]:
        try:
            text = bytes(body).decode(
                "utf-8",
                errors="ignore",
            )
        except Exception as exc:
            raise FingerprintingError(
                "Unable to inspect response body."
            ) from exc

        matches: list[_FingerprintMatch] = []

        for (
            pattern,
            name,
            category,
            rule,
            confidence,
        ) in cls._BODY_RULES:
            match = pattern.search(text)

            if match is None:
                continue

            version = cls._extract_version(match)

            matches.append(
                _FingerprintMatch(
                    name=name,
                    category=category,
                    version=version,
                    evidence_type=(
                        TechnologyEvidenceType.HTML
                    ),
                    observation=(
                        f"HTML response marker matched for {name}."
                    ),
                    rule=rule,
                    confidence=confidence,
                )
            )

        return matches

    @staticmethod
    def _extract_version(
        match: re.Match[str],
    ) -> str | None:
        try:
            version = match.group("version")
        except IndexError:
            return None

        if version is None:
            return None

        normalized = version.strip()

        return normalized if normalized else None

    @staticmethod
    def _add_response_hash_evidence(
        *,
        endpoint: Endpoint,
        response_hash: str,
        technologies: list[Technology],
        evidence: list[TechnologyEvidence],
    ) -> None:
        if not isinstance(response_hash, str):
            raise FingerprintingError(
                "response_hash must be a string."
            )

        normalized_hash = response_hash.strip().lower()

        if (
            len(normalized_hash) != 64
            or any(
                character not in "0123456789abcdef"
                for character in normalized_hash
            )
        ):
            raise FingerprintingError(
                "response_hash must be a SHA-256 hexadecimal digest."
            )

        if not technologies:
            return

        for technology in technologies:
            evidence.append(
                TechnologyEvidence(
                    technology_id=technology.id,
                    evidence_type=(
                        TechnologyEvidenceType.RESPONSE_HASH
                    ),
                    source_id=endpoint.id,
                    observation=(
                        "Observed response SHA-256: "
                        f"{normalized_hash}"
                    ),
                    rule="response_hash_sha256",
                    confidence=TechnologyConfidence.LOW,
                )
            )


__all__ = [
    "FingerprintingError",
    "FingerprintingResult",
    "TechnologyFingerprinter",
]
