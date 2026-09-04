from urllib.parse import urlparse

from .match_result import MatchResult


class UrlMatcher:
    def matches(self, target: str, rule_value: str) -> MatchResult:
        if not target or not rule_value:
            return MatchResult(
                matched=False,
                reason="Target or rule value is empty"
            )

        if not isinstance(target, str):
            return MatchResult(
                matched=False,
                reason="Target must be a string"
            )

        if not isinstance(rule_value, str):
            return MatchResult(
                matched=False,
                reason="Rule value must be a string"
            )

        try:
            target_parsed = urlparse(target)
            rule_parsed = urlparse(rule_value)

            target_port = self._normalize_port(target_parsed)
            rule_port = self._normalize_port(rule_parsed)

        except ValueError:
            return MatchResult(
                matched=False,
                reason="Invalid URL"
            )

        if (
            self._normalize_scheme(target_parsed.scheme)
            != self._normalize_scheme(rule_parsed.scheme)
        ):
            return MatchResult(
                matched=False,
                reason="URL schemes do not match"
            )

        if (
            self._normalize_hostname(target_parsed.hostname)
            != self._normalize_hostname(rule_parsed.hostname)
        ):
            return MatchResult(
                matched=False,
                reason="URL hostnames do not match"
            )

        if target_port != rule_port:
            return MatchResult(
                matched=False,
                reason="URL ports do not match"
            )

        if target_parsed.path != rule_parsed.path:
            return MatchResult(
                matched=False,
                reason="URL paths do not match"
            )

        if target_parsed.query != rule_parsed.query:
            return MatchResult(
                matched=False,
                reason="URL query strings do not match"
            )

        if target_parsed.fragment != rule_parsed.fragment:
            return MatchResult(
                matched=False,
                reason="URL fragments do not match"
            )

        return MatchResult(
            matched=True,
            reason="Exact URL match"
        )

    def _normalize_scheme(self, scheme: str | None) -> str:
        if scheme is None:
            return ""

        return scheme.lower()

    def _normalize_hostname(self, hostname: str | None) -> str:
        if hostname is None:
            return ""

        return hostname.rstrip(".").lower()

    def _normalize_port(self, parsed_url) -> int | None:
        return parsed_url.port