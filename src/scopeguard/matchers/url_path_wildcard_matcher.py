from urllib.parse import urlparse

from .match_result import MatchResult


class UrlPathWildcardMatcher:
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

        if not rule_value.endswith("/*"):
            return MatchResult(
                matched=False,
                reason="Rule is not a valid URL path wildcard"
            )

        rule_base = rule_value[:-2]

        try:
            target_parsed = urlparse(target)
            rule_parsed = urlparse(rule_base)

            target_port = self._normalize_port(target_parsed)
            rule_port = self._normalize_port(rule_parsed)

        except ValueError:
            return MatchResult(
                matched=False,
                reason="Invalid URL"
            )

        if target_parsed.scheme.lower() != rule_parsed.scheme.lower():
            return MatchResult(
                matched=False,
                reason="URL schemes do not match"
            )

        if self._normalize_hostname(target_parsed.hostname) != (
            self._normalize_hostname(rule_parsed.hostname)
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

        rule_path = rule_parsed.path.rstrip("/")

        if not rule_path:
            return MatchResult(
                matched=False,
                reason="Wildcard rule has no specific path"
            )

        target_path = target_parsed.path

        if target_path == rule_path:
            return MatchResult(
                matched=True,
                reason="URL path wildcard match"
            )

        if target_path.startswith(rule_path + "/"):
            return MatchResult(
                matched=True,
                reason="URL path wildcard match"
            )

        return MatchResult(
            matched=False,
            reason="Target path does not match wildcard rule"
        )

    def _normalize_hostname(self, hostname: str | None) -> str:
        if hostname is None:
            return ""

        return hostname.rstrip(".").lower()

    def _normalize_port(self, parsed_url) -> int | None:
        return parsed_url.port