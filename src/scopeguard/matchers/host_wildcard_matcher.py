from .match_result import MatchResult


class HostWildcardMatcher:
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

        target_normalized = self._normalize(target)
        rule_normalized = self._normalize(rule_value)

        if not rule_normalized.startswith("*."):
            return MatchResult(
                matched=False,
                reason="Rule is not a valid host wildcard"
            )

        base_hostname = rule_normalized[2:]

        if not base_hostname:
            return MatchResult(
                matched=False,
                reason="Wildcard base hostname is empty"
            )

        if target_normalized == base_hostname:
            return MatchResult(
                matched=False,
                reason="Wildcard does not match the apex hostname"
            )

        if target_normalized.endswith("." + base_hostname):
            return MatchResult(
                matched=True,
                reason="Host wildcard match"
            )

        return MatchResult(
            matched=False,
            reason="Hostname does not match wildcard rule"
        )

    def _normalize(self, value: str) -> str:
        return value.strip().rstrip(".").lower()