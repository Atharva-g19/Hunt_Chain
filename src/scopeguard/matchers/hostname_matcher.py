from .match_result import MatchResult


class HostnameMatcher:
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

        if target_normalized == rule_normalized:
            return MatchResult(
                matched=True,
                reason="Exact hostname match"
            )

        return MatchResult(
            matched=False,
            reason="Hostname does not exactly match rule"
        )

    def _normalize(self, value: str) -> str:
        return value.strip().rstrip(".").lower()