import ipaddress

from .match_result import MatchResult


class IPv6Matcher:
    """Exact IPv6 address matcher."""

    def matches(
        self,
        target: str,
        rule_value: str,
    ) -> MatchResult:
        if not target or not rule_value:
            return MatchResult(
                matched=False,
                reason="Target or rule value is empty",
            )

        if not isinstance(target, str):
            return MatchResult(
                matched=False,
                reason="Target must be a string",
            )

        if not isinstance(rule_value, str):
            return MatchResult(
                matched=False,
                reason="Rule value must be a string",
            )

        try:
            target_address = ipaddress.ip_address(
                target.strip()
            )
            rule_address = ipaddress.ip_address(
                rule_value.strip()
            )
        except ValueError:
            return MatchResult(
                matched=False,
                reason="Invalid IPv6 address",
            )

        if target_address.version != 6:
            return MatchResult(
                matched=False,
                reason="Target is not an IPv6 address",
            )

        if rule_address.version != 6:
            return MatchResult(
                matched=False,
                reason="Rule is not an IPv6 address",
            )

        if target_address == rule_address:
            return MatchResult(
                matched=True,
                reason="Exact IPv6 address match",
            )

        return MatchResult(
            matched=False,
            reason="IPv6 addresses do not match",
        )