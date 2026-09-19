import ipaddress

from .match_result import MatchResult


class IPv6CIDRMatcher:
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

        if "/" not in rule_value:
            return MatchResult(
                matched=False,
                reason="Rule is not an IPv6 CIDR",
            )

        try:
            target_address = ipaddress.ip_address(
                target.strip()
            )

            network = ipaddress.ip_network(
                rule_value.strip(),
                strict=True,
            )
        except ValueError:
            return MatchResult(
                matched=False,
                reason="Invalid IPv6 or CIDR value",
            )

        if target_address.version != 6:
            return MatchResult(
                matched=False,
                reason="Target is not an IPv6 address",
            )

        if network.version != 6:
            return MatchResult(
                matched=False,
                reason="Rule is not an IPv6 CIDR",
            )

        if target_address in network:
            return MatchResult(
                matched=True,
                reason="IPv6 address belongs to CIDR network",
            )

        return MatchResult(
            matched=False,
            reason="IPv6 address is outside CIDR network",
        )