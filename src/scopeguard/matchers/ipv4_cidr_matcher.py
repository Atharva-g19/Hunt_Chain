import ipaddress

from .match_result import MatchResult


class IPv4CIDRMatcher:
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

        if "/" not in rule_value:
            return MatchResult(
                matched=False,
                reason="Rule is not an IPv4 CIDR"
            )

        try:
            target_address = ipaddress.ip_address(
                target.strip()
            )

            network = ipaddress.ip_network(
                rule_value.strip(),
                strict=True
            )

        except ValueError:
            return MatchResult(
                matched=False,
                reason="Invalid IPv4 or CIDR value"
            )

        if target_address.version != 4:
            return MatchResult(
                matched=False,
                reason="Target is not an IPv4 address"
            )

        if network.version != 4:
            return MatchResult(
                matched=False,
                reason="Rule is not an IPv4 CIDR"
            )

        if target_address in network:
            return MatchResult(
                matched=True,
                reason="IPv4 address belongs to CIDR network"
            )

        return MatchResult(
            matched=False,
            reason="IPv4 address is outside CIDR network"
        )