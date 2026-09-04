from scopeguard.matchers.ipv4_cidr_matcher import IPv4CIDRMatcher


def test_ipv4_inside_cidr_matches():
    matcher = IPv4CIDRMatcher()

    result = matcher.matches(
        "192.168.1.50",
        "192.168.1.0/24"
    )

    assert result.matched is True
    assert result.reason == "IPv4 address belongs to CIDR network"


def test_first_address_matches():
    matcher = IPv4CIDRMatcher()

    result = matcher.matches(
        "192.168.1.0",
        "192.168.1.0/24"
    )

    assert result.matched is True


def test_last_address_matches():
    matcher = IPv4CIDRMatcher()

    result = matcher.matches(
        "192.168.1.255",
        "192.168.1.0/24"
    )

    assert result.matched is True


def test_address_outside_cidr_does_not_match():
    matcher = IPv4CIDRMatcher()

    result = matcher.matches(
        "192.168.2.1",
        "192.168.1.0/24"
    )

    assert result.matched is False
    assert result.reason == "IPv4 address is outside CIDR network"


def test_nearby_address_does_not_match():
    matcher = IPv4CIDRMatcher()

    result = matcher.matches(
        "192.168.0.255",
        "192.168.1.0/24"
    )

    assert result.matched is False


def test_32_cidr_matches_exact_address():
    matcher = IPv4CIDRMatcher()

    result = matcher.matches(
        "192.168.1.10",
        "192.168.1.10/32"
    )

    assert result.matched is True


def test_32_cidr_does_not_match_different_address():
    matcher = IPv4CIDRMatcher()

    result = matcher.matches(
        "192.168.1.11",
        "192.168.1.10/32"
    )

    assert result.matched is False


def test_larger_network_matches():
    matcher = IPv4CIDRMatcher()

    result = matcher.matches(
        "10.20.30.40",
        "10.0.0.0/8"
    )

    assert result.matched is True


def test_address_outside_larger_network_does_not_match():
    matcher = IPv4CIDRMatcher()

    result = matcher.matches(
        "11.20.30.40",
        "10.0.0.0/8"
    )

    assert result.matched is False


def test_ipv6_target_does_not_match():
    matcher = IPv4CIDRMatcher()

    result = matcher.matches(
        "2001:db8::1",
        "192.168.1.0/24"
    )

    assert result.matched is False


def test_ipv6_network_does_not_match():
    matcher = IPv4CIDRMatcher()

    result = matcher.matches(
        "192.168.1.10",
        "2001:db8::/32"
    )

    assert result.matched is False


def test_invalid_target_does_not_match():
    matcher = IPv4CIDRMatcher()

    result = matcher.matches(
        "192.168.1.256",
        "192.168.1.0/24"
    )

    assert result.matched is False


def test_invalid_cidr_does_not_match():
    matcher = IPv4CIDRMatcher()

    result = matcher.matches(
        "192.168.1.10",
        "192.168.1.0/33"
    )

    assert result.matched is False


def test_non_network_address_cidr_does_not_match():
    matcher = IPv4CIDRMatcher()

    result = matcher.matches(
        "192.168.1.50",
        "192.168.1.50/24"
    )

    assert result.matched is False


def test_missing_prefix_does_not_match():
    matcher = IPv4CIDRMatcher()

    result = matcher.matches(
        "192.168.1.10",
        "192.168.1.10"
    )

    assert result.matched is False


def test_empty_target_does_not_match():
    matcher = IPv4CIDRMatcher()

    result = matcher.matches(
        "",
        "192.168.1.0/24"
    )

    assert result.matched is False


def test_empty_rule_does_not_match():
    matcher = IPv4CIDRMatcher()

    result = matcher.matches(
        "192.168.1.10",
        ""
    )

    assert result.matched is False


def test_whitespace_is_ignored():
    matcher = IPv4CIDRMatcher()

    result = matcher.matches(
        " 192.168.1.50 ",
        " 192.168.1.0/24 "
    )

    assert result.matched is True