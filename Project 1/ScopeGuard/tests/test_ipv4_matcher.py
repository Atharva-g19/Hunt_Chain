from scopeguard.matchers.ipv4_matcher import IPv4Matcher


def test_exact_ipv4_matches():
    matcher = IPv4Matcher()

    result = matcher.matches(
        "192.168.1.10",
        "192.168.1.10"
    )

    assert result.matched is True
    assert result.reason == "Exact IPv4 address match"


def test_different_ipv4_does_not_match():
    matcher = IPv4Matcher()

    result = matcher.matches(
        "192.168.1.11",
        "192.168.1.10"
    )

    assert result.matched is False


def test_different_network_does_not_match():
    matcher = IPv4Matcher()

    result = matcher.matches(
        "192.168.2.10",
        "192.168.1.10"
    )

    assert result.matched is False


def test_ipv4_cidr_rule_does_not_match():
    matcher = IPv4Matcher()

    result = matcher.matches(
        "192.168.1.10",
        "192.168.1.0/24"
    )

    assert result.matched is False


def test_ipv6_target_does_not_match():
    matcher = IPv4Matcher()

    result = matcher.matches(
        "2001:db8::1",
        "192.168.1.10"
    )

    assert result.matched is False


def test_ipv6_rule_does_not_match():
    matcher = IPv4Matcher()

    result = matcher.matches(
        "192.168.1.10",
        "2001:db8::1"
    )

    assert result.matched is False


def test_invalid_target_does_not_match():
    matcher = IPv4Matcher()

    result = matcher.matches(
        "192.168.1.256",
        "192.168.1.10"
    )

    assert result.matched is False


def test_invalid_rule_does_not_match():
    matcher = IPv4Matcher()

    result = matcher.matches(
        "192.168.1.10",
        "192.168.1.256"
    )

    assert result.matched is False


def test_whitespace_is_ignored():
    matcher = IPv4Matcher()

    result = matcher.matches(
        " 192.168.1.10 ",
        "192.168.1.10"
    )

    assert result.matched is True


def test_empty_target_does_not_match():
    matcher = IPv4Matcher()

    result = matcher.matches(
        "",
        "192.168.1.10"
    )

    assert result.matched is False


def test_empty_rule_does_not_match():
    matcher = IPv4Matcher()

    result = matcher.matches(
        "192.168.1.10",
        ""
    )

    assert result.matched is False


def test_loopback_ipv4_matches_exactly():
    matcher = IPv4Matcher()

    result = matcher.matches(
        "127.0.0.1",
        "127.0.0.1"
    )

    assert result.matched is True