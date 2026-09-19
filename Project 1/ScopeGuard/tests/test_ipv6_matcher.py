from scopeguard.matchers.ipv6_matcher import IPv6Matcher


def test_exact_ipv6_matches():
    result = IPv6Matcher().matches(
        "2001:db8::1",
        "2001:db8::1",
    )

    assert result.matched is True


def test_different_ipv6_does_not_match():
    result = IPv6Matcher().matches(
        "2001:db8::1",
        "2001:db8::2",
    )

    assert result.matched is False


def test_compressed_and_expanded_ipv6_match():
    result = IPv6Matcher().matches(
        "2001:db8::1",
        "2001:0db8:0:0:0:0:0:1",
    )

    assert result.matched is True


def test_ipv4_does_not_match_ipv6_rule():
    result = IPv6Matcher().matches(
        "192.0.2.1",
        "2001:db8::1",
    )

    assert result.matched is False


def test_invalid_ipv6_does_not_match():
    result = IPv6Matcher().matches(
        "2001:db8::zz",
        "2001:db8::1",
    )

    assert result.matched is False
