from scopeguard.matchers.host_wildcard_matcher import HostWildcardMatcher


def test_direct_subdomain_matches():
    matcher = HostWildcardMatcher()

    result = matcher.matches(
        "www.example.com",
        "*.example.com"
    )

    assert result.matched is True
    assert result.reason == "Host wildcard match"


def test_api_subdomain_matches():
    matcher = HostWildcardMatcher()

    result = matcher.matches(
        "api.example.com",
        "*.example.com"
    )

    assert result.matched is True


def test_nested_subdomain_matches():
    matcher = HostWildcardMatcher()

    result = matcher.matches(
        "v1.api.example.com",
        "*.example.com"
    )

    assert result.matched is True


def test_apex_domain_does_not_match():
    matcher = HostWildcardMatcher()

    result = matcher.matches(
        "example.com",
        "*.example.com"
    )

    assert result.matched is False
    assert result.reason == "Wildcard does not match the apex hostname"


def test_attacker_domain_does_not_match():
    matcher = HostWildcardMatcher()

    result = matcher.matches(
        "example.com.attacker.com",
        "*.example.com"
    )

    assert result.matched is False


def test_prefix_attacker_domain_does_not_match():
    matcher = HostWildcardMatcher()

    result = matcher.matches(
        "evil-example.com",
        "*.example.com"
    )

    assert result.matched is False


def test_different_domain_does_not_match():
    matcher = HostWildcardMatcher()

    result = matcher.matches(
        "www.example.org",
        "*.example.com"
    )

    assert result.matched is False


def test_case_insensitive_matching():
    matcher = HostWildcardMatcher()

    result = matcher.matches(
        "WWW.Example.COM",
        "*.example.com"
    )

    assert result.matched is True


def test_trailing_dot_is_normalized():
    matcher = HostWildcardMatcher()

    result = matcher.matches(
        "www.example.com.",
        "*.example.com"
    )

    assert result.matched is True


def test_whitespace_is_normalized():
    matcher = HostWildcardMatcher()

    result = matcher.matches(
        "  www.example.com  ",
        "*.example.com"
    )

    assert result.matched is True


def test_invalid_rule_does_not_match():
    matcher = HostWildcardMatcher()

    result = matcher.matches(
        "www.example.com",
        "example.com"
    )

    assert result.matched is False


def test_empty_target_does_not_match():
    matcher = HostWildcardMatcher()

    result = matcher.matches(
        "",
        "*.example.com"
    )

    assert result.matched is False


def test_empty_rule_does_not_match():
    matcher = HostWildcardMatcher()

    result = matcher.matches(
        "www.example.com",
        ""
    )

    assert result.matched is False