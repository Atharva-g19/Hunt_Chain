from scopeguard.matchers.hostname_matcher import HostnameMatcher


def test_exact_hostname_matches():
    matcher = HostnameMatcher()

    result = matcher.matches(
        "example.com",
        "example.com"
    )

    assert result.matched is True
    assert result.reason == "Exact hostname match"


def test_different_hostname_does_not_match():
    matcher = HostnameMatcher()

    result = matcher.matches(
        "example.org",
        "example.com"
    )

    assert result.matched is False


def test_subdomain_does_not_match_exact_hostname():
    matcher = HostnameMatcher()

    result = matcher.matches(
        "www.example.com",
        "example.com"
    )

    assert result.matched is False


def test_parent_domain_does_not_match_subdomain_rule():
    matcher = HostnameMatcher()

    result = matcher.matches(
        "example.com",
        "www.example.com"
    )

    assert result.matched is False


def test_attacker_domain_does_not_match():
    matcher = HostnameMatcher()

    result = matcher.matches(
        "example.com.attacker.com",
        "example.com"
    )

    assert result.matched is False


def test_prefix_attacker_domain_does_not_match():
    matcher = HostnameMatcher()

    result = matcher.matches(
        "evil-example.com",
        "example.com"
    )

    assert result.matched is False


def test_hostname_matching_is_case_insensitive():
    matcher = HostnameMatcher()

    result = matcher.matches(
        "Example.COM",
        "example.com"
    )

    assert result.matched is True


def test_trailing_dot_is_normalized():
    matcher = HostnameMatcher()

    result = matcher.matches(
        "example.com.",
        "example.com"
    )

    assert result.matched is True


def test_whitespace_is_normalized():
    matcher = HostnameMatcher()

    result = matcher.matches(
        "  example.com  ",
        "example.com"
    )

    assert result.matched is True


def test_empty_target_does_not_match():
    matcher = HostnameMatcher()

    result = matcher.matches(
        "",
        "example.com"
    )

    assert result.matched is False


def test_empty_rule_does_not_match():
    matcher = HostnameMatcher()

    result = matcher.matches(
        "example.com",
        ""
    )

    assert result.matched is False


def test_hostname_match_is_not_substring_matching():
    matcher = HostnameMatcher()

    result = matcher.matches(
        "notexample.com",
        "example.com"
    )

    assert result.matched is False