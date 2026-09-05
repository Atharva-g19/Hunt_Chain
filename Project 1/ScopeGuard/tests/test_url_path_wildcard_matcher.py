from scopeguard.matchers.url_path_wildcard_matcher import (
    UrlPathWildcardMatcher,
)


def test_direct_path_matches():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://example.com/api/",
        "https://example.com/api/*"
    )

    assert result.matched is True
    assert result.reason == "URL path wildcard match"


def test_nested_path_matches():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://example.com/api/users",
        "https://example.com/api/*"
    )

    assert result.matched is True


def test_deep_nested_path_matches():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://example.com/api/v1/users/123",
        "https://example.com/api/*"
    )

    assert result.matched is True


def test_base_path_without_trailing_slash_matches():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://example.com/api",
        "https://example.com/api/*"
    )

    assert result.matched is True


def test_different_path_does_not_match():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://example.com/admin",
        "https://example.com/api/*"
    )

    assert result.matched is False


def test_similar_prefix_does_not_match():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://example.com/api-attacker",
        "https://example.com/api/*"
    )

    assert result.matched is False


def test_similar_nested_prefix_does_not_match():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://example.com/apix/users",
        "https://example.com/api/*"
    )

    assert result.matched is False


def test_different_hostname_does_not_match():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://api.example.com/api/users",
        "https://example.com/api/*"
    )

    assert result.matched is False


def test_attacker_domain_does_not_match():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://example.com.attacker.com/api/users",
        "https://example.com/api/*"
    )

    assert result.matched is False


def test_prefix_attacker_domain_does_not_match():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://evil-example.com/api/users",
        "https://example.com/api/*"
    )

    assert result.matched is False


def test_different_scheme_does_not_match():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "http://example.com/api/users",
        "https://example.com/api/*"
    )

    assert result.matched is False


def test_different_port_does_not_match():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://example.com:8080/api/users",
        "https://example.com/api/*"
    )

    assert result.matched is False


def test_same_port_matches():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://example.com:8080/api/users",
        "https://example.com:8080/api/*"
    )

    assert result.matched is True


def test_hostname_case_is_normalized():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://Example.COM/api/users",
        "https://example.com/api/*"
    )

    assert result.matched is True


def test_hostname_trailing_dot_is_normalized():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://example.com./api/users",
        "https://example.com/api/*"
    )

    assert result.matched is True


def test_query_string_does_not_change_path_match():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://example.com/api/users?id=10",
        "https://example.com/api/*"
    )

    assert result.matched is True


def test_fragment_does_not_change_path_match():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://example.com/api/users#profile",
        "https://example.com/api/*"
    )

    assert result.matched is True


def test_empty_target_does_not_match():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "",
        "https://example.com/api/*"
    )

    assert result.matched is False


def test_empty_rule_does_not_match():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://example.com/api/users",
        ""
    )

    assert result.matched is False


def test_invalid_rule_without_wildcard_does_not_match():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://example.com/api/users",
        "https://example.com/api/"
    )

    assert result.matched is False


def test_invalid_rule_with_wrong_wildcard_position_does_not_match():
    matcher = UrlPathWildcardMatcher()

    result = matcher.matches(
        "https://example.com/api/users",
        "https://example.com/api/*/users"
    )

    assert result.matched is False