from scopeguard.matchers.url_matcher import UrlMatcher


def test_exact_url_matches():
    matcher = UrlMatcher()

    result = matcher.matches(
        "https://example.com/login",
        "https://example.com/login"
    )

    assert result.matched is True
    assert result.reason == "Exact URL match"


def test_different_path_does_not_match():
    matcher = UrlMatcher()

    result = matcher.matches(
        "https://example.com/logout",
        "https://example.com/login"
    )

    assert result.matched is False
    assert result.reason == "URL paths do not match"


def test_different_hostname_does_not_match():
    matcher = UrlMatcher()

    result = matcher.matches(
        "https://api.example.com/login",
        "https://example.com/login"
    )

    assert result.matched is False
    assert result.reason == "URL hostnames do not match"


def test_different_scheme_does_not_match():
    matcher = UrlMatcher()

    result = matcher.matches(
        "http://example.com/login",
        "https://example.com/login"
    )

    assert result.matched is False
    assert result.reason == "URL schemes do not match"


def test_trailing_path_slash_is_not_ignored():
    matcher = UrlMatcher()

    result = matcher.matches(
        "https://example.com/login/",
        "https://example.com/login"
    )

    assert result.matched is False


def test_query_string_must_match():
    matcher = UrlMatcher()

    result = matcher.matches(
        "https://example.com/login?user=1",
        "https://example.com/login"
    )

    assert result.matched is False
    assert result.reason == "URL query strings do not match"


def test_same_query_string_matches():
    matcher = UrlMatcher()

    result = matcher.matches(
        "https://example.com/login?user=1",
        "https://example.com/login?user=1"
    )

    assert result.matched is True


def test_different_query_string_does_not_match():
    matcher = UrlMatcher()

    result = matcher.matches(
        "https://example.com/login?user=2",
        "https://example.com/login?user=1"
    )

    assert result.matched is False


def test_different_query_parameter_order_does_not_match():
    matcher = UrlMatcher()

    result = matcher.matches(
        "https://example.com/login?a=1&b=2",
        "https://example.com/login?b=2&a=1"
    )

    assert result.matched is False


def test_hostname_case_is_normalized():
    matcher = UrlMatcher()

    result = matcher.matches(
        "https://Example.COM/login",
        "https://example.com/login"
    )

    assert result.matched is True


def test_hostname_trailing_dot_is_normalized():
    matcher = UrlMatcher()

    result = matcher.matches(
        "https://example.com./login",
        "https://example.com/login"
    )

    assert result.matched is True


def test_different_port_does_not_match():
    matcher = UrlMatcher()

    result = matcher.matches(
        "https://example.com:8080/login",
        "https://example.com/login"
    )

    assert result.matched is False
    assert result.reason == "URL ports do not match"


def test_same_port_matches():
    matcher = UrlMatcher()

    result = matcher.matches(
        "https://example.com:8080/login",
        "https://example.com:8080/login"
    )

    assert result.matched is True


def test_attacker_domain_does_not_match():
    matcher = UrlMatcher()

    result = matcher.matches(
        "https://example.com.attacker.com/login",
        "https://example.com/login"
    )

    assert result.matched is False


def test_prefix_attacker_domain_does_not_match():
    matcher = UrlMatcher()

    result = matcher.matches(
        "https://evil-example.com/login",
        "https://example.com/login"
    )

    assert result.matched is False


def test_different_fragment_does_not_match():
    matcher = UrlMatcher()

    result = matcher.matches(
        "https://example.com/login#one",
        "https://example.com/login#two"
    )

    assert result.matched is False
    assert result.reason == "URL fragments do not match"


def test_same_fragment_matches():
    matcher = UrlMatcher()

    result = matcher.matches(
        "https://example.com/login#profile",
        "https://example.com/login#profile"
    )

    assert result.matched is True


def test_empty_target_does_not_match():
    matcher = UrlMatcher()

    result = matcher.matches(
        "",
        "https://example.com/login"
    )

    assert result.matched is False


def test_empty_rule_does_not_match():
    matcher = UrlMatcher()

    result = matcher.matches(
        "https://example.com/login",
        ""
    )

    assert result.matched is False