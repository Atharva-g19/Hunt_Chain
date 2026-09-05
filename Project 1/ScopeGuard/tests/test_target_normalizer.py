import pytest

from scopeguard.normalizers.target_normalizer import TargetNormalizer


def test_normalizes_hostname_to_lowercase():
    target = TargetNormalizer().normalize(
        "Example.COM"
    )

    assert target.raw_value == "Example.COM"
    assert target.normalized_value == "example.com"
    assert target.type == "hostname"


def test_normalizes_hostname_with_trailing_dot():
    target = TargetNormalizer().normalize(
        "example.com."
    )

    assert target.normalized_value == "example.com"
    assert target.type == "hostname"


def test_normalizes_hostname_with_whitespace():
    target = TargetNormalizer().normalize(
        "  Example.COM  "
    )

    assert target.normalized_value == "example.com"
    assert target.type == "hostname"


def test_detects_subdomain_as_hostname():
    target = TargetNormalizer().normalize(
        "Admin.Example.COM"
    )

    assert target.normalized_value == "admin.example.com"
    assert target.type == "hostname"


def test_detects_http_url():
    target = TargetNormalizer().normalize(
        "HTTP://Example.COM/login"
    )

    assert target.normalized_value == (
        "http://example.com/login"
    )
    assert target.type == "url"


def test_detects_https_url():
    target = TargetNormalizer().normalize(
        "HTTPS://Example.COM"
    )

    assert target.normalized_value == (
        "https://example.com"
    )
    assert target.type == "url"


def test_preserves_url_path():
    target = TargetNormalizer().normalize(
        "https://Example.COM/API/Users"
    )

    assert target.normalized_value == (
        "https://example.com/API/Users"
    )


def test_preserves_url_query():
    target = TargetNormalizer().normalize(
        "https://Example.COM/search?q=test"
    )

    assert target.normalized_value == (
        "https://example.com/search?q=test"
    )


def test_preserves_url_fragment():
    target = TargetNormalizer().normalize(
        "https://Example.COM/docs#intro"
    )

    assert target.normalized_value == (
        "https://example.com/docs#intro"
    )


def test_preserves_non_default_port():
    target = TargetNormalizer().normalize(
        "https://Example.COM:8443/login"
    )

    assert target.normalized_value == (
        "https://example.com:8443/login"
    )


def test_detects_ipv4():
    target = TargetNormalizer().normalize(
        "192.168.1.10"
    )

    assert target.normalized_value == "192.168.1.10"
    assert target.type == "ipv4"


def test_normalizes_ipv4_with_whitespace():
    target = TargetNormalizer().normalize(
        " 192.168.1.10 "
    )

    assert target.normalized_value == "192.168.1.10"
    assert target.type == "ipv4"


def test_rejects_non_string_target():
    with pytest.raises(ValueError):
        TargetNormalizer().normalize(12345)


def test_rejects_empty_target():
    with pytest.raises(ValueError):
        TargetNormalizer().normalize("")


def test_rejects_whitespace_only_target():
    with pytest.raises(ValueError):
        TargetNormalizer().normalize("   ")


def test_rejects_cidr_target():
    with pytest.raises(ValueError):
        TargetNormalizer().normalize(
            "192.168.1.0/24"
        )


def test_rejects_ipv6_target():
    with pytest.raises(ValueError):
        TargetNormalizer().normalize(
            "2001:db8::1"
        )


def test_rejects_wildcard_target():
    with pytest.raises(ValueError):
        TargetNormalizer().normalize(
            "*.example.com"
        )


def test_rejects_hostname_with_path():
    with pytest.raises(ValueError):
        TargetNormalizer().normalize(
            "example.com/login"
        )


def test_rejects_invalid_url_scheme():
    with pytest.raises(ValueError):
        TargetNormalizer().normalize(
            "ftp://example.com"
        )


def test_rejects_url_without_hostname():
    with pytest.raises(ValueError):
        TargetNormalizer().normalize(
            "https:///login"
        )


def test_rejects_invalid_url_port():
    with pytest.raises(ValueError):
        TargetNormalizer().normalize(
            "https://example.com:invalid"
        )


def test_raw_value_is_preserved():
    target = TargetNormalizer().normalize(
        "  Example.COM.  "
    )

    assert target.raw_value == "  Example.COM.  "