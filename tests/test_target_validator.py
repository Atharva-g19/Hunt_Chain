import pytest

from scopeguard.models.target import Target
from scopeguard.validators.errors import ScopeValidationError
from scopeguard.validators.target_validator import TargetValidator


def create_target(
    raw_value,
    normalized_value,
    target_type,
):
    return Target(
        raw_value=raw_value,
        normalized_value=normalized_value,
        type=target_type,
    )


def test_valid_hostname_target():
    target = create_target(
        "example.com",
        "example.com",
        "hostname",
    )

    TargetValidator().validate(target)


def test_valid_subdomain_target():
    target = create_target(
        "admin.example.com",
        "admin.example.com",
        "hostname",
    )

    TargetValidator().validate(target)


def test_valid_hostname_with_trailing_dot():
    target = create_target(
        "example.com.",
        "example.com",
        "hostname",
    )

    TargetValidator().validate(target)


def test_hostname_with_scheme_is_invalid():
    target = create_target(
        "https://example.com",
        "https://example.com",
        "hostname",
    )

    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(target)


def test_hostname_with_path_is_invalid():
    target = create_target(
        "example.com/login",
        "example.com/login",
        "hostname",
    )

    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(target)


def test_hostname_with_empty_label_is_invalid():
    target = create_target(
        "api..example.com",
        "api..example.com",
        "hostname",
    )

    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(target)


def test_hostname_with_invalid_character_is_invalid():
    target = create_target(
        "api_example.com",
        "api_example.com",
        "hostname",
    )

    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(target)


def test_valid_host_wildcard_target():
    target = create_target(
        "*.example.com",
        "*.example.com",
        "host_wildcard",
    )

    TargetValidator().validate(target)


def test_host_wildcard_without_prefix_is_invalid():
    target = create_target(
        "example.com",
        "example.com",
        "host_wildcard",
    )

    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(target)


def test_host_wildcard_with_multiple_wildcards_is_invalid():
    target = create_target(
        "*.*.example.com",
        "*.*.example.com",
        "host_wildcard",
    )

    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(target)


def test_valid_url_target():
    target = create_target(
        "https://example.com/login",
        "https://example.com/login",
        "url",
    )

    TargetValidator().validate(target)


def test_http_url_target_is_valid():
    target = create_target(
        "http://example.com",
        "http://example.com",
        "url",
    )

    TargetValidator().validate(target)


def test_url_with_wildcard_is_invalid():
    target = create_target(
        "https://*.example.com",
        "https://*.example.com",
        "url",
    )

    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(target)


def test_url_with_invalid_scheme_is_invalid():
    target = create_target(
        "ftp://example.com",
        "ftp://example.com",
        "url",
    )

    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(target)


def test_url_without_hostname_is_invalid():
    target = create_target(
        "https:///login",
        "https:///login",
        "url",
    )

    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(target)


def test_valid_url_path_wildcard_target():
    target = create_target(
        "https://example.com/api/*",
        "https://example.com/api/*",
        "url_path_wildcard",
    )

    TargetValidator().validate(target)


def test_url_path_wildcard_without_star_is_invalid():
    target = create_target(
        "https://example.com/api/",
        "https://example.com/api/",
        "url_path_wildcard",
    )

    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(target)


def test_url_path_wildcard_with_multiple_stars_is_invalid():
    target = create_target(
        "https://example.com/*/admin/*",
        "https://example.com/*/admin/*",
        "url_path_wildcard",
    )

    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(target)


def test_url_path_wildcard_with_root_only_is_invalid():
    target = create_target(
        "https://example.com/*",
        "https://example.com/*",
        "url_path_wildcard",
    )

    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(target)


def test_valid_ipv4_target():
    target = create_target(
        "192.168.1.10",
        "192.168.1.10",
        "ipv4",
    )

    TargetValidator().validate(target)


def test_invalid_ipv4_target():
    target = create_target(
        "192.168.1.999",
        "192.168.1.999",
        "ipv4",
    )

    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(target)


def test_ipv6_target_is_rejected():
    target = create_target(
        "2001:db8::1",
        "2001:db8::1",
        "ipv4",
    )

    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(target)


def test_none_target_is_invalid():
    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(None)


def test_empty_raw_value_is_invalid():
    target = create_target(
        "",
        "example.com",
        "hostname",
    )

    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(target)


def test_empty_normalized_value_is_invalid():
    target = create_target(
        "example.com",
        "",
        "hostname",
    )

    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(target)


def test_unsupported_target_type_is_invalid():
    target = create_target(
        "example.com",
        "example.com",
        "cidr",
    )

    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(target)


def test_target_cidr_is_not_supported():
    target = create_target(
        "192.168.1.0/24",
        "192.168.1.0/24",
        "ipv4_cidr",
    )

    with pytest.raises(ScopeValidationError):
        TargetValidator().validate(target)