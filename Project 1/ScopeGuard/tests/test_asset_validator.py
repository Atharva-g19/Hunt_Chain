import pytest

from scopeguard.models.asset import Asset
from scopeguard.models.asset_type import AssetType
from scopeguard.validators.asset_validator import AssetValidator
from scopeguard.validators.errors import ScopeValidationError


def test_valid_hostname():
    asset = Asset(
        type=AssetType.HOSTNAME,
        value="example.com"
    )

    AssetValidator().validate(asset)


def test_hostname_cannot_contain_scheme():
    asset = Asset(
        type=AssetType.HOSTNAME,
        value="https://example.com"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_hostname_cannot_contain_path():
    asset = Asset(
        type=AssetType.HOSTNAME,
        value="example.com/admin"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_hostname_cannot_have_empty_label():
    asset = Asset(
        type=AssetType.HOSTNAME,
        value="example..com"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_hostname_label_cannot_start_with_hyphen():
    asset = Asset(
        type=AssetType.HOSTNAME,
        value="-example.com"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_hostname_label_cannot_end_with_hyphen():
    asset = Asset(
        type=AssetType.HOSTNAME,
        value="example-.com"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_hostname_cannot_contain_invalid_character():
    asset = Asset(
        type=AssetType.HOSTNAME,
        value="example_com"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_hostname_allows_trailing_dot():
    asset = Asset(
        type=AssetType.HOSTNAME,
        value="example.com."
    )

    AssetValidator().validate(asset)


def test_valid_host_wildcard():
    asset = Asset(
        type=AssetType.HOST_WILDCARD,
        value="*.example.com"
    )

    AssetValidator().validate(asset)


def test_host_wildcard_must_start_with_star_dot():
    asset = Asset(
        type=AssetType.HOST_WILDCARD,
        value="example.com"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_host_wildcard_cannot_have_multiple_stars():
    asset = Asset(
        type=AssetType.HOST_WILDCARD,
        value="*.*.example.com"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_host_wildcard_cannot_contain_path():
    asset = Asset(
        type=AssetType.HOST_WILDCARD,
        value="*.example.com/admin"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_host_wildcard_cannot_have_invalid_hostname():
    asset = Asset(
        type=AssetType.HOST_WILDCARD,
        value="*.-example.com"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_valid_https_url():
    asset = Asset(
        type=AssetType.URL,
        value="https://example.com"
    )

    AssetValidator().validate(asset)


def test_valid_http_url_with_path():
    asset = Asset(
        type=AssetType.URL,
        value="http://example.com/login"
    )

    AssetValidator().validate(asset)


def test_url_requires_http_or_https():
    asset = Asset(
        type=AssetType.URL,
        value="ftp://example.com"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_url_requires_hostname():
    asset = Asset(
        type=AssetType.URL,
        value="https://"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_url_cannot_contain_wildcard():
    asset = Asset(
        type=AssetType.URL,
        value="https://*.example.com"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_valid_url_path_wildcard():
    asset = Asset(
        type=AssetType.URL_PATH_WILDCARD,
        value="https://example.com/api/*"
    )

    AssetValidator().validate(asset)


def test_valid_nested_url_path_wildcard():
    asset = Asset(
        type=AssetType.URL_PATH_WILDCARD,
        value="https://api.example.com/v1/users/*"
    )

    AssetValidator().validate(asset)


def test_url_path_wildcard_requires_star():
    asset = Asset(
        type=AssetType.URL_PATH_WILDCARD,
        value="https://example.com/api/"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_url_path_wildcard_must_end_with_star():
    asset = Asset(
        type=AssetType.URL_PATH_WILDCARD,
        value="https://example.com/api/*/users"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_url_path_wildcard_cannot_have_multiple_stars():
    asset = Asset(
        type=AssetType.URL_PATH_WILDCARD,
        value="https://example.com/api/*/users/*"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_url_path_wildcard_cannot_wildcard_hostname():
    asset = Asset(
        type=AssetType.URL_PATH_WILDCARD,
        value="https://*.example.com/api/*"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_url_path_wildcard_requires_specific_path():
    asset = Asset(
        type=AssetType.URL_PATH_WILDCARD,
        value="https://example.com/*"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_url_path_wildcard_requires_http_or_https():
    asset = Asset(
        type=AssetType.URL_PATH_WILDCARD,
        value="ftp://example.com/api/*"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_valid_ipv4():
    asset = Asset(
        type=AssetType.IPV4,
        value="192.168.1.10"
    )

    AssetValidator().validate(asset)


def test_valid_public_ipv4():
    asset = Asset(
        type=AssetType.IPV4,
        value="8.8.8.8"
    )

    AssetValidator().validate(asset)


def test_ipv4_rejects_invalid_address():
    asset = Asset(
        type=AssetType.IPV4,
        value="192.168.1.256"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_ipv4_rejects_ipv6():
    asset = Asset(
        type=AssetType.IPV4,
        value="2001:db8::1"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_ipv4_rejects_cidr():
    asset = Asset(
        type=AssetType.IPV4,
        value="192.168.1.0/24"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_valid_ipv4_cidr():
    asset = Asset(
        type=AssetType.IPV4_CIDR,
        value="192.168.1.0/24"
    )

    AssetValidator().validate(asset)


def test_valid_ipv4_cidr_32():
    asset = Asset(
        type=AssetType.IPV4_CIDR,
        value="192.168.1.10/32"
    )

    AssetValidator().validate(asset)


def test_valid_ipv4_cidr_8():
    asset = Asset(
        type=AssetType.IPV4_CIDR,
        value="10.0.0.0/8"
    )

    AssetValidator().validate(asset)


def test_ipv4_cidr_requires_network_address():
    asset = Asset(
        type=AssetType.IPV4_CIDR,
        value="192.168.1.10/24"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_ipv4_cidr_rejects_ipv6():
    asset = Asset(
        type=AssetType.IPV4_CIDR,
        value="2001:db8::/32"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_ipv4_cidr_rejects_invalid_prefix():
    asset = Asset(
        type=AssetType.IPV4_CIDR,
        value="192.168.1.0/33"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)


def test_ipv4_cidr_rejects_missing_prefix():
    asset = Asset(
        type=AssetType.IPV4_CIDR,
        value="192.168.1.0"
    )

    with pytest.raises(ScopeValidationError):
        AssetValidator().validate(asset)