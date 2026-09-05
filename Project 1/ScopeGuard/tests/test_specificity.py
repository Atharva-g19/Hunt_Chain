from scopeguard.models.asset_type import AssetType
from scopeguard.engine.specificity import SpecificityCalculator


def test_hostname_specificity():
    calculator = SpecificityCalculator()

    specificity = calculator.calculate(
        AssetType.HOSTNAME,
        "example.com",
    )

    assert specificity == 100


def test_host_wildcard_specificity():
    calculator = SpecificityCalculator()

    specificity = calculator.calculate(
        AssetType.HOST_WILDCARD,
        "*.example.com",
    )

    assert specificity == 50


def test_exact_url_specificity():
    calculator = SpecificityCalculator()

    specificity = calculator.calculate(
        AssetType.URL,
        "https://example.com",
    )

    assert specificity == 100


def test_shallow_url_path_wildcard():
    calculator = SpecificityCalculator()

    specificity = calculator.calculate(
        AssetType.URL_PATH_WILDCARD,
        "https://example.com/api/*",
    )

    assert specificity == 51


def test_deeper_url_path_is_more_specific():
    calculator = SpecificityCalculator()

    shallow = calculator.calculate(
        AssetType.URL_PATH_WILDCARD,
        "https://example.com/api/*",
    )

    deep = calculator.calculate(
        AssetType.URL_PATH_WILDCARD,
        "https://example.com/api/v1/*",
    )

    assert deep > shallow


def test_deep_url_path_specificity():
    calculator = SpecificityCalculator()

    specificity = calculator.calculate(
        AssetType.URL_PATH_WILDCARD,
        "https://example.com/api/v1/users/*",
    )

    assert specificity == 53


def test_url_path_trailing_slash_does_not_change_depth():
    calculator = SpecificityCalculator()

    without_slash = calculator.calculate(
        AssetType.URL_PATH_WILDCARD,
        "https://example.com/api/*",
    )

    with_slash = calculator.calculate(
        AssetType.URL_PATH_WILDCARD,
        "https://example.com/api//*",
    )

    assert without_slash == 51
    assert with_slash == 51


def test_ipv4_specificity():
    calculator = SpecificityCalculator()

    specificity = calculator.calculate(
        AssetType.IPV4,
        "192.168.1.10",
    )

    assert specificity == 100


def test_ipv4_cidr_specificity():
    calculator = SpecificityCalculator()

    specificity = calculator.calculate(
        AssetType.IPV4_CIDR,
        "192.168.1.0/24",
    )

    assert specificity == 24


def test_narrower_cidr_is_more_specific():
    calculator = SpecificityCalculator()

    broad = calculator.calculate(
        AssetType.IPV4_CIDR,
        "192.168.1.0/24",
    )

    narrow = calculator.calculate(
        AssetType.IPV4_CIDR,
        "192.168.1.0/28",
    )

    assert narrow > broad


def test_ipv4_cidr_prefix_length_16():
    calculator = SpecificityCalculator()

    specificity = calculator.calculate(
        AssetType.IPV4_CIDR,
        "10.0.0.0/16",
    )

    assert specificity == 16


def test_ipv4_cidr_prefix_length_32():
    calculator = SpecificityCalculator()

    specificity = calculator.calculate(
        AssetType.IPV4_CIDR,
        "10.0.0.1/32",
    )

    assert specificity == 32


def test_unknown_asset_type_has_zero_specificity():
    calculator = SpecificityCalculator()

    specificity = calculator.calculate(
        "unknown",
        "example.com",
    )

    assert specificity == 0