"""Unit test for requirement (h): verify CWE mapping table has an entry for all 22 families."""

from hunt_chain_reporting.cwe_mapping import FAMILY_REGISTRY, get_family_metadata

EXPECTED_22_FAMILIES = (
    "clickjacking",
    "open_redirect",
    "cors",
    "ssrf",
    "sql_injection",
    "xss",
    "idor_bola",
    "inventory_management",
    "bopla",
    "csrf",
    "authentication_bypass",
    "function_authorization",
    "business_logic",
    "ato",
    "security_misconfiguration",
    "rce",
    "path_traversal_upload",
    "sensitive_disclosure",
    "resource_consumption",
    "subdomain_takeover",
    "third_party_api",
    "xxe",
)


def test_fixture_h_all_22_families_mapped():
    """Verify structural completeness: every single one of the 22 families has a valid mapping."""
    assert len(FAMILY_REGISTRY) == 22, f"Expected exactly 22 families, found {len(FAMILY_REGISTRY)}"

    for family in EXPECTED_22_FAMILIES:
        assert family in FAMILY_REGISTRY, f"Family '{family}' is missing from FAMILY_REGISTRY"
        meta = FAMILY_REGISTRY[family]

        assert meta.cwe_id.startswith("CWE-"), f"Invalid CWE ID for {family}: {meta.cwe_id}"
        assert meta.cwe_name, f"Empty CWE name for {family}"
        assert meta.cwe_url.startswith("https://cwe.mitre.org/"), f"Invalid CWE URL for {family}: {meta.cwe_url}"
        assert meta.owasp_category, f"Missing OWASP category for {family}"
        assert meta.default_impact, f"Missing impact for {family}"
        assert len(meta.remediation) >= 1, f"Missing remediation guidance for {family}"


def test_alias_resolution():
    """Verify aliases like 'information_disclosure', 'sqli', 'bfla' resolve cleanly."""
    info_meta = get_family_metadata("information_disclosure")
    assert info_meta.family == "sensitive_disclosure"
    assert info_meta.cwe_id == "CWE-200"

    sqli_meta = get_family_metadata("sqli")
    assert sqli_meta.family == "sql_injection"
    assert sqli_meta.cwe_id == "CWE-89"
