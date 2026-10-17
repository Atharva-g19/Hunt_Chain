"""Unit tests for requirements (e) and (f): correlation, deduplication, and vulnerability chaining."""

from hunt_chain_reporting.correlation import correlate_and_deduplicate
from hunt_chain_reporting.models import ReportFinding


def test_fixture_e_deduplication_same_endpoint_parameter():
    """
    (e) Two findings from different sub-testers on the identical endpoint/parameter —
    assert they are merged into one entry listing both tester IDs, not duplicated.
    """
    f1 = ReportFinding(
        finding_id="XSS-01",
        title="Reflected XSS in /search?q=",
        vulnerability_family="xss",
        vulnerability_type="Cross-Site Scripting (XSS)",
        cwe_id="CWE-79",
        cwe_name="XSS",
        owasp_category="A03:2021",
        severity="MEDIUM",
        status="CONFIRMED",
        description="Reflected script tag in search field",
        target="example.com",
        endpoint="/search",
        parameter="q",
        evidence="<script>alert(1)</script>",
        contributing_tester_ids=["XSS-01"],
    )

    f2 = ReportFinding(
        finding_id="XSS-03",
        title="Attribute-based XSS in /search?q=",
        vulnerability_family="xss",
        vulnerability_type="Cross-Site Scripting (XSS)",
        cwe_id="CWE-79",
        cwe_name="XSS",
        owasp_category="A03:2021",
        severity="HIGH",
        status="CONFIRMED",
        description="Event handler onload injection in search field",
        target="example.com",
        endpoint="/search",
        parameter="q",
        evidence="\" autofocus onfocus=alert(1) x=\"",
        contributing_tester_ids=["XSS-03"],
    )

    merged = correlate_and_deduplicate([f1, f2])

    # Assert exactly 1 entry remains
    assert len(merged) == 1
    result = merged[0]

    # Assert both tester IDs are listed
    assert "XSS-01" in result.contributing_tester_ids
    assert "XSS-03" in result.contributing_tester_ids
    # Assert upgraded to highest severity (HIGH)
    assert result.severity == "HIGH"


def test_fixture_f_chain_linking_not_overmerged():
    """
    (f) An IDOR finding and a CSRF finding on the same endpoint —
    assert both remain separate entries but cross-reference each other as related,
    confirming correlation doesn't over-merge genuinely distinct findings.
    """
    f_idor = ReportFinding(
        finding_id="IDOR-01",
        title="IDOR in /api/v1/user/profile allows unauthorized tenant profile modification",
        vulnerability_family="idor_bola",
        vulnerability_type="Broken Object Level Authorization (IDOR)",
        cwe_id="CWE-639",
        cwe_name="IDOR",
        owasp_category="A01:2021",
        severity="HIGH",
        status="CONFIRMED",
        description="User ID manipulation allows updating other users profile",
        target="api.example.com",
        endpoint="/api/v1/user/profile",
        parameter="user_id",
        contributing_tester_ids=["IDOR-01"],
    )

    f_csrf = ReportFinding(
        finding_id="CSRF-01",
        title="CSRF in /api/v1/user/profile allows unauthenticated state changes",
        vulnerability_family="csrf",
        vulnerability_type="Cross-Site Request Forgery (CSRF)",
        cwe_id="CWE-352",
        cwe_name="CSRF",
        owasp_category="A01:2021",
        severity="MEDIUM",
        status="CONFIRMED",
        description="Endpoint lacks anti-CSRF token verification",
        target="api.example.com",
        endpoint="/api/v1/user/profile",
        parameter="",
        contributing_tester_ids=["CSRF-01"],
    )

    results = correlate_and_deduplicate([f_idor, f_csrf])

    # Assert BOTH remain distinct entries
    assert len(results) == 2

    idor_res = next(f for f in results if f.finding_id == "IDOR-01")
    csrf_res = next(f for f in results if f.finding_id == "CSRF-01")

    # Assert cross-references exist
    assert "CSRF-01" in idor_res.related_finding_ids
    assert "IDOR-01" in csrf_res.related_finding_ids
    assert any("IDOR + CSRF Chain" in note for note in idor_res.related_notes)
    assert any("IDOR + CSRF Chain" in note for note in csrf_res.related_notes)
