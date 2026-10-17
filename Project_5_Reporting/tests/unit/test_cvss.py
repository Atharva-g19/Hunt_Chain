"""Unit tests for CVSS 3.1 calculation and derivation."""

from hunt_chain_reporting.cvss import calculate_cvss_31, derive_cvss, score_to_rating


def test_cvss_31_calculation_known_vectors():
    # Standard critical RCE: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H -> 9.8
    score, vector = calculate_cvss_31(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")
    assert score == 9.8
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in vector
    assert score_to_rating(score) == "Critical"

    # Standard Reflected XSS: AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N -> 6.1
    score_xss, _ = calculate_cvss_31(av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N")
    assert score_xss == 6.1
    assert score_to_rating(score_xss) == "Medium"


def test_derive_cvss_for_known_families():
    # SQLi Critical
    data, note = derive_cvss("sql_injection", "CRITICAL")
    assert data is not None
    assert data.base_score >= 9.0
    assert "CVSS:3.1" in data.vector_string

    # Unreliable / unknown family returns None + explicit note
    unknown_data, note = derive_cvss("unknown_experimental_family", "MEDIUM")
    assert unknown_data is None
    assert "CVSS not calculated for this finding type" in note
