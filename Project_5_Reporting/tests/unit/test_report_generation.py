"""Unit tests for requirements (a), (c), and (d): report structure, sorting, and section segmentation."""

import json
from pathlib import Path

from hunt_chain_reporting.generator import generate_report
from hunt_chain_reporting.markdown_renderer import render_markdown_report
from hunt_chain_reporting.writer import write_report_artifacts


def test_fixture_a_mixed_severity_sorting_and_counts(tmp_path: Path):
    """
    (a) A set of mixed-severity confirmed findings renders with correct sort order
    (Critical first) and correct severity-count totals in the Executive Summary.
    """
    auth_data = {
        "state": "IN_SCOPE",
        "rule_id": "RULE-001",
        "target": "target.app.com",
    }

    vuln_data = {
        "findings": [
            {
                "test_id": "LOW-01",
                "family": "clickjacking",
                "status": "CONFIRMED",
                "severity": "LOW",
                "endpoint": "/home",
            },
            {
                "test_id": "CRIT-01",
                "family": "rce",
                "status": "CONFIRMED",
                "severity": "CRITICAL",
                "endpoint": "/admin/exec",
            },
            {
                "test_id": "MED-01",
                "family": "csrf",
                "status": "CONFIRMED",
                "severity": "MEDIUM",
                "endpoint": "/profile/update",
            },
            {
                "test_id": "HIGH-01",
                "family": "sql_injection",
                "status": "CONFIRMED",
                "severity": "HIGH",
                "endpoint": "/api/items",
            },
        ]
    }

    report = generate_report(auth_data, vulnerability_data=vuln_data)

    # Assert severity counts in executive summary
    counts = report.executive_summary.severity_counts
    assert counts["CRITICAL"] == 1
    assert counts["HIGH"] == 1
    assert counts["MEDIUM"] == 1
    assert counts["LOW"] == 1
    assert report.executive_summary.confirmed_count == 4

    # Assert sort order: Critical -> High -> Medium -> Low
    severities = [f.severity.upper() for f in report.confirmed_findings]
    assert severities == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    # Assert Markdown rendering maintains exact order
    md_text = render_markdown_report(report)
    idx_crit = md_text.find("[CRITICAL]")
    idx_high = md_text.find("[HIGH]")
    idx_med = md_text.find("[MEDIUM]")
    idx_low = md_text.find("[LOW]")

    assert -1 < idx_crit < idx_high < idx_med < idx_low


def test_fixture_c_not_confirmed_only_in_section_3(tmp_path: Path):
    """
    (c) A Not Confirmed finding — assert it appears ONLY in Section 3, never Section 2,
    and has no severity/CVSS/remediation fields populated.
    """
    auth_data = {
        "state": "IN_SCOPE",
        "rule_id": "RULE-001",
        "target": "target.app.com",
    }

    vuln_data = {
        "findings": [
            {
                "test_id": "POTENTIAL-01",
                "family": "ssrf",
                "status": "POTENTIAL",
                "severity": "HIGH",
                "endpoint": "/fetch/url",
                "evidence": "Anomalous response time observed",
                "suggested_manual_steps": ["Check internal network DNS resolutions"],
            }
        ]
    }

    # Project 4 rejects or fails to confirm
    val_data = {
        "validations": [
            {
                "result_id": "POTENTIAL-01",
                "status": "NOT_CONFIRMED",
                "proof": "No internal connection received",
            }
        ]
    }

    report = generate_report(auth_data, vulnerability_data=vuln_data, validation_data=val_data)

    # Assert confirmed list is empty
    assert len(report.confirmed_findings) == 0

    # Assert appears in candidates_for_review
    assert len(report.candidates_for_review) == 1
    candidate = report.candidates_for_review[0]

    # Assert no severity, CVSS, or remediation fields populated
    assert candidate.severity == ""
    assert candidate.cvss is None
    assert candidate.suggested_remediation == []

    # Assert Markdown structure
    md_text = render_markdown_report(report)
    assert "## 2. Confirmed Findings" in md_text
    assert "*No confirmed vulnerabilities were identified during this assessment.*" in md_text
    assert "## 3. Candidates for Manual Review (Not Confirmed)" in md_text
    assert "[UNCONFIRMED]" in md_text
    assert "POTENTIAL-01" in candidate.finding_id or "fetch/url" in candidate.endpoint


def test_fixture_d_manual_only_checklist_in_section_4():
    """
    (d) A manual-only stub tester's output — assert it appears only as a checklist item
    in Section 4, formatted as an actionable line, not as a finding.
    """
    auth_data = {
        "state": "IN_SCOPE",
        "rule_id": "RULE-001",
        "target": "target.app.com",
    }

    vuln_data = {
        "findings": [
            {
                "test_id": "LOGIC-01",
                "family": "business_logic",
                "status": "MANUAL_ONLY",
                "endpoint": "/cart/checkout",
                "suggested_manual_steps": [
                    "Test coupon code reuse across multiple sessions",
                    "Attempt negative quantity input on line items",
                ],
            }
        ]
    }

    report = generate_report(auth_data, vulnerability_data=vuln_data)

    # Not in confirmed or candidates
    assert len(report.confirmed_findings) == 0
    assert len(report.candidates_for_review) == 0

    # Present in manual checklist
    assert len(report.manual_checklist) == 1
    item = report.manual_checklist[0]
    assert item.test_id == "LOGIC-01"
    assert "coupon code reuse" in item.action_items[0]

    # Markdown rendering has checklist format
    md_text = render_markdown_report(report)
    assert "## 4. Manual-Only Checklist (Not Automatically Tested)" in md_text
    assert "- [ ] Test coupon code reuse across multiple sessions" in md_text
    assert "- [ ] Attempt negative quantity input on line items" in md_text


def test_end_to_end_writer_dual_output(tmp_path: Path):
    auth_data = {"state": "IN_SCOPE", "rule_id": "R1", "target": "demo.com"}
    vuln_data = {
        "findings": [
            {
                "test_id": "SQLI-01",
                "family": "sql_injection",
                "status": "CONFIRMED",
                "severity": "CRITICAL",
                "endpoint": "/api/users",
                "parameter": "id",
                "evidence": "syntax error near SELECT *",
            }
        ]
    }

    md_path, json_path, data = write_report_artifacts(
        output_directory=tmp_path,
        authorization_data=auth_data,
        vulnerability_data=vuln_data,
    )

    assert md_path.is_file()
    assert json_path.is_file()

    # Assert JSON parses cleanly and contains all keys
    with json_path.open("r", encoding="utf-8") as f:
        parsed = json.load(f)
    assert parsed["report_schema_version"] == "v1.0"
    assert len(parsed["confirmed_findings"]) == 1
    assert parsed["confirmed_findings"][0]["severity"] == "CRITICAL"
    assert parsed["confirmed_findings"][0]["cwe_id"] == "CWE-89"


def test_dict_technologies_and_endpoints_render_cleanly(tmp_path: Path):
    auth_data = {"state": "IN_SCOPE", "rule_id": "R1", "target": "demo.com"}
    recon_data = {
        "technologies": [
            {"id": "t1", "name": "Nginx", "category": "web-server", "version": "1.18.0"},
            {"id": "t2", "name": "Python", "category": "runtime", "version": "3.11"},
        ],
        "endpoints": [{"url": "https://demo.com/api"}],
    }
    vuln_data = {
        "findings": [
            {
                "result_id": "res-101",
                "test_id": "XSS-01",
                "family": "xss",
                "status": "POTENTIAL",
                "severity": "HIGH",
                "endpoint": {"url": "https://demo.com/search", "method": "GET"},
                "evidence": "<script>alert(1)</script>",
            }
        ]
    }
    val_data = {
        "results": [
            {
                "result_id": "res-101:validation",
                "finding_id": "res-101",
                "decision": "CONFIRMED",
                "proof": "Executed alert(1) payload",
            }
        ]
    }

    md_path, json_path, report = write_report_artifacts(
        output_directory=tmp_path,
        authorization_data=auth_data,
        attack_surface_data=recon_data,
        vulnerability_data=vuln_data,
        validation_data=val_data,
    )

    assert md_path.is_file()
    assert json_path.is_file()

    md_content = md_path.read_text(encoding="utf-8")
    assert "Nginx (1.18.0), Python (3.11)" in md_content
    assert "https://demo.com/search" in md_content
    # Verified that Project 4 confirmed status was picked up from finding_id
    assert report.executive_summary.confirmed_count == 1

