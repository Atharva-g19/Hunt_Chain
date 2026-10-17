"""End-to-end report generation test against the PortSwigger Web Security Academy regression matrix."""

import json
from pathlib import Path

from hunt_chain_reporting.generator import generate_report
from hunt_chain_reporting.markdown_renderer import render_markdown_report
from hunt_chain_reporting.writer import write_report_artifacts

PORT_SWIGGER_MATRIX = (
    Path(__file__).resolve().parents[3]
    / "tests"
    / "fixtures"
    / "portswigger_regression_matrix.json"
)


def test_portswigger_matrix_full_report_generation(tmp_path: Path):
    assert PORT_SWIGGER_MATRIX.is_file(), "PortSwigger matrix fixture file missing"

    with open(PORT_SWIGGER_MATRIX, "r", encoding="utf-8") as f:
        labs = json.load(f)

    # 1. Mock ScopeGuard authorization for PortSwigger Academy target
    auth_data = {
        "schema_version": "v1",
        "state": "IN_SCOPE",
        "rule_id": "PORTSWIGGER-ACADEMY-RULE",
        "target": "https://portswigger.net/web-security",
        "timestamp": "2026-10-17T09:00:00Z",
    }

    # 2. Mock Project 2 attack surface
    recon_data = {
        "host": "portswigger.net",
        "endpoints": [lab["endpoint"] for lab in labs],
        "technologies": ["Java", "Apache", "Spring", "Nginx"],
    }

    # 3. Build Project 3 findings and Project 4 validations from matrix
    p3_findings = []
    p4_validations = []

    for lab in labs:
        ep = lab["endpoint"]
        p3_status = lab.get("expected_p3_status", "POTENTIAL")
        p4_decision = lab.get("expected_p4_decision", "NOT_CONFIRMED")
        family = lab.get("vulnerability_family", "security_misconfiguration")

        p3_findings.append({
            "test_id": lab["lab_id"],
            "family": family,
            "status": p3_status,
            "severity": "HIGH" if p4_decision == "CONFIRMED" else "MEDIUM",
            "endpoint": ep.get("path", "/"),
            "method": ep.get("method", "GET"),
            "parameter": list(ep.get("parameters", {}).keys())[0] if ep.get("parameters") else "",
            "description": lab.get("description", ""),
            "evidence": f"Simulated detection trace on {ep.get('path')}",
            "suggested_manual_steps": [
                f"Send crafted {ep.get('method', 'GET')} request to {ep.get('path')}",
                "Inspect response headers and session state",
            ],
        })

        if p3_status != "MANUAL_ONLY":
            p4_validations.append({
                "result_id": lab["lab_id"],
                "status": p4_decision,
                "proof": f"PortSwigger lab differential proof token for {lab['lab_id']}",
            })

    vuln_data = {"findings": p3_findings, "total_requests": len(labs) * 3}
    val_data = {"validations": p4_validations}

    # 4. Generate Report
    md_file, json_file, report = write_report_artifacts(
        output_directory=tmp_path,
        authorization_data=auth_data,
        attack_surface_data=recon_data,
        vulnerability_data=vuln_data,
        validation_data=val_data,
    )

    assert md_file.is_file()
    assert json_file.is_file()

    # Verify Report structure & readability
    md_content = md_file.read_text(encoding="utf-8")
    assert "# Security Assessment & Vulnerability Report — https://portswigger.net/web-security" in md_content
    assert "## 1. Executive Summary" in md_content
    assert "## 2. Confirmed Findings" in md_content
    assert "## 3. Candidates for Manual Review (Not Confirmed)" in md_content
    assert "## 4. Manual-Only Checklist (Not Automatically Tested)" in md_content
    assert "## 5. Scope & Methodology Appendix" in md_content

    # Assert executive summary counts
    assert report.executive_summary.confirmed_count > 0
    assert report.executive_summary.total_findings == len(report.confirmed_findings) + len(report.candidates_for_review) + len(report.manual_checklist)

    # Verify JSON structure
    with open(json_file, "r", encoding="utf-8") as f:
        parsed_json = json.load(f)
    assert parsed_json["report_schema_version"] == "v1.0"
    assert len(parsed_json["confirmed_findings"]) == report.executive_summary.confirmed_count
