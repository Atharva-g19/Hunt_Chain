"""Integration test for Project 5 execution within Hunt_Chain assessment workflow."""

import json
from pathlib import Path
import pytest

from hunt_chain_core import AssessmentManager
from hunt_chain_core.project_5_execution import run_project_5
from hunt_chain_core.project_integration import register_project_1, register_project_4
from hunt_chain_core.project_3_runner import register_project_3
from hunt_chain_core.workflow import AssessmentWorkflow


def test_project_5_workflow_end_to_end(tmp_path: Path):
    runs_dir = tmp_path / "Runs"
    manager = AssessmentManager(runs_dir)
    assessment_name = "TargetCorp_Pentest"
    assessment_dir = manager.create(assessment_name)

    # 1. Register Project 1 (ScopeGuard) authorized result
    p1_data = {
        "schema_version": "v1",
        "state": "IN_SCOPE",
        "rule_id": "SCOPE-RULE-001",
        "target": "https://api.targetcorp.com",
        "timestamp": "2026-10-17T10:00:00Z",
    }
    p1_file = tmp_path / "p1.json"
    p1_file.write_text(json.dumps(p1_data), encoding="utf-8")
    register_project_1(assessment_name, p1_file, runs_dir)

    # 2. Write Project 2 attack surface
    p2_data = {
        "host": "api.targetcorp.com",
        "endpoints": [{"url": "https://api.targetcorp.com/users", "method": "GET"}],
        "technologies": ["Express", "Node.js"],
    }
    (assessment_dir / "attack_surface.json").write_text(json.dumps(p2_data), encoding="utf-8")

    # 3. Write Project 3 findings
    p3_data = {
        "findings": [
            {
                "test_id": "IDOR-01",
                "family": "idor_bola",
                "status": "CONFIRMED",
                "severity": "HIGH",
                "endpoint": "/users/100",
                "evidence": "User 100 invoice retrieved by caller 200",
            },
            {
                "test_id": "SSRF-01",
                "family": "ssrf",
                "status": "POTENTIAL",
                "severity": "CRITICAL",
                "endpoint": "/proxy?url=",
                "evidence": "Timing differential observed",
            },
            {
                "test_id": "LOGIC-01",
                "family": "business_logic",
                "status": "MANUAL_ONLY",
                "endpoint": "/checkout",
                "suggested_manual_steps": ["Verify negative quantity handling"],
            },
        ]
    }
    p3_file = tmp_path / "p3.json"
    p3_file.write_text(json.dumps(p3_data), encoding="utf-8")
    register_project_3(assessment_name, p3_file, runs_dir)

    # 4. Write Project 4 validation
    p4_data = {
        "validations": [
            {
                "result_id": "IDOR-01",
                "status": "CONFIRMED",
                "proof": "Differential tenant record access confirmed",
            },
            {
                "result_id": "SSRF-01",
                "status": "NOT_CONFIRMED",
                "proof": "Egress connection rejected by boundary firewall",
            },
        ]
    }
    p4_file = tmp_path / "p4.json"
    p4_file.write_text(json.dumps(p4_data), encoding="utf-8")
    register_project_4(assessment_name, p4_file, runs_dir)

    # 5. Run Project 5 Reporting
    md_path, json_path, report_data = run_project_5(
        assessment_name=assessment_name,
        runs_directory=runs_dir,
    )

    assert md_path.is_file()
    assert json_path.is_file()

    # Check that report.json is registered in manifest
    manifest = manager.manifest(assessment_name)
    assert "project_5" in manifest["projects"]

    # Verify report contents
    assert report_data.executive_summary.confirmed_count == 1
    assert report_data.executive_summary.not_confirmed_count == 1
    assert report_data.executive_summary.manual_only_count == 1

    md_text = md_path.read_text(encoding="utf-8")
    assert "## 1. Executive Summary" in md_text
    assert "## 2. Confirmed Findings" in md_text
    assert "## 3. Candidates for Manual Review (Not Confirmed)" in md_text
    assert "## 4. Manual-Only Checklist (Not Automatically Tested)" in md_text
    assert "## 5. Scope & Methodology Appendix" in md_text
    assert "SCOPE-RULE-001" in md_text
