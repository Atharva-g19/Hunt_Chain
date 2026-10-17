"""Unit test for requirement (b): secret redaction and fail-loud safety net."""

from pathlib import Path
import pytest

from hunt_chain_reporting.redaction_guard import (
    UnredactedSecretViolationError,
    assert_no_unredacted_secrets,
    redact_text,
    scan_for_unredacted_secrets,
)
from hunt_chain_reporting.writer import write_report_artifacts


def test_fixture_b_redaction_and_both_files_redacted(tmp_path: Path):
    """
    (b) A finding containing a secret-shaped evidence value —
    assert BOTH output files contain only the redacted form.
    """
    raw_secret = "sk_live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz123456"
    
    auth_data = {
        "state": "IN_SCOPE",
        "rule_id": "RULE-PROD-01",
        "target": "api.example.com",
    }
    
    vuln_data = {
        "findings": [
            {
                "test_id": "INFO-01",
                "family": "sensitive_disclosure",
                "status": "CONFIRMED",
                "severity": "HIGH",
                "endpoint": "/api/config.js",
                "evidence": f"Found Stripe key: {raw_secret} in bundle",
                "description": f"Exposed secret key {raw_secret}",
            }
        ]
    }

    md_file, json_file, report_data = write_report_artifacts(
        output_directory=tmp_path,
        authorization_data=auth_data,
        vulnerability_data=vuln_data,
    )

    md_text = md_file.read_text(encoding="utf-8")
    json_text = json_file.read_text(encoding="utf-8")

    # Assert raw secret is NEVER in either file
    assert raw_secret not in md_text
    assert raw_secret not in json_text

    # Assert redacted representation IS present
    assert "sk_live_51Ab********3456" in md_text
    assert "sk_live_51Ab********3456" in json_text


def test_fixture_b_fail_loud_safety_net():
    """
    (b) Assert the fail-loud safety-net check actually triggers if a test deliberately
    feeds an unredacted value past the normal redaction path.
    """
    raw_secret = "sk_live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz123456"
    unredacted_content = f"# Report\nSensitive key leaked: {raw_secret}\n"

    # Assert scanner catches it
    violations = scan_for_unredacted_secrets(unredacted_content)
    assert "Stripe Live Secret Key" in violations

    # Assert safety gate FAILS LOUDLY
    with pytest.raises(UnredactedSecretViolationError, match="Safety check failed: detected unredacted sensitive data"):
        assert_no_unredacted_secrets(unredacted_content, "test_report.md")


def test_fail_loud_for_aws_and_github_tokens():
    aws_key = "AKIA" + "1234567890ABCDEF"
    text = f"AWS key: {aws_key}"
    with pytest.raises(UnredactedSecretViolationError):
        assert_no_unredacted_secrets(text)

    gh_token = "ghp_" + "123456789012345678901234567890123456"
    text_gh = f"GitHub token: {gh_token}"
    with pytest.raises(UnredactedSecretViolationError):
        assert_no_unredacted_secrets(text_gh)
