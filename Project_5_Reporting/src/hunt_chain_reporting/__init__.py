from __future__ import annotations

from .cwe_mapping import FAMILY_REGISTRY, FamilyMetadata, get_family_metadata
from .cvss import calculate_cvss_31, derive_cvss
from .correlation import correlate_and_deduplicate
from .generator import AuthorizationGateError, generate_report
from .markdown_renderer import render_markdown_report
from .json_renderer import render_json_report
from .models import (
    CVSSData,
    ExecutiveSummary,
    FindingStatus,
    ManualChecklistItem,
    ReportData,
    ReportFinding,
    ScopeMethodology,
    SeverityLevel,
)
from .redaction_guard import (
    UnredactedSecretViolationError,
    assert_no_unredacted_secrets,
    redact_string,
    redact_text,
    scan_for_unredacted_secrets,
)
from .writer import write_report_artifacts

__all__ = [
    "FAMILY_REGISTRY",
    "FamilyMetadata",
    "get_family_metadata",
    "calculate_cvss_31",
    "derive_cvss",
    "correlate_and_deduplicate",
    "AuthorizationGateError",
    "generate_report",
    "render_markdown_report",
    "render_json_report",
    "CVSSData",
    "ExecutiveSummary",
    "FindingStatus",
    "ManualChecklistItem",
    "ReportData",
    "ReportFinding",
    "ScopeMethodology",
    "SeverityLevel",
    "UnredactedSecretViolationError",
    "assert_no_unredacted_secrets",
    "redact_string",
    "redact_text",
    "scan_for_unredacted_secrets",
    "write_report_artifacts",
]
