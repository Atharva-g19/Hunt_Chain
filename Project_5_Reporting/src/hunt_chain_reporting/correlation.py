from __future__ import annotations

from typing import Any
from .models import ReportFinding, SeverityLevel


# Known vulnerability chaining relationships
CHAIN_PATTERNS: list[tuple[set[str], str]] = [
    (
        {"idor_bola", "csrf"},
        "IDOR + CSRF Chain: Combining CSRF with IDOR on this endpoint enables remote attackers to force victims into modifying or exfiltrating object records without victim awareness.",
    ),
    (
        {"ssrf", "sensitive_disclosure"},
        "SSRF + Information Disclosure Chain: SSRF reachability enables exfiltration of internal cloud metadata, instance tokens, or private microservice responses.",
    ),
    (
        {"sql_injection", "authentication_bypass"},
        "SQLi + Authentication Bypass Chain: SQL injection on this endpoint facilitates direct authentication circumvention and administrative session extraction.",
    ),
    (
        {"cors", "xss"},
        "CORS + XSS Chain: Permissive CORS policy amplifies XSS execution, allowing cross-origin credential harvesting and token exfiltration.",
    ),
    (
        {"open_redirect", "ssrf"},
        "Open Redirect + SSRF Filter Bypass Chain: Open redirection can be leveraged to bypass naive SSRF hostname allowlists via HTTP 302 chaining.",
    ),
    (
        {"bopla", "function_authorization"},
        "BOPLA + Privilege Escalation Chain: Mass assignment allows updating role attributes, escalating caller privileges across function endpoints.",
    ),
]


def _normalize_endpoint(ep: str) -> str:
    """Normalize endpoint path for correlation comparisons."""
    if not ep:
        return ""
    clean = ep.split("?")[0].rstrip("/")
    return clean.lower()


def correlate_and_deduplicate(findings: list[ReportFinding]) -> list[ReportFinding]:
    """
    Run deduplication and chain correlation across a list of findings.

    1. Merges sub-testers firing on the identical vulnerability family, endpoint, and parameter.
    2. Discovers vulnerability chains (e.g. IDOR + CSRF) and links them via cross-references.
    """
    if not findings:
        return []

    # Step 1: Deduplication by (family, normalized_endpoint, parameter)
    merged_map: dict[tuple[str, str, str], ReportFinding] = {}

    for finding in findings:
        key = (
            finding.vulnerability_family.lower().strip(),
            _normalize_endpoint(finding.endpoint),
            finding.parameter.lower().strip(),
        )

        if key not in merged_map:
            # Ensure contributing tester IDs contains finding's own ID/tester
            if not finding.contributing_tester_ids and finding.finding_id:
                finding.contributing_tester_ids = [finding.finding_id]
            merged_map[key] = finding
        else:
            existing = merged_map[key]
            # Merge tester IDs
            all_testers = list(existing.contributing_tester_ids)
            for tid in (finding.contributing_tester_ids or [finding.finding_id]):
                if tid and tid not in all_testers:
                    all_testers.append(tid)
            existing.contributing_tester_ids = all_testers

            # Take highest severity
            existing_sev = SeverityLevel.from_str(existing.severity)
            new_sev = SeverityLevel.from_str(finding.severity)
            if new_sev.rank < existing_sev.rank:
                existing.severity = finding.severity
                existing.cvss = finding.cvss or existing.cvss

            # Preserve the most comprehensive evidence and reproduction steps
            if len(finding.evidence) > len(existing.evidence):
                existing.evidence = finding.evidence
            if len(finding.steps_to_reproduce) > len(existing.steps_to_reproduce):
                existing.steps_to_reproduce = finding.steps_to_reproduce

    deduplicated = list(merged_map.values())

    # Step 2: Correlation and Chain Linking
    for i in range(len(deduplicated)):
        for j in range(i + 1, len(deduplicated)):
            f1 = deduplicated[i]
            f2 = deduplicated[j]

            # Check if they share the same endpoint or host
            same_endpoint = _normalize_endpoint(f1.endpoint) == _normalize_endpoint(f2.endpoint)
            same_target = f1.target.lower().strip() == f2.target.lower().strip()

            if same_endpoint or (same_target and f1.endpoint and f2.endpoint):
                pair_families = {
                    f1.vulnerability_family.lower().strip(),
                    f2.vulnerability_family.lower().strip(),
                }

                for chain_families, note in CHAIN_PATTERNS:
                    if pair_families == chain_families:
                        # Link f1 -> f2
                        if f2.finding_id not in f1.related_finding_ids:
                            f1.related_finding_ids.append(f2.finding_id)
                            f1.related_notes.append(f"{note} (Related: {f2.finding_id})")

                        # Link f2 -> f1
                        if f1.finding_id not in f2.related_finding_ids:
                            f2.related_finding_ids.append(f1.finding_id)
                            f2.related_notes.append(f"{note} (Related: {f1.finding_id})")

    return deduplicated
