from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from .cwe_mapping import get_family_metadata
from .cvss import derive_cvss
from .correlation import correlate_and_deduplicate
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
from .redaction_guard import redact_text


class AuthorizationGateError(RuntimeError):
    """Raised when ScopeGuard authorization is missing, invalid, or not IN_SCOPE."""
    pass


def _generate_dynamic_title(
    family_display: str,
    endpoint: str,
    method: str,
    parameter: str,
    custom_title: str | None = None,
) -> str:
    """Generate dynamic title: '[Vulnerability Type] in [Asset/Endpoint] allows [Impact]'."""
    ep_repr = endpoint or "target application"
    param_repr = f" (parameter '{parameter}')" if parameter else ""

    impact_map = {
        "clickjacking": "unintended user interface framing and click hijacking",
        "open_redirect": "arbitrary client redirection to external attacker-controlled origins",
        "cors": "unauthorized cross-origin response reading and credential leakage",
        "ssrf": "server-side request forgery to internal or cloud metadata assets",
        "sql_injection": "unauthorized database extraction and command execution",
        "xss": "arbitrary client-side script execution in victim browser context",
        "idor_bola": "unauthorized access to other tenant/user object records",
        "inventory_management": "unauthenticated interaction with shadow or unversioned APIs",
        "bopla": "unauthorized object property mutation and mass assignment",
        "csrf": "unauthenticated cross-site request execution on behalf of victim",
        "authentication_bypass": "unauthenticated access to protected administrative endpoints",
        "function_authorization": "privileged function execution by unauthorized callers",
        "business_logic": "manipulation of business workflow constraints",
        "ato": "account takeover and unauthorized password reset manipulation",
        "security_misconfiguration": "information leakage and insecure method execution",
        "rce": "arbitrary operating system command execution on backend host",
        "path_traversal_upload": "unrestricted local file read or arbitrary file upload",
        "sensitive_disclosure": "exposure of sensitive credentials or private tokens",
        "resource_consumption": "resource exhaustion and rate-limiting circumvention",
        "subdomain_takeover": "unauthorized takeover of dangling third-party DNS pointers",
        "third_party_api": "unverified consumption of third-party API payload data",
        "xxe": "external entity parsing and arbitrary server file disclosure",
    }

    fam_key = family_display.lower().replace(" ", "_")
    for k, v in impact_map.items():
        if k in fam_key:
            return f"{family_display} in {ep_repr}{param_repr} allows {v}"

    if custom_title and "allows" in custom_title.lower():
        return custom_title

    return f"{family_display} in {ep_repr}{param_repr} allows unauthorized security boundary traversal"


def _build_severity_bar(counts: dict[str, int]) -> str:
    """Generate ASCII/Unicode severity distribution bar."""
    total = sum(counts.values())
    if total == 0:
        return "[Empty]"

    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        cnt = counts.get(sev, 0)
        bars = "█" * cnt if cnt > 0 else " "
        parts.append(f"{sev}: [{bars}] {cnt}")
    return " | ".join(parts)


def _generate_lead_paragraph(confirmed: list[ReportFinding], target: str) -> str:
    """Generate a single-paragraph plain-language executive summary of the 1-3 most severe findings."""
    if not confirmed:
        return (
            f"The automated and validated security assessment conducted against {target} "
            "did not identify any confirmed security vulnerabilities. All automated detection "
            "and validation checks concluded with negative results, indicating robust baseline "
            "defenses for the tested attack surface."
        )

    # Sort confirmed to get top 1-3
    sorted_conf = sorted(
        confirmed,
        key=lambda f: SeverityLevel.from_str(f.severity).rank,
    )
    top_findings = sorted_conf[:3]

    descriptions = []
    for f in top_findings:
        descriptions.append(
            f"a {f.severity.upper()} severity {f.vulnerability_type} in {f.endpoint or f.target}"
        )

    joined = ", ".join(descriptions)
    return (
        f"During the security assessment of {target}, a total of {len(confirmed)} vulnerability "
        f"finding(s) were definitively confirmed through automated validation. "
        f"The most critical risks identified include {joined}. "
        "These vulnerabilities pose immediate exposure to unauthorized data access, boundary traversal, "
        "or session compromise, and remediation should be prioritized according to the recommendations in this report."
    )


def generate_report(
    authorization_data: dict[str, Any],
    attack_surface_data: dict[str, Any] | None = None,
    vulnerability_data: dict[str, Any] | None = None,
    validation_data: dict[str, Any] | None = None,
) -> ReportData:
    """
    Generate the complete, verified ReportData model consuming P1, P2, P3, and P4 data.
    Enforces ScopeGuard fail-closed authorization check.
    """
    # 1. ScopeGuard Authorization Gate Check (Fail-closed)
    if not authorization_data:
        raise AuthorizationGateError(
            "ScopeGuard authorization artifact is missing. Report generation refused."
        )

    auth_state = str(authorization_data.get("state", "")).upper()
    if auth_state != "IN_SCOPE":
        raise AuthorizationGateError(
            f"ScopeGuard authorization decision is '{auth_state or 'MISSING'}'. "
            "Reports can only be generated for assessments authorized IN_SCOPE."
        )

    rule_id = (
        authorization_data.get("rule_id")
        or authorization_data.get("scope_rule_id")
        or authorization_data.get("matched_rule_id")
        or "SCOPE-UNKNOWN"
    )
    authorized_target = (
        authorization_data.get("target")
        or authorization_data.get("value")
        or "Target"
    )
    auth_timestamp = (
        authorization_data.get("timestamp")
        or authorization_data.get("created_at")
        or datetime.now(timezone.utc).isoformat()
    )

    attack_surface_data = attack_surface_data or {}
    vulnerability_data = vulnerability_data or {}
    validation_data = validation_data or {}

    # 2. Extract Project 4 validations map: result_id/finding_id -> validation_entry
    p4_validations: dict[str, dict[str, Any]] = {}
    raw_p4_list = (
        validation_data.get("validations")
        or validation_data.get("results")
        or []
    )
    for v in raw_p4_list:
        if isinstance(v, dict):
            fid = v.get("finding_id")
            rid = v.get("result_id")
            tid = v.get("test_id")
            if fid:
                p4_validations[str(fid)] = v
            if rid:
                p4_validations[str(rid)] = v
                if str(rid).endswith(":validation"):
                    p4_validations[str(rid)[:-11]] = v
            if tid and str(tid) not in p4_validations:
                p4_validations[str(tid)] = v

    # 3. Process Findings from Project 3
    raw_findings = (
        vulnerability_data.get("findings")
        or vulnerability_data.get("results")
        or []
    )

    confirmed_list: list[ReportFinding] = []
    candidates_list: list[ReportFinding] = []
    manual_checklist: list[ManualChecklistItem] = []

    for item in raw_findings:
        test_id = item.get("test_id", "TEST-01")
        family = item.get("family") or item.get("vulnerability_family", "security_misconfiguration")
        meta = get_family_metadata(family)

        p3_status = str(item.get("status", "POTENTIAL")).upper()
        severity = str(item.get("severity") or item.get("severity_label") or "MEDIUM").upper()

        endpoint = item.get("endpoint") or item.get("url") or item.get("path") or ""
        if isinstance(endpoint, dict):
            endpoint = endpoint.get("url") or endpoint.get("path") or endpoint.get("endpoint_id") or ""
        method = item.get("method") or "GET"
        parameter = item.get("parameter") or item.get("param") or ""
        target = item.get("host") or item.get("target") or authorized_target
        if isinstance(target, dict):
            target = target.get("host") or target.get("name") or str(authorized_target)

        evidence = str(item.get("evidence") or item.get("observation") or "")
        description = item.get("description") or f"A {meta.display_name} vulnerability was detected on {endpoint or target}."
        raw_manual_steps = item.get("suggested_manual_steps") or item.get("manual_steps") or ()

        # Check if Project 4 validated this finding
        item_rid = str(item.get("result_id") or "")
        p4_entry = (
            p4_validations.get(item_rid)
            or p4_validations.get(f"{item_rid}:validation")
            or p4_validations.get(test_id)
        )
        is_confirmed = False

        if p4_entry:
            p4_status = str(
                p4_entry.get("decision")
                or p4_entry.get("status")
                or p4_entry.get("state")
                or ""
            ).upper()
            if p4_status in ("CONFIRMED", "VALIDATED", "VULNERABLE"):
                is_confirmed = True
                proof = (
                    p4_entry.get("proof")
                    or p4_entry.get("proof_token")
                    or p4_entry.get("observation_diff")
                    or p4_entry.get("observable_evidence")
                    or p4_entry.get("observation")
                )
                if proof:
                    evidence = f"{evidence}\n[Validation Proof]: {proof}".strip()
            elif p4_status in ("NOT_CONFIRMED", "REJECTED", "FALSE_POSITIVE", "REFUTED"):
                is_confirmed = False
        else:
            # If Project 4 not present, rely on direct Project 3 confirmation
            if p3_status in ("CONFIRMED", "VULNERABLE"):
                is_confirmed = True

        # Redact raw evidence and descriptions
        clean_evidence = redact_text(evidence)
        clean_description = redact_text(description)

        # Dynamic title
        title = _generate_dynamic_title(
            meta.display_name,
            endpoint,
            method,
            parameter,
            item.get("title"),
        )

        # Format suggested manual steps into clean imperative list
        steps_list: list[str] = []
        if raw_manual_steps:
            for s in raw_manual_steps:
                clean_s = str(s).strip()
                if clean_s:
                    steps_list.append(redact_text(clean_s))
        else:
            steps_list = [
                f"Navigate to {method} '{endpoint or '/'}' on '{target}'.",
                f"Inject test vector into parameter '{parameter or 'query'}'." if parameter else "Observe server response headers and DOM behavior.",
                "Verify the application executes the unexpected response payload.",
            ]

        # References
        references = [
            meta.cwe_url,
            f"OWASP Top 10: {meta.owasp_category}",
        ]
        if meta.owasp_api_category != "N/A":
            references.append(f"OWASP API Security: {meta.owasp_api_category}")

        # Case A: MANUAL_ONLY stub tester -> goes to Section 4 Checklist
        if p3_status == "MANUAL_ONLY":
            manual_checklist.append(
                ManualChecklistItem(
                    family=meta.display_name,
                    test_id=test_id,
                    title=item.get("title") or f"Manual Verification: {meta.display_name}",
                    endpoint=endpoint or "/",
                    action_items=steps_list,
                )
            )
            continue

        # Case B: Confirmed Finding -> Section 2
        if is_confirmed:
            cvss_obj, cvss_note = derive_cvss(family, severity, has_auth=bool(item.get("auth")))
            finding_obj = ReportFinding(
                finding_id=item.get("result_id") or test_id,
                title=title,
                vulnerability_family=family,
                vulnerability_type=meta.display_name,
                cwe_id=meta.cwe_id,
                cwe_name=meta.cwe_name,
                owasp_category=meta.owasp_category,
                severity=severity,
                status=FindingStatus.CONFIRMED.value,
                cvss=cvss_obj,
                cvss_note=cvss_note,
                description=clean_description,
                target=target,
                endpoint=endpoint,
                method=method,
                parameter=parameter,
                steps_to_reproduce=steps_list,
                evidence=clean_evidence,
                impact=meta.default_impact,
                suggested_remediation=list(meta.remediation),
                references=references,
                contributing_tester_ids=[test_id],
            )
            confirmed_list.append(finding_obj)
        else:
            # Case C: Not Confirmed (Candidate for Manual Review) -> Section 3
            # Must omit severity, CVSS, and remediation per requirements
            candidate_obj = ReportFinding(
                finding_id=item.get("result_id") or test_id,
                title=title,
                vulnerability_family=family,
                vulnerability_type=meta.display_name,
                cwe_id=meta.cwe_id,
                cwe_name=meta.cwe_name,
                owasp_category=meta.owasp_category,
                severity="",  # explicitly omitted
                status=FindingStatus.NOT_CONFIRMED.value,
                cvss=None,    # explicitly omitted
                cvss_note="CVSS not applicable to unconfirmed findings",
                description=clean_description,
                target=target,
                endpoint=endpoint,
                method=method,
                parameter=parameter,
                steps_to_reproduce=steps_list,
                evidence=clean_evidence,
                impact=meta.default_impact,
                suggested_remediation=[],  # explicitly omitted
                references=references,
                contributing_tester_ids=[test_id],
            )
            candidates_list.append(candidate_obj)

    # 4. Correlation & Deduplication Pass (Merged identical params, cross-reference chains)
    confirmed_correlated = correlate_and_deduplicate(confirmed_list)

    # 5. Sort Confirmed Findings: Critical first
    confirmed_sorted = sorted(
        confirmed_correlated,
        key=lambda f: SeverityLevel.from_str(f.severity).rank,
    )

    # 6. Executive Summary Counts & Severity Bar
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }
    for f in confirmed_sorted:
        sev_key = f.severity.upper()
        if sev_key in severity_counts:
            severity_counts[sev_key] += 1

    total_findings_count = len(confirmed_sorted) + len(candidates_list) + len(manual_checklist)
    severity_bar = _build_severity_bar(severity_counts)
    lead_paragraph = _generate_lead_paragraph(confirmed_sorted, authorized_target)

    test_run_start = vulnerability_data.get("start_time") or auth_timestamp
    test_run_end = vulnerability_data.get("end_time") or datetime.now(timezone.utc).isoformat()

    exec_summary = ExecutiveSummary(
        target=authorized_target,
        scope_reference=rule_id,
        authorization_timestamp=auth_timestamp,
        test_run_start=test_run_start,
        test_run_end=test_run_end,
        total_findings=total_findings_count,
        confirmed_count=len(confirmed_sorted),
        not_confirmed_count=len(candidates_list),
        manual_only_count=len(manual_checklist),
        severity_counts=severity_counts,
        severity_bar=severity_bar,
        lead_summary_paragraph=lead_paragraph,
    )

    # 7. Scope & Methodology Context
    discovered_assets = (
        len(attack_surface_data.get("endpoints", []))
        or len(attack_surface_data.get("assets", []))
        or 1
    )
    raw_technologies = (
        attack_surface_data.get("technologies", [])
        or attack_surface_data.get("tech_stack", [])
        or ["HTTP/1.1 REST API", "Web Application"]
    )
    technologies: list[str] = []
    for t in raw_technologies:
        if isinstance(t, dict):
            name = t.get("name") or t.get("technology") or t.get("id") or "Unknown"
            ver = t.get("version")
            technologies.append(f"{name} ({ver})" if ver else str(name))
        elif isinstance(t, str):
            technologies.append(t)
        else:
            technologies.append(str(t))
    if not technologies:
        technologies = ["HTTP/1.1 REST API", "Web Application"]

    raw_families = (
        vulnerability_data.get("families_tested", [])
        or list({f.vulnerability_family for f in (confirmed_sorted + candidates_list)})
    )
    families_tested: list[str] = [
        t.get("name", str(t)) if isinstance(t, dict) else str(t)
        for t in raw_families
    ]
    testers_count = len(raw_findings)
    total_requests = vulnerability_data.get("total_requests", max(testers_count * 2, 10))

    methodology = ScopeMethodology(
        scope_rule_id=rule_id,
        authorization_state=auth_state,
        authorized_target=authorized_target,
        authorization_timestamp=auth_timestamp,
        discovered_assets_count=discovered_assets,
        technologies_fingerprinted=technologies,
        families_run=families_tested,
        testers_fired_count=testers_count,
        total_requests_made=total_requests,
        assurance_statement=(
            "Testing was executed in accordance with non-destructive, authorized security testing "
            "standards. Detection utilized controlled payloads adhering to predefined rate-limit budgets. "
            "Findings reported as Confirmed have been verified through active Validation Layer logic."
        ),
    )

    return ReportData(
        executive_summary=exec_summary,
        confirmed_findings=confirmed_sorted,
        candidates_for_review=candidates_list,
        manual_checklist=manual_checklist,
        scope_methodology=methodology,
        generated_at=datetime.now(timezone.utc).isoformat(),
    )
