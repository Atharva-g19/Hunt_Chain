from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class FindingStatus(str, Enum):
    CONFIRMED = "CONFIRMED"
    NOT_CONFIRMED = "NOT_CONFIRMED"
    MANUAL_ONLY = "MANUAL_ONLY"


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @classmethod
    def from_str(cls, val: str | None) -> SeverityLevel:
        if not val:
            return cls.MEDIUM
        normalized = val.strip().upper()
        if normalized in cls._value2member_map_:
            return cls(normalized)
        return cls.MEDIUM

    @property
    def rank(self) -> int:
        ranks = {
            "CRITICAL": 0,
            "HIGH": 1,
            "MEDIUM": 2,
            "LOW": 3,
            "INFO": 4,
        }
        return ranks.get(self.value, 5)


@dataclass
class CVSSData:
    vector_string: str
    base_score: float
    severity_rating: str
    derived: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "vector_string": self.vector_string,
            "base_score": self.base_score,
            "severity_rating": self.severity_rating,
            "derived": self.derived,
        }


@dataclass
class ReportFinding:
    finding_id: str
    title: str
    vulnerability_family: str
    vulnerability_type: str
    cwe_id: str
    cwe_name: str
    owasp_category: str
    severity: str
    status: str
    description: str
    target: str
    endpoint: str
    method: str = "GET"
    parameter: str = ""
    cvss: CVSSData | None = None
    cvss_note: str = ""
    steps_to_reproduce: list[str] = field(default_factory=list)
    evidence: str = ""
    impact: str = ""
    suggested_remediation: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    contributing_tester_ids: list[str] = field(default_factory=list)
    related_finding_ids: list[str] = field(default_factory=list)
    related_notes: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "title": self.title,
            "vulnerability_family": self.vulnerability_family,
            "vulnerability_type": self.vulnerability_type,
            "cwe_id": self.cwe_id,
            "cwe_name": self.cwe_name,
            "owasp_category": self.owasp_category,
            "severity": self.severity,
            "status": self.status,
            "cvss": self.cvss.to_dict() if self.cvss else None,
            "cvss_note": self.cvss_note,
            "description": self.description,
            "target": self.target,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "steps_to_reproduce": list(self.steps_to_reproduce),
            "evidence": self.evidence,
            "impact": self.impact,
            "suggested_remediation": list(self.suggested_remediation),
            "references": list(self.references),
            "contributing_tester_ids": list(self.contributing_tester_ids),
            "related_finding_ids": list(self.related_finding_ids),
            "related_notes": list(self.related_notes),
            "metadata": dict(self.metadata),
        }


@dataclass
class ManualChecklistItem:
    family: str
    test_id: str
    title: str
    endpoint: str
    action_items: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "family": self.family,
            "test_id": self.test_id,
            "title": self.title,
            "endpoint": self.endpoint,
            "action_items": list(self.action_items),
        }


@dataclass
class ExecutiveSummary:
    target: str
    scope_reference: str
    authorization_timestamp: str
    test_run_start: str
    test_run_end: str
    total_findings: int
    confirmed_count: int
    not_confirmed_count: int
    manual_only_count: int
    severity_counts: dict[str, int]
    severity_bar: str
    lead_summary_paragraph: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scope_reference": self.scope_reference,
            "authorization_timestamp": self.authorization_timestamp,
            "test_run_start": self.test_run_start,
            "test_run_end": self.test_run_end,
            "total_findings": self.total_findings,
            "confirmed_count": self.confirmed_count,
            "not_confirmed_count": self.not_confirmed_count,
            "manual_only_count": self.manual_only_count,
            "severity_counts": dict(self.severity_counts),
            "severity_bar": self.severity_bar,
            "lead_summary_paragraph": self.lead_summary_paragraph,
        }


@dataclass
class ScopeMethodology:
    scope_rule_id: str
    authorization_state: str
    authorized_target: str
    authorization_timestamp: str
    discovered_assets_count: int
    technologies_fingerprinted: list[str]
    families_run: list[str]
    testers_fired_count: int
    total_requests_made: int
    assurance_statement: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "scope_rule_id": self.scope_rule_id,
            "authorization_state": self.authorization_state,
            "authorized_target": self.authorized_target,
            "authorization_timestamp": self.authorization_timestamp,
            "discovered_assets_count": self.discovered_assets_count,
            "technologies_fingerprinted": list(self.technologies_fingerprinted),
            "families_run": list(self.families_run),
            "testers_fired_count": self.testers_fired_count,
            "total_requests_made": self.total_requests_made,
            "assurance_statement": self.assurance_statement,
        }


@dataclass
class ReportData:
    executive_summary: ExecutiveSummary
    confirmed_findings: list[ReportFinding]
    candidates_for_review: list[ReportFinding]
    manual_checklist: list[ManualChecklistItem]
    scope_methodology: ScopeMethodology
    generated_at: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "report_schema_version": "v1.0",
            "generated_at": self.generated_at,
            "executive_summary": self.executive_summary.to_dict(),
            "confirmed_findings": [f.to_dict() for f in self.confirmed_findings],
            "candidates_for_manual_review": [f.to_dict() for f in self.candidates_for_review],
            "manual_only_checklist": [c.to_dict() for c in self.manual_checklist],
            "scope_and_methodology": self.scope_methodology.to_dict(),
        }
