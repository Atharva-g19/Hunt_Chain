from __future__ import annotations

import pytest
from hunt_chain_core.project_4_ui import (
    _extract_host,
    _parse_candidate_selection,
)


def _make_candidate(result_id: str, test_id: str, url: str) -> dict:
    return {
        "result_id": result_id,
        "test_id": test_id,
        "target_id": "target-1",
        "endpoint_id": f"ep-{result_id}",
        "title": f"Finding {test_id}",
        "endpoint": {
            "url": url,
            "method": "GET",
        },
    }


def test_extract_host():
    c1 = _make_candidate("r1", "AUTH-01", "https://admin.example.com/login")
    assert _extract_host(c1) == "admin.example.com"

    c2 = _make_candidate("r2", "IDOR-01", "http://api.example.com:8080/users")
    assert _extract_host(c2) == "api.example.com"

    c3 = _make_candidate("r3", "CSRF-01", "not-a-valid-url")
    assert _extract_host(c3) == "unknown-host"


def test_parse_candidate_selection_single_and_range():
    cands = [
        _make_candidate("r1", "AUTH-01", "https://admin.example.com/1"),
        _make_candidate("r2", "AUTH-02", "https://admin.example.com/2"),
        _make_candidate("r3", "AUTH-03", "https://api.example.com/3"),
        _make_candidate("r4", "AUTH-04", "https://api.example.com/4"),
    ]
    domain_tags = {"admin.example.com": "D1", "api.example.com": "D2"}
    tag_to_cands = {"D1": [cands[0], cands[1]], "D2": [cands[2], cands[3]]}

    # Single number
    sel, cmd = _parse_candidate_selection("2", cands, domain_tags, tag_to_cands)
    assert cmd is None
    assert len(sel) == 1
    assert sel[0]["test_id"] == "AUTH-02"

    # Range
    sel, cmd = _parse_candidate_selection("1-3", cands, domain_tags, tag_to_cands)
    assert cmd is None
    assert len(sel) == 3
    assert [c["test_id"] for c in sel] == ["AUTH-01", "AUTH-02", "AUTH-03"]

    # Comma list
    sel, cmd = _parse_candidate_selection("1, 4", cands, domain_tags, tag_to_cands)
    assert cmd is None
    assert len(sel) == 2
    assert [c["test_id"] for c in sel] == ["AUTH-01", "AUTH-04"]


def test_parse_candidate_selection_all():
    cands = [
        _make_candidate("r1", "AUTH-01", "https://admin.example.com/1"),
        _make_candidate("r2", "AUTH-02", "https://api.example.com/2"),
    ]
    domain_tags = {"admin.example.com": "D1", "api.example.com": "D2"}
    tag_to_cands = {"D1": [cands[0]], "D2": [cands[1]]}

    sel, cmd = _parse_candidate_selection("all", cands, domain_tags, tag_to_cands)
    assert cmd is None
    assert len(sel) == 2

    sel, cmd = _parse_candidate_selection("*", cands, domain_tags, tag_to_cands)
    assert cmd is None
    assert len(sel) == 2


def test_parse_candidate_selection_by_subdomain_tag():
    cands = [
        _make_candidate("r1", "AUTH-01", "https://admin.example.com/1"),
        _make_candidate("r2", "AUTH-02", "https://admin.example.com/2"),
        _make_candidate("r3", "IDOR-01", "https://api.example.com/3"),
    ]
    domain_tags = {"admin.example.com": "D1", "api.example.com": "D2"}
    tag_to_cands = {"D1": [cands[0], cands[1]], "D2": [cands[2]]}

    # Tag D1
    sel, cmd = _parse_candidate_selection("D1", cands, domain_tags, tag_to_cands)
    assert cmd is None
    assert len(sel) == 2
    assert [c["test_id"] for c in sel] == ["AUTH-01", "AUTH-02"]

    # Tag lowercase d2
    sel, cmd = _parse_candidate_selection("d2", cands, domain_tags, tag_to_cands)
    assert cmd is None
    assert len(sel) == 1
    assert sel[0]["test_id"] == "IDOR-01"

    # Multi-tag
    sel, cmd = _parse_candidate_selection("d1, d2", cands, domain_tags, tag_to_cands)
    assert cmd is None
    assert len(sel) == 3


def test_parse_candidate_selection_commands():
    cands = [_make_candidate("r1", "AUTH-01", "https://admin.example.com/1")]
    domain_tags = {"admin.example.com": "D1"}
    tag_to_cands = {"D1": cands}

    # Back
    sel, cmd = _parse_candidate_selection("0", cands, domain_tags, tag_to_cands)
    assert cmd == "BACK"
    assert sel == []

    # Domain filter
    sel, cmd = _parse_candidate_selection("d api.example.com", cands, domain_tags, tag_to_cands)
    assert cmd == "DOMAIN_FILTER:api.example.com"
    assert sel is None

    # Keyword filter
    sel, cmd = _parse_candidate_selection("f idor", cands, domain_tags, tag_to_cands)
    assert cmd == "KEYWORD_FILTER:idor"
    assert sel is None

    # Clear filter
    sel, cmd = _parse_candidate_selection("clear", cands, domain_tags, tag_to_cands)
    assert cmd == "CLEAR_FILTER"
    assert sel is None
