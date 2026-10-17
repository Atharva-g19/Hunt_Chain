from __future__ import annotations

import pytest
from hunt_chain_core.project_3_ui import CATEGORIES, _resolve_categories


def test_resolve_categories_default():
    # Empty input defaults to SQL Injection (17)
    test_ids, names = _resolve_categories("")
    assert len(test_ids) == 10
    assert any("SQLI" in tid for tid in test_ids)
    assert any("SQL Injection" in n for n in names)


def test_resolve_categories_back():
    test_ids, names = _resolve_categories("0")
    assert test_ids == []
    assert names == ["Back"]

    test_ids, names = _resolve_categories("back")
    assert test_ids == []
    assert names == ["Back"]


def test_resolve_categories_all():
    test_ids, names = _resolve_categories("all")
    assert test_ids is None
    assert "All 22 Categories" in names[0]


def test_resolve_categories_multi_word_phrases():
    # "account takeover" should NOT match subdomain takeover
    test_ids, names = _resolve_categories("account takeover")
    assert len(names) == 1
    assert "Account Takeover (ATO)" in names[0]
    assert all(tid.startswith("ATO-") for tid in test_ids)

    # "business logic"
    test_ids, names = _resolve_categories("business logic")
    assert len(names) == 1
    assert "Business Logic (BUSINESS)" in names[0]

    # "sql injection"
    test_ids, names = _resolve_categories("sql injection")
    assert len(names) == 1
    assert "SQL Injection (SQLI)" in names[0]


def test_resolve_categories_indices_and_ranges():
    # Single index
    test_ids, names = _resolve_categories("17")
    assert len(names) == 1
    assert "SQL Injection (SQLI)" in names[0]

    # Multiple comma-separated indices
    test_ids, names = _resolve_categories("1, 17")
    assert len(names) == 2
    assert "Account Takeover (ATO)" in names[0]
    assert "SQL Injection (SQLI)" in names[1]

    # Numeric range 1-3
    test_ids, names = _resolve_categories("1-3")
    assert len(names) == 3
    assert "Account Takeover (ATO)" in names[0]
    assert "Authentication Bypass (AUTH)" in names[1]
    assert "Mass Assignment / BOPLA (BOPLA)" in names[2]


def test_resolve_categories_codes_and_check_ids():
    # Codes
    test_ids, names = _resolve_categories("sqli, xss")
    assert len(names) == 2
    assert any("SQLI" in n for n in names)
    assert any("XSS" in n for n in names)

    # Specific check IDs
    test_ids, names = _resolve_categories("SQLI-08, ATO-01")
    assert test_ids == ["SQLI-08", "ATO-01"]
    assert names == ["SQLI-08", "ATO-01"]


def test_all_22_categories_resolvable():
    for cat in CATEGORIES:
        idx_str = str(cat["index"])
        test_ids, names = _resolve_categories(idx_str)
        assert len(names) == 1
        assert cat["name"] in names[0]
        assert len(test_ids) == cat["checks"]

        code_str = str(cat["code"])
        test_ids, names = _resolve_categories(code_str)
        assert len(names) == 1
        assert cat["name"] in names[0]
