from __future__ import annotations

import math
from typing import Any

from .models import CVSSData


def _roundup(value: float) -> float:
    """CVSS 3.1 roundup function: smallest number, specified to 1 decimal place, >= input."""
    int_input = round(value * 100000)
    if (int_input % 10000) == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def calculate_cvss_31(
    av: str = "N",
    ac: str = "L",
    pr: str = "N",
    ui: str = "N",
    s: str = "U",
    c: str = "N",
    i: str = "N",
    a: str = "N",
) -> tuple[float, str]:
    """
    Calculate CVSS 3.1 Base Score and vector string.
    Returns (base_score, vector_string).
    """
    av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    ac_weights = {"L": 0.77, "H": 0.44}
    ui_weights = {"N": 0.85, "R": 0.62}
    impact_weights = {"N": 0.0, "L": 0.22, "H": 0.56}

    # PR depends on Scope
    if s == "C":
        pr_weights = {"N": 0.85, "L": 0.68, "H": 0.50}
    else:
        pr_weights = {"N": 0.85, "L": 0.62, "H": 0.27}

    weight_av = av_weights.get(av, 0.85)
    weight_ac = ac_weights.get(ac, 0.77)
    weight_pr = pr_weights.get(pr, 0.85)
    weight_ui = ui_weights.get(ui, 0.85)

    weight_c = impact_weights.get(c, 0.0)
    weight_i = impact_weights.get(i, 0.0)
    weight_a = impact_weights.get(a, 0.0)

    iss = 1.0 - ((1.0 - weight_c) * (1.0 - weight_i) * (1.0 - weight_a))
    exploitability = 8.22 * weight_av * weight_ac * weight_pr * weight_ui

    vector_string = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"

    if iss <= 0:
        return 0.0, vector_string

    if s == "U":
        impact = 6.42 * iss
        base_score = _roundup(min(impact + exploitability, 10.0))
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)
        base_score = _roundup(min(1.08 * (impact + exploitability), 10.0))

    return max(0.0, min(10.0, base_score)), vector_string


def score_to_rating(score: float) -> str:
    """Return CVSS 3.1 severity rating from score."""
    if score == 0.0:
        return "None"
    elif score <= 3.9:
        return "Low"
    elif score <= 6.9:
        return "Medium"
    elif score <= 8.9:
        return "High"
    else:
        return "Critical"


def derive_cvss(
    family: str,
    severity: str,
    has_auth: bool = False,
    metadata: dict[str, Any] | None = None,
) -> tuple[CVSSData | None, str]:
    """
    Derive CVSS 3.1 score for standard web vulnerabilities based on real characteristics.
    Returns (CVSSData, "") or (None, reason).
    """
    fam = family.lower().strip()
    sev = severity.upper().strip()
    pr = "L" if has_auth else "N"

    # Known family CVSS vectors
    vectors: dict[str, dict[str, str]] = {
        "sql_injection": {
            "CRITICAL": {"av": "N", "ac": "L", "pr": pr, "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},
            "HIGH": {"av": "N", "ac": "L", "pr": pr, "ui": "N", "s": "U", "c": "H", "i": "L", "a": "N"},
            "MEDIUM": {"av": "N", "ac": "H", "pr": pr, "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        },
        "rce": {
            "CRITICAL": {"av": "N", "ac": "L", "pr": pr, "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},
            "HIGH": {"av": "N", "ac": "H", "pr": pr, "ui": "N", "s": "U", "c": "H", "i": "H", "a": "L"},
        },
        "ssrf": {
            "CRITICAL": {"av": "N", "ac": "L", "pr": pr, "ui": "N", "s": "C", "c": "H", "i": "H", "a": "N"},
            "HIGH": {"av": "N", "ac": "L", "pr": pr, "ui": "N", "s": "C", "c": "H", "i": "N", "a": "N"},
            "MEDIUM": {"av": "N", "ac": "H", "pr": pr, "ui": "N", "s": "C", "c": "L", "i": "N", "a": "N"},
        },
        "xss": {
            "HIGH": {"av": "N", "ac": "L", "pr": pr, "ui": "R", "s": "C", "c": "L", "i": "L", "a": "N"},
            "MEDIUM": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "C", "c": "L", "i": "L", "a": "N"},
            "LOW": {"av": "N", "ac": "H", "pr": "N", "ui": "R", "s": "U", "c": "L", "i": "N", "a": "N"},
        },
        "idor_bola": {
            "HIGH": {"av": "N", "ac": "L", "pr": "L", "ui": "N", "s": "U", "c": "H", "i": "L", "a": "N"},
            "MEDIUM": {"av": "N", "ac": "L", "pr": "L", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        },
        "bopla": {
            "HIGH": {"av": "N", "ac": "L", "pr": "L", "ui": "N", "s": "U", "c": "N", "i": "H", "a": "N"},
            "MEDIUM": {"av": "N", "ac": "L", "pr": "L", "ui": "N", "s": "U", "c": "N", "i": "L", "a": "N"},
        },
        "authentication_bypass": {
            "CRITICAL": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},
            "HIGH": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "L", "a": "N"},
            "MEDIUM": {"av": "N", "ac": "H", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        },
        "function_authorization": {
            "HIGH": {"av": "N", "ac": "L", "pr": "L", "ui": "N", "s": "U", "c": "H", "i": "L", "a": "N"},
            "MEDIUM": {"av": "N", "ac": "L", "pr": "L", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        },
        "csrf": {
            "HIGH": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "N", "i": "H", "a": "N"},
            "MEDIUM": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "N", "i": "L", "a": "N"},
        },
        "open_redirect": {
            "MEDIUM": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "C", "c": "L", "i": "L", "a": "N"},
            "LOW": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "L", "i": "N", "a": "N"},
        },
        "cors": {
            "HIGH": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "H", "i": "N", "a": "N"},
            "MEDIUM": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "L", "i": "N", "a": "N"},
        },
        "sensitive_disclosure": {
            "HIGH": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
            "MEDIUM": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
            "LOW": {"av": "N", "ac": "H", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        },
        "xxe": {
            "HIGH": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
            "MEDIUM": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        },
        "clickjacking": {
            "MEDIUM": {"av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "U", "c": "N", "i": "L", "a": "N"},
            "LOW": {"av": "N", "ac": "H", "pr": "N", "ui": "R", "s": "U", "c": "N", "i": "L", "a": "N"},
        },
        "subdomain_takeover": {
            "HIGH": {"av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "C", "c": "L", "i": "L", "a": "N"},
        },
        "path_traversal_upload": {
            "CRITICAL": {"av": "N", "ac": "L", "pr": pr, "ui": "N", "s": "U", "c": "H", "i": "H", "a": "H"},
            "HIGH": {"av": "N", "ac": "L", "pr": pr, "ui": "N", "s": "U", "c": "H", "i": "N", "a": "N"},
            "MEDIUM": {"av": "N", "ac": "L", "pr": pr, "ui": "N", "s": "U", "c": "L", "i": "N", "a": "N"},
        },
    }

    family_entry = vectors.get(fam, {})
    params = family_entry.get(sev)
    if not params:
        # Check closest severity or fallback
        if family_entry:
            first_sev = next(iter(family_entry.values()))
            params = first_sev
        else:
            return None, "CVSS not calculated for this finding type"

    score, vector = calculate_cvss_31(**params)
    rating = score_to_rating(score)
    return CVSSData(vector_string=vector, base_score=score, severity_rating=rating), ""
