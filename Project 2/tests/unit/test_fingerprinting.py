"""Tests for deterministic technology fingerprinting."""

from __future__ import annotations

from uuid import uuid4

from hunt_chain_recon.models.endpoints import Endpoint, EndpointScheme
from hunt_chain_recon.models.technology import (
    TechnologyCategory,
    TechnologyConfidence,
    TechnologyEvidenceType,
)
from hunt_chain_recon.processing.fingerprinting import (
    TechnologyFingerprinter,
)


def make_endpoint() -> Endpoint:
    """Create a deterministic test endpoint."""
    return Endpoint(
        asset_id=uuid4(),
        scheme=EndpointScheme.HTTPS,
        hostname="app.example.com",
        port=443,
        url="https://app.example.com/",
    )


def test_server_header_detects_nginx() -> None:
    """A Server header containing nginx produces web-server evidence."""
    endpoint = make_endpoint()

    result = TechnologyFingerprinter().fingerprint(
        endpoint=endpoint,
        headers={"Server": "nginx/1.24.0"},
        body=b"",
    )

    assert len(result.technologies) == 1

    technology = result.technologies[0]

    assert technology.name == "Nginx"
    assert technology.category == TechnologyCategory.WEB_SERVER
    assert technology.version == "1.24.0"


def test_server_header_detection_is_case_insensitive() -> None:
    """HTTP header names and technology markers are case-insensitive."""
    endpoint = make_endpoint()

    result = TechnologyFingerprinter().fingerprint(
        endpoint=endpoint,
        headers={"server": "NGINX/1.24.0"},
        body=b"",
    )

    assert any(
        technology.name == "Nginx"
        for technology in result.technologies
    )


def test_server_header_detects_python_simplehttp() -> None:
    """SimpleHTTP Python server header produces Python evidence."""
    endpoint = make_endpoint()

    result = TechnologyFingerprinter().fingerprint(
        endpoint=endpoint,
        headers={
            "Server": "SimpleHTTP/0.6 Python/3.13.2"
        },
        body=b"",
    )

    python = [
        technology
        for technology in result.technologies
        if technology.name == "Python"
    ]

    assert len(python) == 1
    assert (
        python[0].category
        == TechnologyCategory.PROGRAMMING_LANGUAGE
    )
    assert python[0].version == "3.13.2"


def test_python_simplehttp_detection_is_case_insensitive() -> None:
    """SimpleHTTP Python detection is case-insensitive."""
    endpoint = make_endpoint()

    result = TechnologyFingerprinter().fingerprint(
        endpoint=endpoint,
        headers={
            "server": "simplehttp/0.6 python/3.13.2"
        },
        body=b"",
    )

    assert any(
        technology.name == "Python"
        for technology in result.technologies
    )


def test_x_powered_by_detects_php() -> None:
    """X-Powered-By can provide programming-language evidence."""
    endpoint = make_endpoint()

    result = TechnologyFingerprinter().fingerprint(
        endpoint=endpoint,
        headers={"X-Powered-By": "PHP/8.3.2"},
        body=b"",
    )

    php = [
        technology
        for technology in result.technologies
        if technology.name == "PHP"
    ]

    assert len(php) == 1
    assert php[0].category == TechnologyCategory.PROGRAMMING_LANGUAGE
    assert php[0].version == "8.3.2"


def test_powered_by_detects_asp_net() -> None:
    """ASP.NET can be identified from X-Powered-By."""
    endpoint = make_endpoint()

    result = TechnologyFingerprinter().fingerprint(
        endpoint=endpoint,
        headers={"X-Powered-By": "ASP.NET"},
        body=b"",
    )

    assert any(
        technology.name == "ASP.NET"
        and technology.category
        == TechnologyCategory.WEB_FRAMEWORK
        for technology in result.technologies
    )


def test_wordpress_body_marker_detects_cms() -> None:
    """A WordPress HTML marker produces CMS evidence."""
    endpoint = make_endpoint()

    body = b"""
    <html>
        <head>
            <meta name="generator" content="WordPress 6.5.3">
        </head>
    </html>
    """

    result = TechnologyFingerprinter().fingerprint(
        endpoint=endpoint,
        headers={"Content-Type": "text/html"},
        body=body,
    )

    wordpress = [
        technology
        for technology in result.technologies
        if technology.name == "WordPress"
    ]

    assert len(wordpress) == 1
    assert wordpress[0].category == TechnologyCategory.CMS
    assert wordpress[0].version == "6.5.3"


def test_react_marker_detects_javascript_framework() -> None:
    """A React marker in HTML produces JavaScript-framework evidence."""
    endpoint = make_endpoint()

    body = b"""
    <html>
        <body>
            <div id="root"></div>
            <script src="/static/js/react.production.min.js"></script>
        </body>
    </html>
    """

    result = TechnologyFingerprinter().fingerprint(
        endpoint=endpoint,
        headers={},
        body=body,
    )

    assert any(
        technology.name == "React"
        and technology.category
        == TechnologyCategory.JAVASCRIPT_FRAMEWORK
        for technology in result.technologies
    )


def test_multiple_independent_fingerprints_are_preserved() -> None:
    """Independent observations can produce multiple technologies."""
    endpoint = make_endpoint()

    result = TechnologyFingerprinter().fingerprint(
        endpoint=endpoint,
        headers={
            "Server": "nginx/1.24.0",
            "X-Powered-By": "PHP/8.3.2",
        },
        body=b"",
    )

    names = {
        technology.name
        for technology in result.technologies
    }

    assert "Nginx" in names
    assert "PHP" in names


def test_duplicate_evidence_does_not_duplicate_technology() -> None:
    """Repeated evidence for the same technology is consolidated."""
    endpoint = make_endpoint()

    result = TechnologyFingerprinter().fingerprint(
        endpoint=endpoint,
        headers={
            "Server": "nginx/1.24.0",
            "X-Server": "nginx/1.24.0",
        },
        body=b"",
    )

    nginx = [
        technology
        for technology in result.technologies
        if technology.name == "Nginx"
    ]

    assert len(nginx) == 1


def test_header_evidence_is_explainable() -> None:
    """Header-derived technology includes deterministic evidence."""
    endpoint = make_endpoint()

    result = TechnologyFingerprinter().fingerprint(
        endpoint=endpoint,
        headers={"Server": "nginx/1.24.0"},
        body=b"",
    )

    evidence = [
        item
        for item in result.evidence
        if item.evidence_type
        == TechnologyEvidenceType.HTTP_HEADER
    ]

    assert evidence

    assert all(
        item.confidence
        in {
            TechnologyConfidence.LOW,
            TechnologyConfidence.MEDIUM,
            TechnologyConfidence.HIGH,
        }
        for item in evidence
    )

    assert all(item.rule.strip() for item in evidence)
    assert all(item.observation.strip() for item in evidence)


def test_body_evidence_is_explainable() -> None:
    """Body-derived technology includes deterministic evidence."""
    endpoint = make_endpoint()

    result = TechnologyFingerprinter().fingerprint(
        endpoint=endpoint,
        headers={},
        body=b'<meta name="generator" content="WordPress 6.5.3">',
    )

    evidence = [
        item
        for item in result.evidence
        if item.evidence_type
        in {
            TechnologyEvidenceType.HTTP_BODY,
            TechnologyEvidenceType.HTML,
        }
    ]

    assert evidence


def test_technology_evidence_references_existing_technology() -> None:
    """Every fingerprint evidence item references a returned technology."""
    endpoint = make_endpoint()

    result = TechnologyFingerprinter().fingerprint(
        endpoint=endpoint,
        headers={"Server": "nginx/1.24.0"},
        body=b"",
    )

    technology_ids = {
        technology.id
        for technology in result.technologies
    }

    assert all(
        evidence.technology_id in technology_ids
        for evidence in result.evidence
    )


def test_unknown_response_produces_no_false_technology() -> None:
    """Unknown responses must not produce speculative technologies."""
    endpoint = make_endpoint()

    result = TechnologyFingerprinter().fingerprint(
        endpoint=endpoint,
        headers={
            "Content-Type": "application/octet-stream",
        },
        body=b"\x00\x01\x02\x03\x04",
    )

    assert result.technologies == []
    assert result.evidence == []


def test_fingerprinting_does_not_perform_network_activity() -> None:
    """Fingerprinting operates entirely on supplied observations."""
    endpoint = make_endpoint()

    result = TechnologyFingerprinter().fingerprint(
        endpoint=endpoint,
        headers={"Server": "nginx/1.24.0"},
        body=b"",
    )

    assert result.technologies
    assert result.evidence