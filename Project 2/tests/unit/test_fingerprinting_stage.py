"""Tests for technology fingerprinting stage evidence flow."""

from __future__ import annotations

from types import SimpleNamespace
from uuid import uuid4

from hunt_chain_recon.models.endpoints import Endpoint
from hunt_chain_recon.models.http import HTTPObservation
from hunt_chain_recon.pipeline.fingerprinting import FingerprintingStage
from hunt_chain_recon.pipeline.http import HTTPStageResult


def test_redirect_response_headers_are_fingerprinted() -> None:
    """Redirect evidence retains observable final-response technologies."""
    endpoint = Endpoint(
        asset_id=uuid4(),
        scheme="https",
        hostname="example.com",
        port=443,
        url="https://example.com",
    )
    observation = HTTPObservation(
        endpoint_id=endpoint.id,
        state="REDIRECT",
        status_code=200,
        headers={
            "server": "cloudflare",
            "x-nextjs-cache": "HIT",
        },
        redirect_chain=["https://example.com/en"],
    )
    state = {
        "endpoints": [endpoint],
        "http_results": HTTPStageResult(
            observations=[observation],
            raw_bodies={},
        ),
    }
    context = SimpleNamespace(
        config=SimpleNamespace(
            fingerprinting=SimpleNamespace(enabled=True)
        ),
        execution_policy=SimpleNamespace(
            require_allowed=lambda activity: None
        ),
        require_authorized=lambda: None,
        get_state=state.get,
        set_state=state.__setitem__,
    )

    result = FingerprintingStage().execute(context)

    assert {technology.name for technology in result.technologies} == {
        "Cloudflare",
        "Next.js",
    }
    assert len(result.evidence) == 2
