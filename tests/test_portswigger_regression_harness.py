"""PortSwigger Web Security Academy Ground-Truth Regression Harness.

Tracked regression suite mapping PortSwigger labs to expected vulnerability
family outcomes across Project 3 testers and Project 4 validation strategies.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from hunt_chain_vulnerability.testers.families.csrf import (
    build_testers as build_csrf_testers,
)
from hunt_chain_vulnerability.testers.families.authentication_bypass import (
    build_testers as build_auth_testers,
)
from hunt_chain_vulnerability.testers.families.ato import (
    build_testers as build_ato_testers,
)
from hunt_chain_vulnerability.testers.families.cors import (
    build_testers as build_cors_testers,
)
from hunt_chain_vulnerability.testers.families.ssrf import (
    build_testers as build_ssrf_testers,
)
from hunt_chain_vulnerability.testers.canary import MockCanaryListener
from hunt_chain_project4.validation.family_strategies import (
    CsrfRequestIntegrityStrategy,
    AuthenticationBypassStrategy,
    AtoWorkflowStrategy,
    CorsOriginStrategy,
    SsrfUrlBoundaryStrategy,
)
from hunt_chain_project4.input.project3 import ValidationCandidate, Project3Endpoint
from hunt_chain_project4.validation.observation import (
    ResponseObservation,
    ObservationComparison,
)
from hunt_chain_project4.validation.profiles import ValidationProfile
from hunt_chain_project4.validation.plan import ValidationPlan, ValidationRequest


FIXTURES_PATH = Path(__file__).parent / "fixtures" / "portswigger_regression_matrix.json"


def load_matrix() -> list[dict[str, Any]]:
    with open(FIXTURES_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def build_test_context(lab: dict[str, Any], probe_fn=None) -> Any:
    """Construct an execution context matching the PortSwigger lab specification."""
    ep_spec = lab["endpoint"]
    method = ep_spec.get("method", "GET")
    path = ep_spec.get("path", "/")
    url = f"https://target.example{path}"
    headers = dict(ep_spec.get("headers", {}))
    body = ep_spec.get("body") or ""
    resp_body = ep_spec.get("response_body") or body or ""
    params = list(ep_spec.get("parameters", {}).keys())

    endpoint = SimpleNamespace(
        endpoint_id=f"ep-{lab['lab_id']}",
        method=method,
        path=path,
        url=url,
        parameters=params,
        body_parameters=params if method in ("POST", "PUT", "PATCH") else [],
        body_parameter_values=ep_spec.get("parameters", {}),
        content_type=headers.get("Content-Type", "text/html"),
    )

    ctx = SimpleNamespace(
        endpoint=endpoint,
        target=SimpleNamespace(target_id="target-001"),
        execution_mode="NORMAL",
        metadata={
            "response": SimpleNamespace(
                status_code=200,
                headers=headers,
                body=resp_body,
                text=resp_body if isinstance(resp_body, str) else "",
            )
        },
        sessions=(),
        probe=probe_fn,
    )
    return ctx


class TestPortSwiggerRegressionHarness:
    """Permanent regression harness for PortSwigger lab ground-truth results."""

    @pytest.mark.parametrize("lab", [l for l in load_matrix() if l["category"] != "CSRF"])
    def test_csrf_negative_controls_must_not_produce_potential_or_confirmed(self, lab):
        """CSRF testers must report NOT_DETECTED on non-CSRF endpoints."""
        ctx = build_test_context(lab)
        csrf_testers = build_csrf_testers()

        for tester in csrf_testers:
            res = tester.execute(ctx)
            test_id = tester.definition.test_id
            assert res["status"] == "NOT_DETECTED", (
                f"False Positive Regression: {test_id} reported {res['status']} "
                f"on non-CSRF lab '{lab['title']}' ({lab['lab_id']}). Observation: {res.get('observation')}"
            )

    @pytest.mark.parametrize("lab", [l for l in load_matrix() if l["category"] == "CSRF"])
    def test_csrf_positive_controls_must_detect_vulnerability(self, lab):
        """CSRF testers must report POTENTIAL on real CSRF endpoints."""
        expected_ids = lab["expected_tester_ids"]
        lab_id = lab["lab_id"]

        def mock_probe(req):
            headers = getattr(req, "headers", {}) or {}
            headers_lower = {str(k).lower(): str(v) for k, v in headers.items()}
            referer = headers_lower.get("referer", "")
            origin = headers_lower.get("origin", "")

            if lab_id == "csrf-referer-validation-omitted":
                if referer or origin:
                    if "huntchain-attacker.example" in referer or "huntchain-attacker.example" in origin:
                        return SimpleNamespace(status_code=400, headers={}, body="Invalid Referer")
                return SimpleNamespace(status_code=302, headers={"Location": "/my-account?updated=1"}, body="Success")

            if lab_id == "csrf-broken-referer-validation":
                target_domain = "target.example"
                if referer or origin:
                    if target_domain not in referer and target_domain not in origin:
                        return SimpleNamespace(status_code=400, headers={}, body="Invalid Referer")
                return SimpleNamespace(status_code=302, headers={"Location": "/my-account?updated=1"}, body="Success")

            return SimpleNamespace(status_code=302, headers={"Location": "/my-account?updated=1"}, body="Success")

        ctx = build_test_context(lab, probe_fn=mock_probe)
        csrf_testers = build_csrf_testers()

        found_ids = []
        for tester in csrf_testers:
            res = tester.execute(ctx)
            if res["status"] == "POTENTIAL":
                found_ids.append(tester.definition.test_id)

        assert any(tid in found_ids for tid in expected_ids), (
            f"False Negative Regression: Expected tester in {expected_ids} to fire on '{lab['title']}', "
            f"but found {found_ids}"
        )

    @pytest.mark.parametrize("lab", [l for l in load_matrix() if l["category"] in ("OAuth", "Authentication")])
    def test_auth_and_ato_positive_controls_must_detect_vulnerability(self, lab):
        """AUTH and ATO testers must detect vulnerabilities on real Auth/OAuth labs."""
        expected_ids = lab["expected_tester_ids"]
        ctx = build_test_context(lab)

        all_testers = build_auth_testers() + build_ato_testers()
        found_ids = []
        for tester in all_testers:
            res = tester.execute(ctx)
            if res["status"] == "POTENTIAL":
                found_ids.append(tester.definition.test_id)

        assert any(tid in found_ids for tid in expected_ids), (
            f"False Negative Regression: Expected auth/ato tester in {expected_ids} to fire on '{lab['title']}', "
            f"but found {found_ids}"
        )

    def test_csrf_project4_validation_rejects_login_redirect_and_unauth(self):
        """Project 4 CSRF strategy must reject simulated attacks that redirect to login or show unauthenticated body."""
        strategy = CsrfRequestIntegrityStrategy()
        from hunt_chain_project4.validation.profiles import FAMILY_PROFILES
        profile = FAMILY_PROFILES["csrf"]
        endpoint = Project3Endpoint(
            endpoint_id="ep-1",
            target_id="target-1",
            url="https://target.example/my-account/change-email",
            method="POST",
            path="/my-account/change-email",
            parameters=("email",),
            metadata={},
        )
        cand = ValidationCandidate(
            result_id="res-1",
            test_id="CSRF-01",
            target_id="target-1",
            endpoint_id="ep-1",
            title="State-Changing Endpoint CSRF Surface",
            observation="POST /my-account/change-email lacks CSRF protection",
            confidence="high",
            evidence_ids=("ev-1",),
            source_result={"metadata": {}},
            source_evidence=(),
            endpoint=endpoint,
        )
        baseline = ResponseObservation(
            status_code=200,
            final_url="https://target.example/my-account/change-email",
            redirect_count=0,
            body_hash="hash0",
            body_excerpt="Form HTML",
            headers={},
        )
        # Case 1: Server redirected attacker probe to /login
        val_redirect = ResponseObservation(
            status_code=302,
            final_url="https://target.example/login",
            redirect_count=1,
            body_hash="hash1",
            body_excerpt="Redirecting to login",
            headers={"location": "/login"},
        )
        from hunt_chain_project4.validation.observation import compare_observations

        comp_redirect = compare_observations(baseline, val_redirect)
        decision = strategy.evaluate(cand, profile, baseline, val_redirect, comp_redirect)
        assert not decision.confirmed, f"Expected confirmed=False for login redirect, got {decision}"

        # Case 2: Server returned 200 with unauthenticated session warning
        val_unauth = ResponseObservation(
            status_code=200,
            final_url="https://target.example/my-account/change-email",
            redirect_count=0,
            body_hash="hash2",
            body_excerpt="Please log in to continue",
            headers={},
        )
        comp_unauth = compare_observations(baseline, val_unauth)
        decision2 = strategy.evaluate(cand, profile, baseline, val_unauth, comp_unauth)
        assert not decision2.confirmed, f"Expected confirmed=False for unauthenticated session, got {decision2}"

        # Case 3: Genuine CSRF success (HTTP 302 to account page with updated=1)
        val_success = ResponseObservation(
            status_code=302,
            final_url="https://target.example/my-account?updated=1",
            redirect_count=1,
            body_hash="hash3",
            body_excerpt="Email updated successfully",
            headers={"location": "/my-account?updated=1"},
        )
        comp_success = compare_observations(baseline, val_success)
        decision3 = strategy.evaluate(cand, profile, baseline, val_success, comp_success)
        assert decision3.confirmed, f"Expected confirmed=True for genuine CSRF success, got {decision3}"

    def test_csrf05_non_session_cookie_detection_and_validation(self):
        """CSRF-05 must detect non-session cookie CSRF on sensitive actions with high severity and confirm in Project 4."""
        lab = next(l for l in load_matrix() if l["lab_id"] == "csrf-token-tied-to-non-session-cookie")

        def mock_probe(req):
            headers = getattr(req, "headers", {}) or {}
            cookie_str = headers.get("Cookie", "")
            # Verify session cookie was NOT wiped out
            assert "session=victim_sess" in cookie_str, f"Session cookie was lost: {cookie_str}"
            assert "csrfKey=" in cookie_str, f"csrfKey was not set: {cookie_str}"
            return SimpleNamespace(status_code=302, headers={"Location": "/my-account?updated=1"}, body="Success")

        ctx = build_test_context(lab, probe_fn=mock_probe)
        from hunt_chain_vulnerability.testers.families.csrf import CSRF05Tester
        tester = CSRF05Tester()
        res = tester.execute(ctx)

        assert res["status"] == "POTENTIAL", f"Expected POTENTIAL, got {res}"
        assert res.get("severity") == "high", f"Expected severity high on sensitive email change, got {res.get('severity')}"
        assert res["metadata"].get("token_tied_to_non_session_cookie") is True, f"Metadata should flag decoupled cookie: {res}"
        assert res.get("validation_plan") is not None, "Expected validation plan"

        # Now test Project 4 validation
        from hunt_chain_project4.validation.family_strategies import CsrfRequestIntegrityStrategy
        from hunt_chain_project4.validation.profiles import FAMILY_PROFILES
        from hunt_chain_project4.input.project3 import ValidationCandidate, Project3Endpoint
        from hunt_chain_project4.validation.observation import ResponseObservation, compare_observations

        ep = Project3Endpoint(
            endpoint_id="ep-1",
            target_id="target-1",
            url=lab["endpoint"]["path"],
            method="POST",
            path=lab["endpoint"]["path"],
            parameters=("email", "csrf"),
            metadata={},
        )
        cand = ValidationCandidate(
            result_id="res-csrf-05",
            test_id="CSRF-05",
            target_id="target-1",
            endpoint_id="ep-1",
            title=res.get("title", "Cookie-Based Authentication CSRF Surface"),
            observation=res["observation"],
            confidence="high",
            evidence_ids=(),
            source_result=res,
            source_evidence=(),
            endpoint=ep,
            validation_plan=res.get("validation_plan"),
        )
        baseline = ResponseObservation(
            status_code=200,
            final_url="https://target.example/my-account/change-email",
            redirect_count=0,
            body_hash="hash0",
            body_excerpt="Form HTML",
            headers={},
        )
        val_success = ResponseObservation(
            status_code=302,
            final_url="https://target.example/my-account?updated=1",
            redirect_count=1,
            body_hash="hash3",
            body_excerpt="Email updated successfully",
            headers={"location": "/my-account?updated=1"},
        )
        comp = compare_observations(baseline, val_success)
        decision = CsrfRequestIntegrityStrategy().evaluate(cand, FAMILY_PROFILES["csrf"], baseline, val_success, comp)
        assert decision.confirmed is True, f"Expected CSRF-05 to be confirmed in Project 4, got {decision}"

    @pytest.mark.parametrize("lab", [l for l in load_matrix() if l["category"] == "CORS"])
    def test_cors_positive_controls_must_detect_and_confirm_vulnerability(self, lab):
        """CORS testers must detect vulnerabilities on real PortSwigger CORS labs and confirm in Project 4."""
        expected_ids = lab["expected_tester_ids"]
        lab_id = lab["lab_id"]

        def mock_probe(req, url=None):
            headers = getattr(req, "headers", {}) or {}
            headers_lower = {str(k).lower(): str(v) for k, v in headers.items()}
            origin = headers_lower.get("origin", "")
            cookie = headers_lower.get("cookie", "")

            resp_headers = {}
            if "session=" in cookie or "victim" in cookie:
                if lab_id == "cors-basic-origin-reflection":
                    if origin:
                        resp_headers["Access-Control-Allow-Origin"] = origin
                        resp_headers["Access-Control-Allow-Credentials"] = "true"
                elif lab_id == "cors-trusted-null-origin":
                    if origin == "null":
                        resp_headers["Access-Control-Allow-Origin"] = "null"
                        resp_headers["Access-Control-Allow-Credentials"] = "true"
                elif lab_id == "cors-trusted-insecure-protocol":
                    if origin and origin.startswith("http://"):
                        resp_headers["Access-Control-Allow-Origin"] = origin
                        resp_headers["Access-Control-Allow-Credentials"] = "true"
                elif lab_id == "cors-internal-intranet-subdomain":
                    if origin and ("sub." in origin or "intranet." in origin or "stock." in origin or origin.endswith(".attacker.com") or "evil" in origin):
                        resp_headers["Access-Control-Allow-Origin"] = origin
                        resp_headers["Access-Control-Allow-Credentials"] = "true"

            body = lab["endpoint"].get("response_body", "")
            return SimpleNamespace(status_code=200, headers=resp_headers, body=body, text=body)

        ctx = build_test_context(lab, probe_fn=mock_probe)
        cors_testers = build_cors_testers()

        found_ids = []
        winning_results = []
        for tester in cors_testers:
            res = tester.execute(ctx)
            if res["status"] == "POTENTIAL":
                found_ids.append(tester.definition.test_id)
                winning_results.append(res)

        assert any(tid in found_ids for tid in expected_ids), (
            f"False Negative Regression: Expected cors tester in {expected_ids} to fire on '{lab['title']}', "
            f"but found {found_ids}"
        )

        best_res = winning_results[0]
        val_plan = best_res.get("validation_plan")
        assert val_plan is not None, f"Expected validation plan on {best_res}"

        from hunt_chain_project4.validation.profiles import FAMILY_PROFILES
        from hunt_chain_project4.input.project3 import ValidationCandidate, Project3Endpoint
        from hunt_chain_project4.validation.observation import ResponseObservation, compare_observations

        ep = Project3Endpoint(
            endpoint_id=f"ep-{lab_id}",
            target_id="target-1",
            url=f"https://target.example{lab['endpoint']['path']}",
            method=lab["endpoint"]["method"],
            path=lab["endpoint"]["path"],
            parameters=(),
            metadata={},
        )
        cand = ValidationCandidate(
            result_id=f"res-{lab_id}",
            test_id=best_res["test_id"],
            target_id="target-1",
            endpoint_id=f"ep-{lab_id}",
            title=f"CORS Finding {best_res['test_id']}",
            observation=best_res["observation"],
            confidence="high",
            evidence_ids=(),
            source_result=best_res,
            source_evidence=(),
            endpoint=ep,
            validation_plan=val_plan,
        )
        baseline = ResponseObservation(
            status_code=200,
            final_url=f"https://target.example{lab['endpoint']['path']}",
            redirect_count=0,
            body_hash="basehash",
            body_excerpt=lab["endpoint"].get("response_body", ""),
            headers={},
        )

        mut_req = val_plan.mutation
        mut_headers = {str(k).lower(): str(v) for k, v in mut_req.headers.items()}
        mut_origin = mut_headers.get("origin", "")
        mut_cookie = mut_headers.get("cookie", "session=victim_session_token_123")
        sim_resp = mock_probe(SimpleNamespace(headers={"origin": mut_origin, "cookie": mut_cookie}))

        val_obs = ResponseObservation(
            status_code=sim_resp.status_code,
            final_url=f"https://target.example{lab['endpoint']['path']}",
            redirect_count=0,
            body_hash="valhash",
            body_excerpt=sim_resp.body,
            headers={str(k).lower(): str(v) for k, v in sim_resp.headers.items()},
        )
        comp = compare_observations(baseline, val_obs)
        decision = CorsOriginStrategy().evaluate(cand, FAMILY_PROFILES["cors"], baseline, val_obs, comp)
        assert decision.confirmed is True, (
            f"Project 4 Validation failed to confirm CORS finding on '{lab['title']}': {decision.reason}"
        )

    @pytest.mark.parametrize("lab", [l for l in load_matrix() if l["category"] == "SSRF"])
    def test_ssrf_portswigger_positive_controls_and_escalation_ladder(self, lab):
        """SSRF testers must detect and confirm findings on PortSwigger SSRF labs including hard escalation rungs."""
        expected_ids = lab["expected_tester_ids"]
        lab_id = lab["lab_id"]
        listener = MockCanaryListener()

        def mock_probe(req, url=None):
            req_url = getattr(req, "url", "") or str(url or "")
            req_url_lower = req_url.lower()

            if lab_id == "ssrf-basic-local-server":
                if "127.0.0.1" in req_url_lower or "localhost" in req_url_lower:
                    return SimpleNamespace(
                        status_code=200,
                        headers={"content-type": "text/html"},
                        body="<h1>Admin Panel</h1><p>Delete user carlos</p>",
                        text="<h1>Admin Panel</h1><p>Delete user carlos</p>",
                    )
            elif lab_id == "ssrf-blacklist-filter-bypass":
                if "127.0.0.1" in req_url_lower or "localhost" in req_url_lower:
                    return SimpleNamespace(status_code=403, headers={}, body="Blocked: Blacklisted host", text="Blocked: Blacklisted host")
                if "2130706433" in req_url_lower or "127.1" in req_url_lower:
                    return SimpleNamespace(
                        status_code=200,
                        headers={"content-type": "text/html"},
                        body="<h1>Admin Panel</h1><p>Delete user carlos</p>",
                        text="<h1>Admin Panel</h1><p>Delete user carlos</p>",
                    )
            elif lab_id == "ssrf-whitelist-filter-bypass":
                if "target.example@" in req_url_lower or "weliketoshop.net@" in req_url_lower:
                    return SimpleNamespace(
                        status_code=200,
                        headers={"content-type": "text/html"},
                        body="<h1>Admin Panel</h1><p>Delete user carlos</p>",
                        text="<h1>Admin Panel</h1><p>Delete user carlos</p>",
                    )
                return SimpleNamespace(status_code=400, headers={}, body="Invalid domain whitelist", text="Invalid domain whitelist")
            elif lab_id == "ssrf-blind-out-of-band":
                if "canary-audit.net" in req_url:
                    for part in req_url.split("/"):
                        if "canary-audit.net" in part:
                            tok = part.split(".canary-audit.net")[0].replace("http://", "").replace("https://", "")
                            listener.record_hit(tok, protocol="HTTP")
                return SimpleNamespace(status_code=200, headers={"content-type": "application/json"}, body='{"status": "queued"}', text='{"status": "queued"}')
            elif lab_id == "ssrf-filter-bypass-via-open-redirection":
                if "redirect" in req_url_lower or "nextproduct" in req_url_lower:
                    if "canary-audit.net" in req_url:
                        for part in req_url.split("/"):
                            if "canary-audit.net" in part:
                                tok = part.split(".canary-audit.net")[0].replace("http://", "").replace("https://", "")
                                listener.record_hit(tok, protocol="HTTP")
                        return SimpleNamespace(status_code=200, headers={}, body="Reached internal target", text="Reached internal target")
                    return SimpleNamespace(status_code=302, headers={"location": "http://127.0.0.1/"}, body="", text="")

            return SimpleNamespace(status_code=400, headers={}, body="Bad Request", text="Bad Request")

        ctx = build_test_context(lab, probe_fn=mock_probe)
        ctx.metadata["canary_listener"] = listener
        ctx.metadata["canary_domain"] = "canary-audit.net"

        ssrf_testers = build_ssrf_testers()
        found_ids = []
        winning_results = []

        for tester in ssrf_testers:
            res = tester.execute(ctx)
            if res["status"] in ("CONFIRMED", "POTENTIAL"):
                found_ids.append(tester.definition.test_id)
                winning_results.append(res)

        assert any(tid in found_ids for tid in expected_ids), (
            f"Expected SSRF tester in {expected_ids} to fire on '{lab['title']}', but got {found_ids}"
        )

        best_res = winning_results[0]
        if "escalation_rung" in lab:
            assert best_res["metadata"]["escalation_rung"] == lab["escalation_rung"], (
                f"Expected escalation rung {lab['escalation_rung']} on '{lab['title']}', got {best_res['metadata']['escalation_rung']}"
            )


