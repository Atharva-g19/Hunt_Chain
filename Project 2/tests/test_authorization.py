"""Authorization tests for Hunt_Chain Project 2.

These tests verify the authorization boundary between Project 1
(ScopeGuard) and Project 2.

No network activity is performed.
"""

from pathlib import Path

import pytest

from hunt_chain_recon.authorization import (
    AuthorizationDecision,
    AuthorizationError,
    AuthorizationResult,
    ScopeGuardAdapter,
)
from hunt_chain_recon.config.models import AuthorizationConfig


PROJECT_1_SCOPE = (
    Path(__file__).resolve().parents[2]
    / "Project 1"
    / "ScopeGuard"
    / "examples"
    / "basic_scope.yaml"
)


def build_authorization_config(
    reference: str = "test-scopeguard-reference",
    scope_file: str | None = None,
) -> AuthorizationConfig:
    """Build a ScopeGuard authorization configuration."""
    return AuthorizationConfig(
        provider="scopeguard",
        reference=reference,
        scope_file=scope_file,
    )


@pytest.mark.parametrize(
    ("decision", "expected_authorized"),
    [
        (AuthorizationDecision.IN_SCOPE, True),
        (AuthorizationDecision.OUT_OF_SCOPE, False),
        (AuthorizationDecision.UNKNOWN, False),
        (AuthorizationDecision.CONFLICT, False),
    ],
)
def test_authorization_decisions(
    decision: AuthorizationDecision,
    expected_authorized: bool,
) -> None:
    """Verify that only IN_SCOPE is considered authorized."""
    result = AuthorizationResult(
        target="example.com",
        decision=decision,
        provider="scopeguard",
        reference="test-scopeguard-reference",
    )

    assert result.is_authorized is expected_authorized


def test_in_scope_is_the_only_authorized_decision() -> None:
    """Verify the authorization invariant explicitly."""
    for decision in AuthorizationDecision:
        result = AuthorizationResult(
            target="example.com",
            decision=decision,
            provider="scopeguard",
            reference="test-scopeguard-reference",
        )

        if decision is AuthorizationDecision.IN_SCOPE:
            assert result.is_authorized is True
        else:
            assert result.is_authorized is False


def test_authorization_result_normalizes_target() -> None:
    """Verify lightweight target normalization."""
    result = AuthorizationResult(
        target="  Example.COM.  ",
        decision="IN_SCOPE",
        provider="scopeguard",
        reference="test-scopeguard-reference",
    )

    assert result.target == "example.com"
    assert result.is_authorized is True


def test_invalid_authorization_decision_is_rejected() -> None:
    """Verify that unsupported authorization decisions are rejected."""
    with pytest.raises(ValueError):
        AuthorizationResult(
            target="example.com",
            decision="AUTHORIZED",
            provider="scopeguard",
            reference="test-scopeguard-reference",
        )


def test_empty_authorization_reference_is_rejected() -> None:
    """Verify that an empty authorization reference cannot be accepted."""
    with pytest.raises(ValueError):
        AuthorizationConfig(
            provider="scopeguard",
            reference="",
        )


def test_non_scopeguard_provider_is_rejected_by_adapter() -> None:
    """Verify that the ScopeGuard adapter rejects another provider."""
    adapter = ScopeGuardAdapter()

    authorization = AuthorizationConfig(
        provider="other-provider",
        reference="test-reference",
    )

    with pytest.raises(AuthorizationError):
        adapter.evaluate(
            target="example.com",
            authorization=authorization,
        )


def test_empty_target_is_rejected_by_adapter() -> None:
    """Verify that an empty target cannot be evaluated."""
    adapter = ScopeGuardAdapter()

    authorization = build_authorization_config()

    with pytest.raises(AuthorizationError):
        adapter.evaluate(
            target="   ",
            authorization=authorization,
        )


def test_placeholder_scopeguard_reference_is_never_authorized() -> None:
    """Verify that the default placeholder cannot authorize a target."""
    adapter = ScopeGuardAdapter()

    authorization = build_authorization_config(
        reference="REPLACE_WITH_SCOPEGUARD_REFERENCE",
    )

    with pytest.raises(AuthorizationError):
        adapter.evaluate(
            target="example.com",
            authorization=authorization,
        )


def test_scopeguard_integration_returns_in_scope() -> None:
    """Verify that Project 1 can authorize an included target."""
    adapter = ScopeGuardAdapter()

    authorization = build_authorization_config(
        reference="basic-scope-test",
        scope_file=str(PROJECT_1_SCOPE),
    )

    result = adapter.evaluate(
        target="example.com",
        authorization=authorization,
    )

    assert result.decision is AuthorizationDecision.IN_SCOPE
    assert result.is_authorized is True
    assert result.target == "example.com"
    assert result.provider == "scopeguard"


def test_scopeguard_integration_returns_out_of_scope() -> None:
    """Verify that Project 1 blocks an excluded target."""
    adapter = ScopeGuardAdapter()

    authorization = build_authorization_config(
        reference="basic-scope-test",
        scope_file=str(PROJECT_1_SCOPE),
    )

    result = adapter.evaluate(
        target="admin.example.com",
        authorization=authorization,
    )

    assert result.decision is AuthorizationDecision.OUT_OF_SCOPE
    assert result.is_authorized is False


def test_scopeguard_integration_supports_wildcard_rules() -> None:
    """Verify that Project 1 wildcard rules reach Project 2."""
    adapter = ScopeGuardAdapter()

    authorization = build_authorization_config(
        reference="basic-scope-test",
        scope_file=str(PROJECT_1_SCOPE),
    )

    result = adapter.evaluate(
        target="test.api.example.com",
        authorization=authorization,
    )

    assert result.decision is AuthorizationDecision.IN_SCOPE
    assert result.is_authorized is True


def test_missing_scope_file_fails_closed() -> None:
    """Verify that a missing ScopeGuard file cannot authorize a target."""
    adapter = ScopeGuardAdapter()

    authorization = build_authorization_config(
        reference="basic-scope-test",
        scope_file="does-not-exist.yaml",
    )

    with pytest.raises(AuthorizationError):
        adapter.evaluate(
            target="example.com",
            authorization=authorization,
        )