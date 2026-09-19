"""ScopeGuard authorization adapter for Hunt_Chain Project 2.

The adapter provides the integration boundary between Project 2 and
Project 1 (ScopeGuard).

Project 1 remains responsible for scope loading, normalization,
matching, specificity, and authorization decisions.

Project 2 converts the resulting ScopeGuard decision into its own
AuthorizationResult model.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from hunt_chain_recon.authorization.models import (
    AuthorizationDecision,
    AuthorizationResult,
)
from hunt_chain_recon.config.models import AuthorizationConfig


class AuthorizationError(Exception):
    """Raised when an authorization decision cannot be obtained."""


class AuthorizationProvider(ABC):
    """Abstract interface for authorization decision providers."""

    @abstractmethod
    def evaluate(
        self,
        target: str,
        authorization: AuthorizationConfig,
    ) -> AuthorizationResult:
        """Evaluate authorization for the supplied target."""
        raise NotImplementedError


class ScopeGuardAdapter(AuthorizationProvider):
    """Adapter for Project 1 ScopeGuard authorization.

    Scope matching is delegated completely to Project 1.

    Project 2 only translates the resulting ScopeGuard decision into
    its own authorization model.
    """

    name = "scopeguard"

    def evaluate(
        self,
        target: str,
        authorization: AuthorizationConfig,
    ) -> AuthorizationResult:
        """Evaluate a target using Project 1 ScopeGuard."""

        normalized_target = target.strip().lower().rstrip(".")

        if not normalized_target:
            raise AuthorizationError(
                "Authorization cannot be evaluated for an empty target."
            )

        if authorization.provider.strip().lower() != self.name:
            raise AuthorizationError(
                "Configured authorization provider is not ScopeGuard."
            )

        if not authorization.reference.strip():
            raise AuthorizationError(
                "ScopeGuard authorization reference must not be empty."
            )

        if authorization.reference == (
            "REPLACE_WITH_SCOPEGUARD_REFERENCE"
        ):
            raise AuthorizationError(
                "A real ScopeGuard authorization reference is required "
                "before reconnaissance can execute."
            )

        if not authorization.scope_file:
            raise AuthorizationError(
                "A ScopeGuard scope file is required for integration."
            )

        scope_path = Path(authorization.scope_file)

        if not scope_path.exists():
            raise AuthorizationError(
                f"ScopeGuard scope file not found: {scope_path}"
            )

        if not scope_path.is_file():
            raise AuthorizationError(
                f"ScopeGuard scope path is not a file: {scope_path}"
            )

        try:
            from scopeguard.engine.scope_engine import ScopeEngine
            from scopeguard.loaders.yaml_scope_loader import (
                YamlScopeLoader,
            )
        except ImportError as exc:
            raise AuthorizationError(
                "Project 1 ScopeGuard is not available to Project 2."
            ) from exc

        try:
            scope = YamlScopeLoader().load(scope_path)
            decision = ScopeEngine().check(
                scope,
                normalized_target,
            )
        except Exception as exc:
            raise AuthorizationError(
                "ScopeGuard failed to evaluate the target."
            ) from exc

        decision_mapping = {
            "IN_SCOPE": AuthorizationDecision.IN_SCOPE,
            "OUT_OF_SCOPE": AuthorizationDecision.OUT_OF_SCOPE,
            "UNKNOWN": AuthorizationDecision.UNKNOWN,
            "CONFLICT": AuthorizationDecision.CONFLICT,
        }

        decision_state = decision.state.value

        try:
            project2_decision = decision_mapping[decision_state]
        except KeyError as exc:
            raise AuthorizationError(
                f"ScopeGuard returned an unsupported decision state: "
                f"{decision_state}"
            ) from exc

        return AuthorizationResult(
            target=normalized_target,
            decision=project2_decision,
            provider=self.name,
            reference=authorization.reference,
            reason=decision.reason,
            metadata={
                "scopeguard_scope_file": str(scope_path),
                "scopeguard_program": scope.program.name,
                "matched_rules": list(decision.matched_rules),
                "winning_rule": decision.winning_rule,
            },
        )
