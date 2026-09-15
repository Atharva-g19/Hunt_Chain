"""Pipeline execution context for Hunt_Chain Project 2.

The PipelineContext carries the validated state required by Project 2
pipeline stages.

The context connects:

    Configuration
        +
    ScopeGuard authorization result
        +
    Execution policy
        +
    Politeness controller
        +
    Reconnaissance run metadata

Pipeline stages consume this context rather than independently deciding
whether a target is authorized, which execution mode applies, or how
network politeness should be enforced.

This module performs no network activity and does not execute providers.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from hunt_chain_recon.authorization.models import AuthorizationResult
from hunt_chain_recon.config.models import ReconConfig
from hunt_chain_recon.models.run import ReconRun
from hunt_chain_recon.policy.execution import ExecutionPolicy
from hunt_chain_recon.policy.politeness import PolitenessController


@dataclass
class PipelineContext:
    """Runtime context shared by Project 2 pipeline stages.

    The context represents a single reconnaissance execution.

    Authorization is explicitly represented by ``authorization``.
    Execution restrictions are represented by ``execution_policy``.
    Network politeness is represented by ``politeness``.

    A pipeline stage must not bypass these objects and independently
    decide whether reconnaissance is permitted or how request limits
    should be applied.
    """

    config: ReconConfig
    authorization: AuthorizationResult
    execution_policy: ExecutionPolicy
    politeness: PolitenessController
    run: ReconRun

    state: dict[str, object] = field(default_factory=dict)

    def is_authorized(self) -> bool:
        """Return whether the ScopeGuard result permits reconnaissance."""
        return self.authorization.is_authorized

    def require_authorized(self) -> None:
        """Require an authorized target before pipeline execution.

        Raises:
            PermissionError: If the authorization result is not IN_SCOPE.
        """
        if not self.is_authorized():
            raise PermissionError(
                "Pipeline execution is blocked because the target is not "
                "authorized by ScopeGuard."
            )

    def target(self) -> str:
        """Return the normalized target associated with this pipeline run."""
        return self.config.target.value.strip().lower().rstrip(".")

    def set_state(self, key: str, value: object) -> None:
        """Store pipeline state for later stages.

        Pipeline state is intentionally generic at this layer. Domain
        observations should remain in the appropriate Project 2 models.
        """
        normalized_key = key.strip()

        if not normalized_key:
            raise ValueError("Pipeline state key must not be empty.")

        self.state[normalized_key] = value

    def get_state(self, key: str) -> object | None:
        """Return a stored pipeline state value, if present."""
        normalized_key = key.strip()

        if not normalized_key:
            raise ValueError("Pipeline state key must not be empty.")

        return self.state.get(normalized_key)