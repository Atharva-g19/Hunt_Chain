"""Execution policy for Hunt_Chain Project 2.

This module defines the runtime restrictions associated with the selected
Project 2 execution mode.

Execution policy is intentionally separate from authorization:

    ScopeGuard
        -> determines whether the target is authorized

    ExecutionPolicy
        -> determines which reconnaissance activities are permitted
           under the selected execution mode

Only ScopeGuard authorization may permit reconnaissance to begin.
ExecutionPolicy never grants authorization by itself.

V1 supports two execution modes:

- active:
    Permits all Project 2 V1 reconnaissance activities.

- passive_only:
    Permits passive discovery only. Activities that directly interact
    with target infrastructure, such as DNS resolution and HTTP probing,
    are denied.

This module performs no network activity.
"""

from __future__ import annotations

from enum import Enum

from hunt_chain_recon.config.models import ExecutionConfig


class ExecutionPolicyError(Exception):
    """Raised when a reconnaissance activity violates execution policy."""


class ExecutionActivity(str, Enum):
    """Reconnaissance activities recognized by the V1 execution policy."""

    PASSIVE_DISCOVERY = "PASSIVE_DISCOVERY"
    DNS_RESOLUTION = "DNS_RESOLUTION"
    HTTP_PROBING = "HTTP_PROBING"
    INFRASTRUCTURE_LOOKUP = "INFRASTRUCTURE_LOOKUP"


class ExecutionPolicy:
    """Enforce reconnaissance activity restrictions for an execution mode.

    The policy is derived entirely from the configured execution mode.

    It does not:
    - evaluate authorization,
    - contact ScopeGuard,
    - perform network requests,
    - execute providers,
    - determine whether an activity is safe in general.

    It only determines whether an activity is permitted by the selected
    Project 2 execution mode.
    """

    def __init__(self, config: ExecutionConfig) -> None:
        """Initialize the policy from the execution configuration.

        Args:
            config: Validated Project 2 execution configuration.
        """
        self._mode = config.mode

    @property
    def mode(self) -> str:
        """Return the configured execution mode."""
        return self._mode

    def allows(self, activity: ExecutionActivity) -> bool:
        """Return whether the activity is permitted by this policy.

        Active mode permits all V1 execution activities.

        Passive-only mode permits only passive discovery. Direct target
        interaction is denied.
        """
        if self._mode == "active":
            return True

        if self._mode == "passive_only":
            return activity is ExecutionActivity.PASSIVE_DISCOVERY

        return False

    def require_allowed(self, activity: ExecutionActivity) -> None:
        """Require an activity to be permitted by the current policy.

        Args:
            activity: Reconnaissance activity that is about to execute.

        Raises:
            ExecutionPolicyError: If the activity is not permitted.
        """
        if not self.allows(activity):
            raise ExecutionPolicyError(
                f"Execution activity '{activity.value}' is not permitted "
                f"in '{self._mode}' mode."
            )

    def permitted_activities(self) -> tuple[ExecutionActivity, ...]:
        """Return all activities permitted by the current execution mode."""
        return tuple(
            activity
            for activity in ExecutionActivity
            if self.allows(activity)
        )