"""Network politeness controller for Hunt_Chain Project 2.

This module provides the central politeness interface used by active
reconnaissance providers.

Politeness is deliberately separated from individual providers so that
providers cannot accidentally implement inconsistent request-rate or
concurrency behavior.

The controller currently provides:

- request-rate limiting,
- concurrent-operation limiting,
- explicit acquire/release operations.

It performs no network activity.

Authorization remains the responsibility of ScopeGuard and the pipeline.
Execution mode restrictions remain the responsibility of ExecutionPolicy.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from hunt_chain_recon.config.models import PolitenessConfig
from hunt_chain_recon.policy.rate_limiter import RateLimiter


class PolitenessError(Exception):
    """Raised when an invalid politeness operation occurs."""


class PolitenessController:
    """Coordinate request-rate and concurrency limits.

    The controller combines two independent controls:

    1. Rate limiting:
       Controls how frequently operations may begin.

    2. Concurrency limiting:
       Controls how many operations may be active simultaneously.

    Providers should use this controller instead of implementing their
    own independent rate or concurrency controls.
    """

    def __init__(self, config: PolitenessConfig) -> None:
        """Initialize the politeness controller.

        Args:
            config: Validated Project 2 politeness configuration.
        """
        self._concurrency_limit = config.concurrency
        self._semaphore = threading.BoundedSemaphore(
            self._concurrency_limit
        )
        self._rate_limiter = RateLimiter(
            config.requests_per_second
        )

    @property
    def concurrency_limit(self) -> int:
        """Return the configured maximum concurrency."""
        return self._concurrency_limit

    @property
    def requests_per_second(self) -> float:
        """Return the configured request rate."""
        return 1.0 / self._rate_limiter.interval_seconds

    @property
    def interval_seconds(self) -> float:
        """Return the minimum interval between operation starts."""
        return self._rate_limiter.interval_seconds

    def acquire(self) -> None:
        """Acquire permission for one operation.

        Rate limiting is applied before the concurrency slot is acquired.

        The caller must eventually call ``release`` after the operation
        finishes.
        """
        self._rate_limiter.acquire()

        acquired = self._semaphore.acquire()

        if not acquired:
            raise PolitenessError(
                "Unable to acquire a concurrency slot."
            )

    def release(self) -> None:
        """Release a previously acquired concurrency slot."""
        try:
            self._semaphore.release()
        except ValueError as exc:
            raise PolitenessError(
                "Cannot release a concurrency slot that was not acquired."
            ) from exc

    @contextmanager
    def operation(self) -> Iterator[None]:
        """Provide a context manager for one polite operation.

        The concurrency slot is always released when the context exits,
        including when the wrapped operation raises an exception.

        Example:

            with politeness.operation():
                perform_network_operation()
        """
        self.acquire()

        try:
            yield
        finally:
            self.release()