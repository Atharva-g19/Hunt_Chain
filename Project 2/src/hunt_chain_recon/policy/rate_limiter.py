"""Request-rate limiting for Hunt_Chain Project 2.

This module implements the V1 request-rate control used by Project 2's
politeness layer.

The rate limiter:

- enforces a configurable maximum request rate,
- uses a monotonic clock,
- is safe to use from multiple threads,
- performs no network activity,
- is independent of any particular provider,
- does not determine authorization.

Authorization remains the responsibility of ScopeGuard and the pipeline
execution policy.

V1 uses a simple interval-based limiter. For a configured rate of
``2 requests per second``, the limiter maintains approximately ``0.5``
seconds between permitted request starts.
"""

from __future__ import annotations

import threading
import time


class RateLimitError(Exception):
    """Raised when an invalid rate-limit configuration is supplied."""


class RateLimiter:
    """Thread-safe interval-based request-rate limiter.

    The limiter controls the spacing between request starts.

    It does not perform the request itself.

    Example:

        limiter = RateLimiter(2.0)

        limiter.acquire()
        perform_request()

        limiter.acquire()
        perform_request()

    With a rate of 2 requests per second, the second acquire may wait
    approximately 0.5 seconds depending on timing.
    """

    def __init__(
        self,
        requests_per_second: float,
        clock: callable = time.monotonic,
        sleeper: callable = time.sleep,
    ) -> None:
        """Initialize the rate limiter.

        Args:
            requests_per_second: Maximum permitted request-start rate.
            clock: Monotonic clock function, injectable for deterministic
                testing.
            sleeper: Sleep function, injectable for deterministic testing.

        Raises:
            RateLimitError: If the configured rate is not positive.
        """
        if requests_per_second <= 0:
            raise RateLimitError(
                "requests_per_second must be greater than zero."
            )

        self._interval = 1.0 / requests_per_second
        self._clock = clock
        self._sleeper = sleeper
        self._lock = threading.Lock()
        self._next_allowed_at: float | None = None

    @property
    def interval_seconds(self) -> float:
        """Return the minimum interval between request starts."""
        return self._interval

    def acquire(self) -> None:
        """Wait until the next request start is permitted.

        The calculation and reservation of the next request slot are
        protected by a lock so concurrent callers cannot reserve the same
        request slot.

        No network operation is performed by this method.
        """
        with self._lock:
            now = self._clock()

            if self._next_allowed_at is None:
                self._next_allowed_at = now + self._interval
                return

            wait_seconds = self._next_allowed_at - now

            if wait_seconds > 0:
                self._sleeper(wait_seconds)
                now = self._clock()

            self._next_allowed_at = max(
                self._next_allowed_at + self._interval,
                now + self._interval,
            )

    def reset(self) -> None:
        """Reset the limiter so the next acquire can proceed immediately."""
        with self._lock:
            self._next_allowed_at = None