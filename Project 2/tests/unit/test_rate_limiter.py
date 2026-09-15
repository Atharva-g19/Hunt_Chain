"""Unit tests for the Hunt_Chain Project 2 rate limiter.

These tests use injected clock and sleeper functions so no real waiting
or network activity occurs.
"""

from __future__ import annotations

import pytest

from hunt_chain_recon.policy import RateLimitError, RateLimiter


class FakeClock:
    """Deterministic monotonic clock for rate-limiter tests."""

    def __init__(self, value: float = 0.0) -> None:
        """Initialize the fake clock."""
        self.value = value

    def now(self) -> float:
        """Return the current fake time."""
        return self.value

    def sleep(self, seconds: float) -> None:
        """Advance fake time instead of actually sleeping."""
        self.value += seconds


def test_rate_limiter_calculates_interval() -> None:
    """Verify that the configured rate produces the expected interval."""
    limiter = RateLimiter(2.0)

    assert limiter.interval_seconds == pytest.approx(0.5)


def test_first_acquire_does_not_sleep() -> None:
    """Verify that the first request can proceed immediately."""
    clock = FakeClock()
    sleep_calls: list[float] = []

    def sleeper(seconds: float) -> None:
        sleep_calls.append(seconds)
        clock.value += seconds

    limiter = RateLimiter(
        2.0,
        clock=clock.now,
        sleeper=sleeper,
    )

    limiter.acquire()

    assert sleep_calls == []
    assert clock.value == pytest.approx(0.0)


def test_second_acquire_waits_for_required_interval() -> None:
    """Verify that consecutive requests are separated by the rate interval."""
    clock = FakeClock()
    sleep_calls: list[float] = []

    def sleeper(seconds: float) -> None:
        sleep_calls.append(seconds)
        clock.value += seconds

    limiter = RateLimiter(
        2.0,
        clock=clock.now,
        sleeper=sleeper,
    )

    limiter.acquire()
    limiter.acquire()

    assert sleep_calls == [pytest.approx(0.5)]


def test_multiple_acquires_maintain_rate_spacing() -> None:
    """Verify that repeated requests maintain the configured spacing."""
    clock = FakeClock()
    sleep_calls: list[float] = []

    def sleeper(seconds: float) -> None:
        sleep_calls.append(seconds)
        clock.value += seconds

    limiter = RateLimiter(
        2.0,
        clock=clock.now,
        sleeper=sleeper,
    )

    limiter.acquire()
    limiter.acquire()
    limiter.acquire()

    assert sleep_calls == [
        pytest.approx(0.5),
        pytest.approx(0.5),
    ]


def test_reset_allows_next_request_immediately() -> None:
    """Verify that resetting removes the previously reserved request slot."""
    clock = FakeClock()
    sleep_calls: list[float] = []

    def sleeper(seconds: float) -> None:
        sleep_calls.append(seconds)
        clock.value += seconds

    limiter = RateLimiter(
        2.0,
        clock=clock.now,
        sleeper=sleeper,
    )

    limiter.acquire()
    limiter.reset()
    limiter.acquire()

    assert sleep_calls == []


@pytest.mark.parametrize(
    "requests_per_second",
    [
        0,
        -1,
        -10.0,
    ],
)
def test_non_positive_rate_is_rejected(
    requests_per_second: float,
) -> None:
    """Verify that invalid request rates are rejected."""
    with pytest.raises(RateLimitError):
        RateLimiter(requests_per_second)


def test_higher_rate_produces_smaller_interval() -> None:
    """Verify that increasing the rate decreases the interval."""
    slow_limiter = RateLimiter(2.0)
    fast_limiter = RateLimiter(10.0)

    assert slow_limiter.interval_seconds == pytest.approx(0.5)
    assert fast_limiter.interval_seconds == pytest.approx(0.1)
    assert fast_limiter.interval_seconds < slow_limiter.interval_seconds