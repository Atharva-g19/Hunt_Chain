"""Unit tests for the Hunt_Chain Project 2 politeness controller.

These tests perform no network activity.

Rate-limiter behavior is tested using injected deterministic timing,
while concurrency behavior uses the controller's real semaphore with
short-lived local operations.
"""

from __future__ import annotations

import threading
import time

import pytest

from hunt_chain_recon.config.models import PolitenessConfig
from hunt_chain_recon.policy.politeness import (
    PolitenessController,
    PolitenessError,
)
from hunt_chain_recon.policy.rate_limiter import RateLimiter


class FakeClock:
    """Deterministic monotonic clock for politeness tests."""

    def __init__(self, value: float = 0.0) -> None:
        """Initialize the fake clock."""
        self.value = value

    def now(self) -> float:
        """Return the current fake time."""
        return self.value

    def sleep(self, seconds: float) -> None:
        """Advance fake time without actually sleeping."""
        self.value += seconds


def build_config(
    concurrency: int = 5,
    requests_per_second: float = 2.0,
) -> PolitenessConfig:
    """Build a deterministic politeness configuration."""
    return PolitenessConfig(
        concurrency=concurrency,
        requests_per_second=requests_per_second,
        timeout_seconds=10.0,
    )


def test_controller_exposes_configured_limits() -> None:
    """Verify that configured limits are exposed correctly."""
    controller = PolitenessController(
        build_config(
            concurrency=5,
            requests_per_second=2.0,
        )
    )

    assert controller.concurrency_limit == 5
    assert controller.requests_per_second == pytest.approx(2.0)
    assert controller.interval_seconds == pytest.approx(0.5)


def test_controller_acquire_and_release() -> None:
    """Verify that a normal operation can acquire and release a slot."""
    controller = PolitenessController(
        build_config(
            concurrency=1,
            requests_per_second=100.0,
        )
    )

    controller.acquire()
    controller.release()


def test_operation_context_releases_slot_after_success() -> None:
    """Verify that operation() releases its slot after success."""
    controller = PolitenessController(
        build_config(
            concurrency=1,
            requests_per_second=100.0,
        )
    )

    with controller.operation():
        pass

    controller.acquire()
    controller.release()


def test_operation_context_releases_slot_after_exception() -> None:
    """Verify that operation() releases its slot after an exception."""
    controller = PolitenessController(
        build_config(
            concurrency=1,
            requests_per_second=100.0,
        )
    )

    with pytest.raises(RuntimeError):
        with controller.operation():
            raise RuntimeError("simulated operation failure")

    controller.acquire()
    controller.release()


def test_second_concurrent_operation_waits_for_available_slot() -> None:
    """Verify that concurrency=1 prevents simultaneous operations."""
    controller = PolitenessController(
        build_config(
            concurrency=1,
            requests_per_second=100.0,
        )
    )

    first_acquired = threading.Event()
    release_first = threading.Event()
    second_acquired = threading.Event()

    def first_operation() -> None:
        """Hold the only concurrency slot."""
        with controller.operation():
            first_acquired.set()
            release_first.wait(timeout=2.0)

    def second_operation() -> None:
        """Attempt to acquire the occupied slot."""
        with controller.operation():
            second_acquired.set()

    first_thread = threading.Thread(target=first_operation)
    second_thread = threading.Thread(target=second_operation)

    first_thread.start()

    assert first_acquired.wait(timeout=2.0)

    second_thread.start()

    time.sleep(0.05)

    assert second_acquired.is_set() is False

    release_first.set()

    first_thread.join(timeout=2.0)
    second_thread.join(timeout=2.0)

    assert first_thread.is_alive() is False
    assert second_thread.is_alive() is False
    assert second_acquired.is_set() is True


def test_invalid_release_is_rejected() -> None:
    """Verify that releasing without acquiring a slot fails."""
    controller = PolitenessController(
        build_config(
            concurrency=1,
            requests_per_second=100.0,
        )
    )

    with pytest.raises(PolitenessError):
        controller.release()


def test_rate_limiter_is_used_by_controller() -> None:
    """Verify the controller's rate configuration matches its limiter."""
    fake_clock = FakeClock()
    sleep_calls: list[float] = []

    def sleeper(seconds: float) -> None:
        sleep_calls.append(seconds)
        fake_clock.value += seconds

    rate_limiter = RateLimiter(
        2.0,
        clock=fake_clock.now,
        sleeper=sleeper,
    )

    assert rate_limiter.interval_seconds == pytest.approx(0.5)

    rate_limiter.acquire()
    rate_limiter.acquire()

    assert sleep_calls == [pytest.approx(0.5)]