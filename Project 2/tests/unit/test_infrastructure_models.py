"""Tests for infrastructure observation models."""

from __future__ import annotations

from uuid import UUID

import pytest
from pydantic import ValidationError

from hunt_chain_recon.models.infrastructure import (
    InfrastructureConfidence,
    InfrastructureObservation,
    InfrastructureObservationType,
)


def test_shared_ip_observation() -> None:
    """A shared-IP observation is represented correctly."""
    observation = InfrastructureObservation(
        observation_type="SHARED_IP",
        ip_address="192.0.2.10",
        value="3 hostnames",
        evidence="Three authorized hostnames resolve to the same IP.",
        confidence="HIGH",
    )

    assert observation.observation_type == (
        InfrastructureObservationType.SHARED_IP
    )
    assert observation.ip_address == "192.0.2.10"
    assert observation.confidence == InfrastructureConfidence.HIGH
    assert isinstance(observation.id, UUID)


def test_provider_observation() -> None:
    """A provider observation is represented correctly."""
    observation = InfrastructureObservation(
        observation_type="PROVIDER",
        ip_address="192.0.2.20",
        value="Example Provider",
        evidence="Provider metadata identified the observed IP.",
        confidence="MEDIUM",
    )

    assert observation.observation_type == (
        InfrastructureObservationType.PROVIDER
    )
    assert observation.value == "Example Provider"


def test_observation_type_is_normalized() -> None:
    """Observation type strings are normalized."""
    observation = InfrastructureObservation(
        observation_type=" provider ",
        value="Example Provider",
        evidence="Provider metadata.",
        confidence=" low ",
    )

    assert observation.observation_type == (
        InfrastructureObservationType.PROVIDER
    )
    assert observation.confidence == InfrastructureConfidence.LOW


def test_empty_value_is_rejected() -> None:
    """Required observation values cannot be empty."""
    with pytest.raises(ValidationError):
        InfrastructureObservation(
            observation_type="OTHER",
            value="   ",
            evidence="Evidence.",
            confidence="LOW",
        )


def test_empty_evidence_is_rejected() -> None:
    """Required evidence cannot be empty."""
    with pytest.raises(ValidationError):
        InfrastructureObservation(
            observation_type="OTHER",
            value="Example",
            evidence="   ",
            confidence="LOW",
        )


def test_invalid_confidence_is_rejected() -> None:
    """Only V1 confidence tiers are accepted."""
    with pytest.raises(ValidationError):
        InfrastructureObservation(
            observation_type="OTHER",
            value="Example",
            evidence="Evidence.",
            confidence="UNKNOWN",
        )


def test_extra_fields_are_rejected() -> None:
    """The infrastructure model remains strict."""
    with pytest.raises(ValidationError):
        InfrastructureObservation(
            observation_type="OTHER",
            value="Example",
            evidence="Evidence.",
            confidence="LOW",
            vulnerability="confirmed",
        )


def test_optional_ip_address_can_be_omitted() -> None:
    """Some provider observations may not map directly to an IP."""
    observation = InfrastructureObservation(
        observation_type="PROVIDER",
        value="Example Provider",
        evidence="Provider metadata.",
        confidence="MEDIUM",
    )

    assert observation.ip_address is None


def test_ip_address_is_normalized() -> None:
    """Optional IP addresses are whitespace-normalized."""
    observation = InfrastructureObservation(
        observation_type="OTHER",
        ip_address=" 192.0.2.50 ",
        value="Example",
        evidence="Observed metadata.",
        confidence="LOW",
    )

    assert observation.ip_address == "192.0.2.50"