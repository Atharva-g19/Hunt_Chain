"""Tests for Hunt_Chain Project 2 DNS observation models."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from hunt_chain_recon.models.dns import (
    DNSObservation,
    DNSRecord,
    DNSRecordType,
    DNSResolutionStatus,
)


def test_dns_record_supports_a_record():
    """A records are represented correctly."""
    record = DNSRecord(
        record_type=DNSRecordType.A,
        value="192.168.1.10",
        ttl=300,
    )

    assert record.record_type is DNSRecordType.A
    assert record.value == "192.168.1.10"
    assert record.ttl == 300


def test_dns_record_supports_aaaa_record():
    """AAAA records are represented correctly."""
    record = DNSRecord(
        record_type=DNSRecordType.AAAA,
        value="2001:db8::1",
        ttl=600,
    )

    assert record.record_type is DNSRecordType.AAAA
    assert record.value == "2001:db8::1"
    assert record.ttl == 600


def test_dns_record_supports_cname_record():
    """CNAME records are represented correctly."""
    record = DNSRecord(
        record_type=DNSRecordType.CNAME,
        value="target.example.net",
        ttl=120,
    )

    assert record.record_type is DNSRecordType.CNAME
    assert record.value == "target.example.net"
    assert record.ttl == 120


def test_dns_record_ttl_is_optional():
    """DNS TTL may be unavailable."""
    record = DNSRecord(
        record_type=DNSRecordType.A,
        value="192.168.1.10",
    )

    assert record.ttl is None


def test_dns_record_rejects_empty_value():
    """DNS record values cannot be empty."""
    with pytest.raises(ValidationError):
        DNSRecord(
            record_type=DNSRecordType.A,
            value="",
        )


def test_dns_record_rejects_negative_ttl():
    """DNS TTL cannot be negative."""
    with pytest.raises(ValidationError):
        DNSRecord(
            record_type=DNSRecordType.A,
            value="192.168.1.10",
            ttl=-1,
        )


def test_dns_observation_resolved_state():
    """Resolved DNS observations are represented correctly."""
    observation = DNSObservation(
        hostname="api.example.com",
        status=DNSResolutionStatus.RESOLVED,
        records=[
            DNSRecord(
                record_type=DNSRecordType.A,
                value="192.168.1.10",
            )
        ],
    )

    assert observation.hostname == "api.example.com"
    assert observation.status is DNSResolutionStatus.RESOLVED
    assert observation.has_records() is True
    assert observation.error is None


def test_dns_observation_unresolved_state():
    """Unresolved hostnames are preserved."""
    observation = DNSObservation(
        hostname="missing.example.com",
        status=DNSResolutionStatus.UNRESOLVED,
    )

    assert observation.status is DNSResolutionStatus.UNRESOLVED
    assert observation.has_records() is False
    assert observation.records == []


def test_dns_observation_timeout_state():
    """DNS timeout state is preserved."""
    observation = DNSObservation(
        hostname="slow.example.com",
        status=DNSResolutionStatus.TIMEOUT,
        error="DNS resolution timed out.",
    )

    assert observation.status is DNSResolutionStatus.TIMEOUT
    assert observation.error == "DNS resolution timed out."


def test_dns_observation_error_state():
    """DNS resolver errors are preserved."""
    observation = DNSObservation(
        hostname="broken.example.com",
        status=DNSResolutionStatus.ERROR,
        error="Resolver failure.",
    )

    assert observation.status is DNSResolutionStatus.ERROR
    assert observation.error == "Resolver failure."


def test_dns_observation_cname_records():
    """CNAME records can be extracted from an observation."""
    observation = DNSObservation(
        hostname="app.example.com",
        status=DNSResolutionStatus.RESOLVED,
        records=[
            DNSRecord(
                record_type=DNSRecordType.CNAME,
                value="app.example.net",
            ),
            DNSRecord(
                record_type=DNSRecordType.A,
                value="192.168.1.10",
            ),
        ],
    )

    cname_records = observation.cname_records()

    assert len(cname_records) == 1
    assert cname_records[0].value == "app.example.net"


def test_dns_observation_address_records():
    """A and AAAA records can be extracted."""
    observation = DNSObservation(
        hostname="dual.example.com",
        status=DNSResolutionStatus.RESOLVED,
        records=[
            DNSRecord(
                record_type=DNSRecordType.A,
                value="192.168.1.10",
            ),
            DNSRecord(
                record_type=DNSRecordType.AAAA,
                value="2001:db8::1",
            ),
            DNSRecord(
                record_type=DNSRecordType.CNAME,
                value="dual.example.net",
            ),
        ],
    )

    address_records = observation.address_records()

    assert len(address_records) == 2

    assert {
        record.record_type
        for record in address_records
    } == {
        DNSRecordType.A,
        DNSRecordType.AAAA,
    }


def test_dns_observation_without_records_has_no_addresses():
    """An observation without records returns no address records."""
    observation = DNSObservation(
        hostname="missing.example.com",
        status=DNSResolutionStatus.UNRESOLVED,
    )

    assert observation.address_records() == []


def test_dns_observation_without_records_has_no_cnames():
    """An observation without records returns no CNAME records."""
    observation = DNSObservation(
        hostname="missing.example.com",
        status=DNSResolutionStatus.UNRESOLVED,
    )

    assert observation.cname_records() == []


def test_dns_observation_rejects_empty_hostname():
    """DNS observations require a hostname."""
    with pytest.raises(ValidationError):
        DNSObservation(
            hostname="",
            status=DNSResolutionStatus.UNRESOLVED,
        )


def test_dns_observation_rejects_negative_record_ttl():
    """Nested DNS record validation is enforced."""
    with pytest.raises(ValidationError):
        DNSObservation(
            hostname="example.com",
            status=DNSResolutionStatus.RESOLVED,
            records=[
                DNSRecord(
                    record_type=DNSRecordType.A,
                    value="192.168.1.10",
                    ttl=-10,
                )
            ],
        )


def test_dns_model_forbids_unknown_record_fields():
    """DNS records reject undeclared fields."""
    with pytest.raises(ValidationError):
        DNSRecord(
            record_type=DNSRecordType.A,
            value="192.168.1.10",
            unexpected="value",
        )


def test_dns_model_forbids_unknown_observation_fields():
    """DNS observations reject undeclared fields."""
    with pytest.raises(ValidationError):
        DNSObservation(
            hostname="example.com",
            status=DNSResolutionStatus.RESOLVED,
            unexpected="value",
        )


def test_dns_observation_model_dump_uses_v1_values():
    """Serialized DNS observations use stable enum values."""
    observation = DNSObservation(
        hostname="example.com",
        status=DNSResolutionStatus.RESOLVED,
        records=[
            DNSRecord(
                record_type=DNSRecordType.A,
                value="192.168.1.10",
                ttl=300,
            )
        ],
    )

    dumped = observation.model_dump()

    assert dumped["hostname"] == "example.com"
    assert dumped["status"] == "RESOLVED"
    assert dumped["records"][0]["record_type"] == "A"
    assert dumped["records"][0]["value"] == "192.168.1.10"
    assert dumped["records"][0]["ttl"] == 300