"""DNS observation models for Hunt_Chain Project 2.

This module defines the normalized representation of DNS observations.

V1 deliberately preserves unsuccessful DNS states:

    RESOLVED
    UNRESOLVED
    TIMEOUT
    ERROR

A failed DNS lookup does not mean that the corresponding hostname should
be removed from the attack surface.

DNS observations are observations, not vulnerability conclusions.

This module performs no DNS queries and no network activity.
"""

from __future__ import annotations

from enum import Enum
from uuid import UUID, uuid4

from pydantic import AliasChoices, BaseModel, ConfigDict, Field


class DNSResolutionStatus(str, Enum):
    """Result state of a DNS resolution attempt."""

    RESOLVED = "RESOLVED"
    UNRESOLVED = "UNRESOLVED"
    TIMEOUT = "TIMEOUT"
    ERROR = "ERROR"


class DNSRecordType(str, Enum):
    """DNS record types supported by Project 2 V1."""

    A = "A"
    AAAA = "AAAA"
    CNAME = "CNAME"


class DNSRecord(BaseModel):
    """A single normalized DNS record observation."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
    )

    record_type: DNSRecordType = Field(
        validation_alias=AliasChoices("record_type", "type"),
    )
    value: str = Field(min_length=1)
    ttl: int | None = Field(
        default=None,
        ge=0,
    )

    @property
    def type(self) -> DNSRecordType:
        """Backward-compatible alias for the record type."""
        return self.record_type

    @type.setter
    def type(self, value: DNSRecordType | str) -> None:
        """Allow assignment via the older field name."""
        self.record_type = DNSRecordType(value) if isinstance(value, str) else value


class DNSObservation(BaseModel):
    """Normalized DNS observation for a hostname."""

    model_config = ConfigDict(
        extra="forbid",
        validate_assignment=True,
    )

    id: UUID = Field(
        default_factory=uuid4,
        description="Unique identifier for the DNS observation.",
    )

    asset_id: UUID | None = Field(
        default=None,
        description="Identifier of the asset associated with this DNS observation.",
    )

    hostname: str = Field(min_length=1)
    status: DNSResolutionStatus = Field(
        validation_alias=AliasChoices("status", "state"),
    )
    records: list[DNSRecord] = Field(
        default_factory=list
    )
    error: str | None = None

    @property
    def state(self) -> DNSResolutionStatus:
        """Backward-compatible alias for resolution status."""
        return self.status

    @state.setter
    def state(self, value: DNSResolutionStatus | str) -> None:
        """Allow assignment via the older field name."""
        self.status = DNSResolutionStatus(value) if isinstance(value, str) else value

    def has_records(self) -> bool:
        """Return whether the observation contains DNS records."""
        return bool(self.records)

    def cname_records(self) -> list[DNSRecord]:
        """Return all observed CNAME records."""
        return [
            record
            for record in self.records
            if record.record_type is DNSRecordType.CNAME
        ]

    def address_records(self) -> list[DNSRecord]:
        """Return A and AAAA records."""
        return [
            record
            for record in self.records
            if record.record_type in {
                DNSRecordType.A,
                DNSRecordType.AAAA,
            }
        ]