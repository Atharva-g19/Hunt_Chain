"""Regression tests for the internal-to-V1 DNS serialization boundary."""

from __future__ import annotations

from hunt_chain_recon.models.dns import DNSObservation, DNSRecord
from hunt_chain_recon.output.json_writer import JSONOutputWriter


def test_dns_serialization_uses_stable_v1_field_names() -> None:
    document = {
        "dns_observations": [
            DNSObservation(
                hostname="example.com",
                status="RESOLVED",
                records=[DNSRecord(record_type="A", value="192.0.2.1")],
            ).model_dump(mode="json")
        ]
    }

    JSONOutputWriter._normalize_dns_observations(document)

    observation = document["dns_observations"][0]
    assert observation["state"] == "RESOLVED"
    assert "status" not in observation
    assert "observed_at" in observation
    assert observation["records"][0]["type"] == "A"
    assert "record_type" not in observation["records"][0]
