"""Tests for the Hunt_Chain Project 2 JSON output writer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hunt_chain_recon.models.attack_surface import AttackSurface
from hunt_chain_recon.output.json_writer import (
    JSONOutputError,
    JSONOutputWriter,
    JSONSchemaValidationError,
)


def build_attack_surface() -> AttackSurface:
    """Build a minimal valid AttackSurface for output tests."""
    from hunt_chain_recon.models.run import ReconRun

    target = "example.com"

    run = ReconRun.create(
        target=target,
    )

    return AttackSurface(
        schema_version="v1",
        run=run,
        target={
            "value": target,
            "type": "DOMAIN",
        },
        authorization={
            "provider": "scopeguard",
            "reference": "test-reference",
        },
        execution={
            "mode": "active",
        },
        assets=[],
        dns_observations=[],
        services=[],
        endpoints=[],
        http_observations=[],
        technologies=[],
        technology_evidence=[],
        indicators=[],
        relationships=[],
        metadata={
            "test": True,
        },
    )


def test_serialize_returns_json_compatible_dictionary() -> None:
    """Serialization must produce JSON-compatible data."""
    writer = JSONOutputWriter()
    attack_surface = build_attack_surface()

    document = writer.serialize(
        attack_surface
    )

    assert isinstance(
        document,
        dict,
    )

    assert document["schema_version"] == "v1"
    assert document["target"]["value"] == "example.com"
    assert document["target"]["type"] == "DOMAIN"


def test_serialize_can_be_encoded_as_json() -> None:
    """Serialized output must be directly JSON serializable."""
    writer = JSONOutputWriter()
    attack_surface = build_attack_surface()

    document = writer.serialize(
        attack_surface
    )

    encoded = json.dumps(
        document
    )

    assert isinstance(
        encoded,
        str,
    )


def test_validate_accepts_valid_document() -> None:
    """A valid Attack Surface document must pass schema validation."""
    writer = JSONOutputWriter()
    attack_surface = build_attack_surface()

    document = writer.serialize(
        attack_surface
    )

    writer.validate(
        document
    )


def test_validate_rejects_unknown_top_level_field() -> None:
    """Schema validation must reject undeclared top-level fields."""
    writer = JSONOutputWriter()
    attack_surface = build_attack_surface()

    document = writer.serialize(
        attack_surface
    )
    document["unexpected"] = "invalid"

    with pytest.raises(
        JSONSchemaValidationError,
        match="unexpected",
    ):
        writer.validate(
            document
        )


def test_validate_rejects_invalid_schema_version() -> None:
    """Schema validation must reject unsupported schema versions."""
    writer = JSONOutputWriter()
    attack_surface = build_attack_surface()

    document = writer.serialize(
        attack_surface
    )
    document["schema_version"] = "v2"

    with pytest.raises(
        JSONSchemaValidationError,
        match="v1",
    ):
        writer.validate(
            document
        )


def test_validate_rejects_invalid_uuid() -> None:
    """Schema validation must reject malformed UUID values."""
    writer = JSONOutputWriter()
    attack_surface = build_attack_surface()

    document = writer.serialize(
        attack_surface
    )
    document["run"]["id"] = "invalid-uuid"

    with pytest.raises(
        JSONSchemaValidationError,
    ):
        writer.validate(
            document
        )


def test_write_creates_output_file(
    tmp_path: Path,
) -> None:
    """Writing must create the requested JSON output file."""
    writer = JSONOutputWriter()
    attack_surface = build_attack_surface()

    output_path = tmp_path / "attack_surface.json"

    result = writer.write(
        attack_surface,
        output_path,
    )

    assert result == output_path
    assert output_path.is_file()


def test_write_creates_parent_directories(
    tmp_path: Path,
) -> None:
    """Writing must create missing parent directories."""
    writer = JSONOutputWriter()
    attack_surface = build_attack_surface()

    output_path = (
        tmp_path
        / "nested"
        / "output"
        / "attack_surface.json"
    )

    writer.write(
        attack_surface,
        output_path,
    )

    assert output_path.is_file()


def test_written_file_contains_valid_json(
    tmp_path: Path,
) -> None:
    """The written file must contain valid JSON."""
    writer = JSONOutputWriter()
    attack_surface = build_attack_surface()

    output_path = tmp_path / "attack_surface.json"

    writer.write(
        attack_surface,
        output_path,
    )

    with output_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        document = json.load(
            file
        )

    assert document["schema_version"] == "v1"
    assert document["target"]["value"] == "example.com"
    assert document["metadata"]["test"] is True


def test_written_document_round_trips_through_model(
    tmp_path: Path,
) -> None:
    """Written JSON must be reconstructable as AttackSurface."""
    writer = JSONOutputWriter()
    attack_surface = build_attack_surface()

    output_path = tmp_path / "attack_surface.json"

    writer.write(
        attack_surface,
        output_path,
    )

    with output_path.open(
        "r",
        encoding="utf-8",
    ) as file:
        document = json.load(
            file
        )

    reconstructed = AttackSurface.model_validate(
        document
    )

    assert reconstructed.schema_version == "v1"
    assert reconstructed.run.target == "example.com"
    assert reconstructed.target.value == "example.com"


def test_missing_schema_raises_output_error(
    tmp_path: Path,
) -> None:
    """A missing schema must prevent output validation."""
    missing_schema = (
        tmp_path
        / "missing"
        / "attack_surface_v1.json"
    )

    writer = JSONOutputWriter(
        schema_path=missing_schema
    )

    attack_surface = build_attack_surface()

    with pytest.raises(
        JSONOutputError,
        match="schema not found",
    ):
        writer.write(
            attack_surface,
            tmp_path / "attack_surface.json",
        )


def test_non_attack_surface_input_is_rejected() -> None:
    """The writer must require an AttackSurface instance."""
    writer = JSONOutputWriter()

    with pytest.raises(
        TypeError,
        match="AttackSurface",
    ):
        writer.serialize(
            {"schema_version": "v1"}  # type: ignore[arg-type]
        )