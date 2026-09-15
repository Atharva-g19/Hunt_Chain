"""Tests for the Hunt_Chain Project 2 Attack Surface Model V1 schema."""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from jsonschema import Draft202012Validator, FormatChecker

from hunt_chain_recon.models.attack_surface import AttackSurface
from hunt_chain_recon.models.run import ReconRun


SCHEMA_PATH = (
    Path(__file__).resolve().parents[2]
    / "schemas"
    / "attack_surface_v1.json"
)


def load_schema() -> dict:
    """Load the Attack Surface Model V1 JSON schema."""
    with SCHEMA_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        return json.load(file)


def build_minimal_attack_surface() -> AttackSurface:
    """Build the smallest valid AttackSurface model."""
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
        metadata={},
    )


def validate_attack_surface(instance: dict) -> list[str]:
    """Return JSON Schema validation errors for an instance."""
    validator = Draft202012Validator(
        load_schema(),
        format_checker=FormatChecker(),
    )

    return [
        error.message
        for error in validator.iter_errors(instance)
    ]


def test_schema_file_exists() -> None:
    """The V1 schema file must exist."""
    assert SCHEMA_PATH.is_file()


def test_schema_is_valid_json() -> None:
    """The V1 schema must contain valid JSON."""
    schema = load_schema()

    assert isinstance(schema, dict)
    assert schema["$schema"] == (
        "https://json-schema.org/draft/2020-12/schema"
    )


def test_schema_itself_is_valid() -> None:
    """The schema must pass JSON Schema meta-validation."""
    schema = load_schema()

    Draft202012Validator.check_schema(schema)


def test_minimal_attack_surface_matches_schema() -> None:
    """A minimal valid AttackSurface must satisfy the V1 schema."""
    attack_surface = build_minimal_attack_surface()

    instance = attack_surface.model_dump(
        mode="json",
    )

    errors = validate_attack_surface(instance)

    assert errors == []


def test_schema_version_must_be_v1() -> None:
    """The schema must reject unsupported schema versions."""
    attack_surface = build_minimal_attack_surface()

    instance = attack_surface.model_dump(
        mode="json",
    )
    instance["schema_version"] = "v2"

    errors = validate_attack_surface(instance)

    assert any(
        "v1" in error
        for error in errors
    )


def test_unknown_top_level_property_is_rejected() -> None:
    """The V1 contract must reject undeclared top-level fields."""
    attack_surface = build_minimal_attack_surface()

    instance = attack_surface.model_dump(
        mode="json",
    )
    instance["unexpected_field"] = "should-not-exist"

    errors = validate_attack_surface(instance)

    assert any(
        "unexpected_field" in error
        for error in errors
    )


def test_required_top_level_property_is_enforced() -> None:
    """The schema must reject an instance missing a required field."""
    attack_surface = build_minimal_attack_surface()

    instance = attack_surface.model_dump(
        mode="json",
    )
    del instance["authorization"]

    errors = validate_attack_surface(instance)

    assert any(
        "authorization" in error
        for error in errors
    )


def test_invalid_target_type_is_rejected() -> None:
    """The target type must be one of the supported V1 values."""
    attack_surface = build_minimal_attack_surface()

    instance = attack_surface.model_dump(
        mode="json",
    )
    instance["target"]["type"] = "INVALID"

    errors = validate_attack_surface(instance)

    assert any(
        "INVALID" in error
        for error in errors
    )


def test_invalid_relationship_type_is_rejected() -> None:
    """Relationship types must use the V1 relationship vocabulary."""
    attack_surface = build_minimal_attack_surface()

    asset_id = uuid4()
    instance = attack_surface.model_dump(
        mode="json",
    )

    instance["relationships"] = [
        {
            "id": str(uuid4()),
            "type": "INVALID_RELATIONSHIP",
            "source_id": str(asset_id),
            "target_id": str(asset_id),
            "evidence_ids": [],
            "metadata": {},
        }
    ]

    errors = validate_attack_surface(instance)

    assert any(
        "INVALID_RELATIONSHIP" in error
        for error in errors
    )


def test_invalid_uuid_is_rejected() -> None:
    """UUID fields must contain valid UUID values."""
    attack_surface = build_minimal_attack_surface()

    instance = attack_surface.model_dump(
        mode="json",
    )
    instance["run"]["id"] = "not-a-valid-uuid"

    errors = validate_attack_surface(instance)

    assert any(
        "not-a-valid-uuid" in error
        for error in errors
    )