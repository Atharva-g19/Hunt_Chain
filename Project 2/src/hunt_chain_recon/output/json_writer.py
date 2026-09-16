
from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from uuid import UUID

from jsonschema import Draft202012Validator, SchemaError

from hunt_chain_recon.models.attack_surface import AttackSurface


class JSONOutputError(Exception):
    """Raised when JSON output cannot be generated."""


class JSONSchemaValidationError(JSONOutputError):
    """Raised when JSON schema validation fails."""


class JSONOutputWriter:
    """Serialize, validate, and persist Project 2 AttackSurface output."""

    DEFAULT_SCHEMA_PATH = (
        Path(__file__).resolve().parents[3]
        / "schemas"
        / "attack_surface_v1.json"
    )

    def __init__(
        self,
        schema_path: str | Path | None = None,
    ) -> None:
        self.schema_path = (
            Path(schema_path)
            if schema_path is not None
            else self.DEFAULT_SCHEMA_PATH
        )

    def serialize(
        self,
        attack_surface: AttackSurface,
    ) -> dict[str, Any]:
        """Serialize an AttackSurface into a JSON-compatible dictionary."""

        if not isinstance(attack_surface, AttackSurface):
            raise TypeError("Expected AttackSurface instance")

        document = attack_surface.model_dump(mode="json")

        self._normalize_asset_sources(document)

        return document

    @staticmethod
    def _normalize_asset_sources(
        document: dict[str, Any],
    ) -> None:
        """
        Convert the internal V1 provenance representation into the
        structured discovery_source representation required by the
        serialized AttackSurface schema.

        Internally, Asset.sources remains list[str] so existing Project 2
        processing and deduplication behavior is preserved.

        Serialized V1 output represents each provenance source as:

            {
                "provider": "<source>",
                "reference": null,
                "metadata": {}
            }
        """

        assets = document.get("assets")

        if not isinstance(assets, list):
            return

        for asset in assets:
            if not isinstance(asset, dict):
                continue

            sources = asset.get("sources")

            if not isinstance(sources, list):
                continue

            normalized_sources: list[dict[str, Any]] = []

            for source in sources:
                if isinstance(source, str):
                    normalized_sources.append(
                        {
                            "provider": source,
                            "reference": None,
                            "metadata": {},
                        }
                    )
                    continue

                # Preserve already-structured source data if encountered.
                if isinstance(source, dict):
                    normalized_sources.append(source)

            asset["sources"] = normalized_sources

    def _load_schema(self) -> dict[str, Any]:
        """Load the configured JSON schema."""

        if not self.schema_path.exists():
            raise JSONOutputError(
                f"schema not found: {self.schema_path}"
            )

        try:
            with self.schema_path.open(
                "r",
                encoding="utf-8",
            ) as handle:
                schema = json.load(handle)

        except (OSError, json.JSONDecodeError) as exc:
            raise JSONOutputError(
                f"Unable to load schema: {self.schema_path}"
            ) from exc

        if not isinstance(schema, dict):
            raise JSONOutputError(
                f"Invalid schema document: {self.schema_path}"
            )

        return schema

    def validate(
        self,
        document: dict[str, Any],
    ) -> None:
        """
        Validate a serialized AttackSurface document.

        The validation consists of:
        1. JSON Schema validation.
        2. Explicit UUID validation for run.id.
        """

        if not isinstance(document, dict):
            raise TypeError(
                "Expected serialized AttackSurface dictionary"
            )

        schema = self._load_schema()

        run = document.get("run")

        if isinstance(run, dict):
            run_id = run.get("id")

            if isinstance(run_id, str):
                try:
                    UUID(run_id)
                except ValueError as exc:
                    raise JSONSchemaValidationError(
                        "AttackSurface schema validation failed: "
                        "run.id must be a valid UUID"
                    ) from exc

        try:
            validator = Draft202012Validator(schema)

            errors = sorted(
                validator.iter_errors(document),
                key=lambda error: list(error.absolute_path),
            )

        except SchemaError as exc:
            raise JSONOutputError(
                f"Invalid JSON schema: {self.schema_path}"
            ) from exc

        if errors:
            messages: list[str] = []

            for error in errors:
                path = ".".join(
                    str(part)
                    for part in error.absolute_path
                )

                if path:
                    messages.append(
                        f"{path}: {error.message}"
                    )
                else:
                    messages.append(error.message)

            raise JSONSchemaValidationError(
                "AttackSurface schema validation failed: "
                + "; ".join(messages)
            )

    def write(
        self,
        attack_surface: AttackSurface,
        output_path: str | Path,
    ) -> Path:
        """Validate and write an AttackSurface JSON document."""

        if not isinstance(attack_surface, AttackSurface):
            raise TypeError("Expected AttackSurface instance")

        output_path = Path(output_path)

        document = self.serialize(attack_surface)

        self.validate(document)

        try:
            output_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            with output_path.open(
                "w",
                encoding="utf-8",
            ) as handle:
                json.dump(
                    document,
                    handle,
                    indent=2,
                    ensure_ascii=False,
                    sort_keys=True,
                )
                handle.write("\n")

        except (OSError, TypeError, ValueError) as exc:
            raise JSONOutputError(
                f"Failed to write JSON output: {output_path}"
            ) from exc

        return output_path

