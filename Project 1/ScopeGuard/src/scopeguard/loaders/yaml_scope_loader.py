from pathlib import Path

import yaml

from ..models.asset import Asset
from ..models.asset_type import AssetType
from ..models.effect import Effect
from ..models.program import Program
from ..models.scope import Scope
from ..models.scope_rule import ScopeRule
from ..validators.asset_validator import AssetValidator
from ..validators.scope_validator import ScopeValidator


class YamlScopeLoader:
    def __init__(
        self,
        scope_validator=None,
        asset_validator=None,
    ) -> None:
        self._scope_validator = (
            scope_validator
            if scope_validator is not None
            else ScopeValidator()
        )

        self._asset_validator = (
            asset_validator
            if asset_validator is not None
            else AssetValidator()
        )

    def load(self, path: str | Path) -> Scope:
        file_path = Path(path)

        if not file_path.exists():
            raise FileNotFoundError(
                f"Scope file not found: {file_path}"
            )

        if not file_path.is_file():
            raise ValueError(
                f"Scope path is not a file: {file_path}"
            )

        with file_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = yaml.safe_load(file)

        scope = self._build_scope(data)

        self._scope_validator.validate(scope)

        for rule in scope.rules:
            self._asset_validator.validate(rule.asset)

        return scope

    def _build_scope(self, data) -> Scope:
        if not isinstance(data, dict):
            raise ValueError(
                "Scope YAML must contain a mapping"
            )

        version = data.get("version")

        if version is None:
            raise ValueError(
                "Scope version is required"
            )

        program_data = data.get("program")

        if not isinstance(program_data, dict):
            raise ValueError(
                "Program section is required"
            )

        program_name = program_data.get("name")

        if not isinstance(program_name, str):
            raise ValueError(
                "Program name is required"
            )

        scope_data = data.get("scope")

        if not isinstance(scope_data, dict):
            raise ValueError(
                "Scope section is required"
            )

        rules_data = scope_data.get("rules", [])

        if not isinstance(rules_data, list):
            raise ValueError(
                "Scope rules must be a list"
            )

        rules = [
            self._build_rule(rule_data)
            for rule_data in rules_data
        ]

        return Scope(
            version=str(version),
            program=Program(
                name=program_name,
            ),
            rules=rules,
        )

    def _build_rule(self, data) -> ScopeRule:
        if not isinstance(data, dict):
            raise ValueError(
                "Each scope rule must be a mapping"
            )

        rule_id = data.get("id")

        if not isinstance(rule_id, str):
            raise ValueError(
                "Rule ID is required"
            )

        effect_value = data.get("effect")

        try:
            effect = Effect(effect_value)
        except ValueError as exc:
            raise ValueError(
                f"Invalid effect for rule {rule_id}: "
                f"{effect_value}"
            ) from exc

        asset_data = data.get("asset")

        if not isinstance(asset_data, dict):
            raise ValueError(
                f"Asset is required for rule {rule_id}"
            )

        asset_type_value = asset_data.get("type")
        asset_value = asset_data.get("value")

        try:
            asset_type = AssetType(asset_type_value)
        except ValueError as exc:
            raise ValueError(
                f"Invalid asset type for rule {rule_id}: "
                f"{asset_type_value}"
            ) from exc

        if not isinstance(asset_value, str):
            raise ValueError(
                f"Asset value is required for rule {rule_id}"
            )

        asset = Asset(
            type=asset_type,
            value=asset_value,
        )

        return ScopeRule(
            id=rule_id,
            effect=effect,
            asset=asset,
            category=asset_data.get("category"),
            description=data.get("description"),
            condition=data.get("condition"),
        )
    