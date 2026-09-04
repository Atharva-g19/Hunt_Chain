from .errors import ScopeValidationError
from ..models.asset_type import AssetType


class ScopeValidator:
    def validate(self, scope) -> None:
        if scope is None:
            raise ScopeValidationError("Scope cannot be None")

        if not scope.version:
            raise ScopeValidationError("Scope version is required")

        if scope.program is None:
            raise ScopeValidationError("Program is required")

        if not scope.program.name.strip():
            raise ScopeValidationError("Program name cannot be empty")

        rule_ids = set()

        for rule in scope.rules:
            if not rule.id.strip():
                raise ScopeValidationError("Rule ID is required")

            if rule.id in rule_ids:
                raise ScopeValidationError(
                    f"Duplicate rule ID: {rule.id}"
                )

            rule_ids.add(rule.id)

            if rule.effect is None:
                raise ScopeValidationError(
                    f"Rule {rule.id}: effect is required"
                )

            if rule.asset is None:
                raise ScopeValidationError(
                    f"Rule {rule.id}: asset is required"
                )

            if rule.asset.type not in AssetType:
                raise ScopeValidationError(
                    f"Rule {rule.id}: unsupported asset type"
                )

            if not rule.asset.value.strip():
                raise ScopeValidationError(
                    f"Rule {rule.id}: asset value cannot be empty"
                )