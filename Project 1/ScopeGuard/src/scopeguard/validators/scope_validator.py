from ..models.asset_type import AssetType
from ..models.effect import Effect
from .errors import ScopeValidationError


class ScopeValidator:
    def validate(self, scope) -> None:
        if scope is None:
            raise ScopeValidationError(
                "Scope cannot be None"
            )

        if scope.program is None:
            raise ScopeValidationError(
                "Program is required"
            )

        if not isinstance(scope.program.name, str):
            raise ScopeValidationError(
                "Program name must be a string"
            )

        if not scope.program.name.strip():
            raise ScopeValidationError(
                "Program name cannot be empty"
            )

        if not isinstance(scope.rules, list):
            raise ScopeValidationError(
                "Scope rules must be a list"
            )

        rule_ids = set()

        for rule in scope.rules:
            self._validate_rule(
                rule,
                rule_ids,
            )

    def _validate_rule(
        self,
        rule,
        rule_ids: set[str],
    ) -> None:
        if rule is None:
            raise ScopeValidationError(
                "Scope rule cannot be None"
            )

        if not isinstance(rule.id, str):
            raise ScopeValidationError(
                "Rule ID must be a string"
            )

        if not rule.id.strip():
            raise ScopeValidationError(
                "Rule ID is required"
            )

        if rule.id in rule_ids:
            raise ScopeValidationError(
                f"Duplicate rule ID: {rule.id}"
            )

        rule_ids.add(rule.id)

        if not isinstance(rule.effect, Effect):
            raise ScopeValidationError(
                f"Rule {rule.id}: invalid effect"
            )

        if rule.asset is None:
            raise ScopeValidationError(
                f"Rule {rule.id}: asset is required"
            )

        if not isinstance(rule.asset.type, AssetType):
            raise ScopeValidationError(
                f"Rule {rule.id}: unsupported asset type"
            )

        if not isinstance(rule.asset.value, str):
            raise ScopeValidationError(
                f"Rule {rule.id}: asset value must be a string"
            )

        if not rule.asset.value.strip():
            raise ScopeValidationError(
                f"Rule {rule.id}: asset value cannot be empty"
            )

        if rule.condition is not None:
            if not isinstance(rule.condition, str):
                raise ScopeValidationError(
                    f"Rule {rule.id}: condition must be a string"
                )

            if not rule.condition.strip():
                raise ScopeValidationError(
                    f"Rule {rule.id}: condition cannot be empty"
                )