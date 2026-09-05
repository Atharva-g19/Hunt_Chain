from ..matchers.registry import MatcherRegistry
from ..models.decision import Decision
from ..models.decision_state import DecisionState
from ..models.scope import Scope
from ..models.target import Target
from ..normalizers.target_normalizer import TargetNormalizer
from ..validators.asset_validator import AssetValidator
from ..validators.scope_validator import ScopeValidator
from ..validators.target_validator import TargetValidator
from .specificity import SpecificityCalculator


class ScopeEngine:
    def __init__(
        self,
        matcher_registry=None,
        specificity_calculator=None,
        scope_validator=None,
        asset_validator=None,
        target_validator=None,
        target_normalizer=None,
    ) -> None:
        self._matcher_registry = (
            matcher_registry
            if matcher_registry is not None
            else MatcherRegistry()
        )

        self._specificity_calculator = (
            specificity_calculator
            if specificity_calculator is not None
            else SpecificityCalculator()
        )

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

        self._target_validator = (
            target_validator
            if target_validator is not None
            else TargetValidator()
        )

        self._target_normalizer = (
            target_normalizer
            if target_normalizer is not None
            else TargetNormalizer()
        )

    def find_matching_rules(
        self,
        scope: Scope,
        target: Target,
    ) -> list[dict]:
        matches = []

        for rule in scope.rules:
            matcher = self._matcher_registry.get(rule.asset.type)

            if matcher is None:
                continue

            result = matcher.matches(
                target.normalized_value,
                rule.asset.value,
            )

            if result.matched:
                specificity = self._specificity_calculator.calculate(
                    rule.asset.type,
                    rule.asset.value,
                )

                matches.append(
                    {
                        "rule_id": rule.id,
                        "effect": rule.effect,
                        "asset_type": rule.asset.type,
                        "asset_value": rule.asset.value,
                        "reason": result.reason,
                        "specificity": specificity,
                        "condition": rule.condition,
                    }
                )

        return matches

    def check(
        self,
        scope: Scope,
        target: Target | str,
    ) -> Decision:
        self._validate_scope(scope)

        normalized_target = self._prepare_target(target)

        matches = self.find_matching_rules(
            scope,
            normalized_target,
        )

        if not matches:
            return Decision(
                state=DecisionState.OUT_OF_SCOPE,
                target=normalized_target,
                matched_rules=[],
                winning_rule=None,
                reason="No matching scope rule",
            )

        matched_rule_ids = [
            match["rule_id"]
            for match in matches
        ]

        highest_specificity = max(
            match["specificity"]
            for match in matches
        )

        highest_matches = [
            match
            for match in matches
            if match["specificity"] == highest_specificity
        ]

        conditional_matches = [
            match
            for match in highest_matches
            if match["condition"] is not None
        ]

        if conditional_matches:
            return Decision(
                state=DecisionState.UNKNOWN,
                target=normalized_target,
                matched_rules=matched_rule_ids,
                winning_rule=None,
                reason=(
                    "The highest-specificity matching rule contains "
                    "a condition that cannot be evaluated in V1"
                ),
            )

        include_matches = [
            match
            for match in highest_matches
            if match["effect"].value == "include"
        ]

        exclude_matches = [
            match
            for match in highest_matches
            if match["effect"].value == "exclude"
        ]

        if include_matches and exclude_matches:
            return Decision(
                state=DecisionState.CONFLICT,
                target=normalized_target,
                matched_rules=matched_rule_ids,
                winning_rule=None,
                reason=(
                    "Include and exclude rules with equal "
                    "highest specificity match"
                ),
            )

        if include_matches:
            winning_match = include_matches[0]

            return Decision(
                state=DecisionState.IN_SCOPE,
                target=normalized_target,
                matched_rules=matched_rule_ids,
                winning_rule=winning_match["rule_id"],
                reason=(
                    f"Rule {winning_match['rule_id']} won by "
                    f"specificity ({highest_specificity})"
                ),
            )

        winning_match = exclude_matches[0]

        return Decision(
            state=DecisionState.OUT_OF_SCOPE,
            target=normalized_target,
            matched_rules=matched_rule_ids,
            winning_rule=winning_match["rule_id"],
            reason=(
                f"Rule {winning_match['rule_id']} won by "
                f"specificity ({highest_specificity})"
            ),
        )

    def _prepare_target(
        self,
        target: Target | str,
    ) -> Target:
        if isinstance(target, str):
            target = self._target_normalizer.normalize(
                target
            )

        self._validate_target(target)

        return target

    def _validate_scope(self, scope: Scope) -> None:
        self._scope_validator.validate(scope)

        for rule in scope.rules:
            self._asset_validator.validate(rule.asset)

    def _validate_target(self, target: Target) -> None:
        self._target_validator.validate(target)