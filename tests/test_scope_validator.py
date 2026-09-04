import pytest

from scopeguard.models.asset import Asset
from scopeguard.models.asset_type import AssetType
from scopeguard.models.effect import Effect
from scopeguard.models.program import Program
from scopeguard.models.scope import Scope
from scopeguard.models.scope_rule import ScopeRule
from scopeguard.validators.errors import ScopeValidationError
from scopeguard.validators.scope_validator import ScopeValidator


def create_valid_scope(rules=None):
    if rules is None:
        rules = [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="example.com",
                ),
            )
        ]

    return Scope(
        version="1",
        program=Program(
            name="Example Program",
        ),
        rules=rules,
    )


def test_valid_scope_passes():
    validator = ScopeValidator()

    scope = create_valid_scope()

    validator.validate(scope)


def test_none_scope_is_rejected():
    validator = ScopeValidator()

    with pytest.raises(
        ScopeValidationError,
        match="Scope cannot be None",
    ):
        validator.validate(None)


def test_missing_version_is_rejected():
    validator = ScopeValidator()

    scope = create_valid_scope()
    scope.version = ""

    with pytest.raises(
        ScopeValidationError,
        match="Scope version is required",
    ):
        validator.validate(scope)


def test_missing_program_is_rejected():
    validator = ScopeValidator()

    scope = create_valid_scope()
    scope.program = None

    with pytest.raises(
        ScopeValidationError,
        match="Program is required",
    ):
        validator.validate(scope)


def test_empty_program_name_is_rejected():
    validator = ScopeValidator()

    scope = create_valid_scope()
    scope.program.name = "   "

    with pytest.raises(
        ScopeValidationError,
        match="Program name cannot be empty",
    ):
        validator.validate(scope)


def test_duplicate_rule_id_is_rejected():
    validator = ScopeValidator()

    rules = [
        ScopeRule(
            id="S001",
            effect=Effect.INCLUDE,
            asset=Asset(
                type=AssetType.HOSTNAME,
                value="example.com",
            ),
        ),
        ScopeRule(
            id="S001",
            effect=Effect.EXCLUDE,
            asset=Asset(
                type=AssetType.HOSTNAME,
                value="internal.example.com",
            ),
        ),
    ]

    scope = create_valid_scope(rules)

    with pytest.raises(
        ScopeValidationError,
        match="Duplicate rule ID: S001",
    ):
        validator.validate(scope)


def test_none_rule_is_rejected():
    validator = ScopeValidator()

    scope = create_valid_scope([None])

    with pytest.raises(
        ScopeValidationError,
        match="Scope rule cannot be None",
    ):
        validator.validate(scope)


def test_non_string_rule_id_is_rejected():
    validator = ScopeValidator()

    rule = ScopeRule(
        id=123,
        effect=Effect.INCLUDE,
        asset=Asset(
            type=AssetType.HOSTNAME,
            value="example.com",
        ),
    )

    scope = create_valid_scope([rule])

    with pytest.raises(
        ScopeValidationError,
        match="Rule ID must be a string",
    ):
        validator.validate(scope)


def test_empty_rule_id_is_rejected():
    validator = ScopeValidator()

    rule = ScopeRule(
        id="   ",
        effect=Effect.INCLUDE,
        asset=Asset(
            type=AssetType.HOSTNAME,
            value="example.com",
        ),
    )

    scope = create_valid_scope([rule])

    with pytest.raises(
        ScopeValidationError,
        match="Rule ID is required",
    ):
        validator.validate(scope)


def test_invalid_effect_is_rejected():
    validator = ScopeValidator()

    rule = ScopeRule(
        id="S001",
        effect="include",
        asset=Asset(
            type=AssetType.HOSTNAME,
            value="example.com",
        ),
    )

    scope = create_valid_scope([rule])

    with pytest.raises(
        ScopeValidationError,
        match="Rule S001: invalid effect",
    ):
        validator.validate(scope)


def test_none_asset_is_rejected():
    validator = ScopeValidator()

    rule = ScopeRule(
        id="S001",
        effect=Effect.INCLUDE,
        asset=None,
    )

    scope = create_valid_scope([rule])

    with pytest.raises(
        ScopeValidationError,
        match="Rule S001: asset is required",
    ):
        validator.validate(scope)


def test_invalid_asset_type_is_rejected():
    validator = ScopeValidator()

    rule = ScopeRule(
        id="S001",
        effect=Effect.INCLUDE,
        asset=Asset(
            type="hostname",
            value="example.com",
        ),
    )

    scope = create_valid_scope([rule])

    with pytest.raises(
        ScopeValidationError,
        match="Rule S001: unsupported asset type",
    ):
        validator.validate(scope)


def test_non_string_asset_value_is_rejected():
    validator = ScopeValidator()

    rule = ScopeRule(
        id="S001",
        effect=Effect.INCLUDE,
        asset=Asset(
            type=AssetType.HOSTNAME,
            value=123,
        ),
    )

    scope = create_valid_scope([rule])

    with pytest.raises(
        ScopeValidationError,
        match="Rule S001: asset value must be a string",
    ):
        validator.validate(scope)


def test_empty_asset_value_is_rejected():
    validator = ScopeValidator()

    rule = ScopeRule(
        id="S001",
        effect=Effect.INCLUDE,
        asset=Asset(
            type=AssetType.HOSTNAME,
            value="   ",
        ),
    )

    scope = create_valid_scope([rule])

    with pytest.raises(
        ScopeValidationError,
        match="Rule S001: asset value cannot be empty",
    ):
        validator.validate(scope)