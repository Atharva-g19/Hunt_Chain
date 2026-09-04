import pytest

from scopeguard.models.program import Program
from scopeguard.models.scope import Scope
from scopeguard.validators.errors import ScopeValidationError
from scopeguard.validators.scope_validator import ScopeValidator


def test_valid_scope():
    scope = Scope(
        version="1",
        program=Program(name="Example Program")
    )

    ScopeValidator().validate(scope)


def test_scope_cannot_be_none():
    with pytest.raises(ScopeValidationError):
        ScopeValidator().validate(None)


def test_scope_version_required():
    scope = Scope(
        version="",
        program=Program(name="Example Program")
    )

    with pytest.raises(ScopeValidationError):
        ScopeValidator().validate(scope)


def test_program_required():
    scope = Scope(
        version="1",
        program=None
    )

    with pytest.raises(ScopeValidationError):
        ScopeValidator().validate(scope)


def test_program_name_cannot_be_empty():
    scope = Scope(
        version="1",
        program=Program(name="   ")
    )

    with pytest.raises(ScopeValidationError):
        ScopeValidator().validate(scope)


from scopeguard.models.asset import Asset
from scopeguard.models.asset_type import AssetType
from scopeguard.models.effect import Effect
from scopeguard.models.scope_rule import ScopeRule


def test_duplicate_rule_ids():
    rules = [
        ScopeRule(
            id="S001",
            effect=Effect.INCLUDE,
            asset=Asset(AssetType.HOSTNAME, "example.com")
        ),
        ScopeRule(
            id="S001",
            effect=Effect.EXCLUDE,
            asset=Asset(AssetType.HOSTNAME, "admin.example.com")
        ),
    ]

    scope = Scope(
        version="1",
        program=Program(name="Example"),
        rules=rules
    )

    with pytest.raises(ScopeValidationError):
        ScopeValidator().validate(scope)


def test_rule_asset_required():
    rule = ScopeRule(
        id="S001",
        effect=Effect.INCLUDE,
        asset=None
    )

    scope = Scope(
        version="1",
        program=Program(name="Example"),
        rules=[rule]
    )

    with pytest.raises(ScopeValidationError):
        ScopeValidator().validate(scope)


def test_rule_asset_value_required():
    rule = ScopeRule(
        id="S001",
        effect=Effect.INCLUDE,
        asset=Asset(AssetType.HOSTNAME, "   ")
    )

    scope = Scope(
        version="1",
        program=Program(name="Example"),
        rules=[rule]
    )

    with pytest.raises(ScopeValidationError):
        ScopeValidator().validate(scope)