from scopeguard.models.asset import Asset
from scopeguard.models.effect import Effect
from scopeguard.models.program import Program
from scopeguard.models.scope import Scope
from scopeguard.models.scope_rule import ScopeRule


def test_scope_creation():
    rule = ScopeRule(
        id="S001",
        effect=Effect.INCLUDE,
        asset=Asset(
            type="hostname",
            value="example.com"
        )
    )

    scope = Scope(
        version="1",
        program=Program(name="Example Program"),
        rules=[rule]
    )

    assert scope.version == "1"
    assert scope.program.name == "Example Program"
    assert len(scope.rules) == 1
    assert scope.rules[0].id == "S001"