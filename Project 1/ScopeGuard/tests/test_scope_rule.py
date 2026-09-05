from scopeguard.models.asset import Asset
from scopeguard.models.effect import Effect
from scopeguard.models.scope_rule import ScopeRule


def test_scope_rule_creation():
    rule = ScopeRule(
        id="S001",
        effect=Effect.INCLUDE,
        asset=Asset(
            type="hostname",
            value="example.com"
        ),
        category="web_application",
        description="Main website"
    )

    assert rule.id == "S001"
    assert rule.effect == Effect.INCLUDE
    assert rule.asset.value == "example.com"
    assert rule.category == "web_application"
    assert rule.description == "Main website"
    assert rule.condition is None