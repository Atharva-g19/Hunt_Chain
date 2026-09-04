from scopeguard import (
    Asset,
    AssetType,
    DecisionState,
    Effect,
    Program,
    Scope,
    ScopeEngine,
    ScopeRule,
)


def test_scopeguard_public_api():
    scope = Scope(
        version="1",
        program=Program(
            name="Example Program"
        ),
        rules=[
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="example.com",
                ),
            )
        ],
    )

    decision = ScopeEngine().check(
        scope,
        "example.com",
    )

    assert decision.state == DecisionState.IN_SCOPE
    assert decision.winning_rule == "S001"


def test_public_api_supports_out_of_scope_decision():
    scope = Scope(
        version="1",
        program=Program(
            name="Example Program"
        ),
        rules=[
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="example.com",
                ),
            )
        ],
    )

    decision = ScopeEngine().check(
        scope,
        "attacker.com",
    )

    assert decision.state == DecisionState.OUT_OF_SCOPE


def test_public_api_supports_wildcard_scope():
    scope = Scope(
        version="1",
        program=Program(
            name="Example Program"
        ),
        rules=[
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOST_WILDCARD,
                    value="*.example.com",
                ),
            )
        ],
    )

    decision = ScopeEngine().check(
        scope,
        "api.example.com",
    )

    assert decision.state == DecisionState.IN_SCOPE 