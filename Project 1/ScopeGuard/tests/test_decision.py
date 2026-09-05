from scopeguard.models.decision import Decision
from scopeguard.models.target import Target


def test_decision_creation():
    target = Target(
        raw_value="example.com",
        normalized_value="example.com",
        type="hostname"
    )

    decision = Decision(
        state="IN_SCOPE",
        target=target,
        matched_rules=["S001"],
        winning_rule="S001",
        reason="Exact hostname match"
    )

    assert decision.state == "IN_SCOPE"
    assert decision.target.normalized_value == "example.com"
    assert decision.matched_rules == ["S001"]
    assert decision.winning_rule == "S001"
    assert decision.reason == "Exact hostname match"