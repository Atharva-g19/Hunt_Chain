import json

from scopeguard.models.decision import Decision
from scopeguard.models.decision_state import DecisionState
from scopeguard.models.target import Target
from scopeguard.serializers.decision_serializer import DecisionSerializer


def create_decision(
    state=DecisionState.IN_SCOPE,
    matched_rules=None,
    winning_rule="S001",
    reason="Rule S001 won by specificity (100)",
):
    if matched_rules is None:
        matched_rules = ["S001"]

    return Decision(
        state=state,
        target=Target(
            raw_value=" Example.COM ",
            normalized_value="example.com",
            type="hostname",
        ),
        matched_rules=matched_rules,
        winning_rule=winning_rule,
        reason=reason,
    )


def test_to_dict_serializes_decision():
    serializer = DecisionSerializer()

    decision = create_decision()

    result = serializer.to_dict(decision)

    assert result == {
        "state": "IN_SCOPE",
        "target": {
            "raw_value": " Example.COM ",
            "normalized_value": "example.com",
            "type": "hostname",
        },
        "matched_rules": ["S001"],
        "winning_rule": "S001",
        "reason": "Rule S001 won by specificity (100)",
    }


def test_to_dict_serializes_out_of_scope_decision():
    serializer = DecisionSerializer()

    decision = create_decision(
        state=DecisionState.OUT_OF_SCOPE,
        matched_rules=[],
        winning_rule=None,
        reason="No matching scope rule",
    )

    result = serializer.to_dict(decision)

    assert result["state"] == "OUT_OF_SCOPE"
    assert result["matched_rules"] == []
    assert result["winning_rule"] is None
    assert result["reason"] == "No matching scope rule"


def test_to_dict_does_not_modify_decision():
    serializer = DecisionSerializer()

    decision = create_decision()

    original_rules = decision.matched_rules.copy()

    serializer.to_dict(decision)

    assert decision.matched_rules == original_rules


def test_to_json_returns_valid_json():
    serializer = DecisionSerializer()

    decision = create_decision()

    result = serializer.to_json(decision)

    parsed = json.loads(result)

    assert parsed["state"] == "IN_SCOPE"
    assert parsed["target"]["normalized_value"] == "example.com"
    assert parsed["winning_rule"] == "S001"


def test_to_json_is_pretty_printed():
    serializer = DecisionSerializer()

    decision = create_decision()

    result = serializer.to_json(decision)

    assert "\n" in result
    assert "  \"state\"" in result


def test_to_json_preserves_null_winning_rule():
    serializer = DecisionSerializer()

    decision = create_decision(
        state=DecisionState.OUT_OF_SCOPE,
        matched_rules=[],
        winning_rule=None,
        reason="No matching scope rule",
    )

    result = serializer.to_json(decision)

    parsed = json.loads(result)

    assert parsed["winning_rule"] is None
    