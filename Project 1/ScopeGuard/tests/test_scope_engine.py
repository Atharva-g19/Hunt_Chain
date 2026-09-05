import pytest

from scopeguard.engine.scope_engine import ScopeEngine
from scopeguard.models.asset import Asset
from scopeguard.models.asset_type import AssetType
from scopeguard.models.decision_state import DecisionState
from scopeguard.models.effect import Effect
from scopeguard.models.program import Program
from scopeguard.models.scope import Scope
from scopeguard.models.scope_rule import ScopeRule
from scopeguard.models.target import Target
from scopeguard.validators.errors import ScopeValidationError


def create_scope(rules):
    return Scope(
        version="1",
        program=Program(name="Test Program"),
        rules=rules,
    )


def create_target(value, target_type="hostname"):
    return Target(
        raw_value=value,
        normalized_value=value,
        type=target_type,
    )


def test_include_rule_produces_in_scope():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="example.com",
                ),
            )
        ]
    )

    target = create_target("example.com")

    decision = ScopeEngine().check(scope, target)

    assert decision.state == DecisionState.IN_SCOPE
    assert decision.winning_rule == "S001"
    assert decision.matched_rules == ["S001"]


def test_exclude_rule_produces_out_of_scope():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.EXCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="admin.example.com",
                ),
            )
        ]
    )

    target = create_target("admin.example.com")

    decision = ScopeEngine().check(scope, target)

    assert decision.state == DecisionState.OUT_OF_SCOPE
    assert decision.winning_rule == "S001"
    assert decision.matched_rules == ["S001"]


def test_no_matching_rule_produces_out_of_scope():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="example.com",
                ),
            )
        ]
    )

    target = create_target("example.org")

    decision = ScopeEngine().check(scope, target)

    assert decision.state == DecisionState.OUT_OF_SCOPE
    assert decision.winning_rule is None
    assert decision.matched_rules == []
    assert decision.reason == "No matching scope rule"


def test_more_specific_exclude_beats_broader_include():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOST_WILDCARD,
                    value="*.example.com",
                ),
            ),
            ScopeRule(
                id="S002",
                effect=Effect.EXCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="admin.example.com",
                ),
            ),
        ]
    )

    target = create_target("admin.example.com")

    decision = ScopeEngine().check(scope, target)

    assert decision.state == DecisionState.OUT_OF_SCOPE
    assert decision.winning_rule == "S002"
    assert decision.matched_rules == ["S001", "S002"]


def test_more_specific_include_beats_broader_exclude():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.EXCLUDE,
                asset=Asset(
                    type=AssetType.HOST_WILDCARD,
                    value="*.example.com",
                ),
            ),
            ScopeRule(
                id="S002",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="admin.example.com",
                ),
            ),
        ]
    )

    target = create_target("admin.example.com")

    decision = ScopeEngine().check(scope, target)

    assert decision.state == DecisionState.IN_SCOPE
    assert decision.winning_rule == "S002"


def test_equal_specificity_opposite_effects_produce_conflict():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="admin.example.com",
                ),
            ),
            ScopeRule(
                id="S002",
                effect=Effect.EXCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="admin.example.com",
                ),
            ),
        ]
    )

    target = create_target("admin.example.com")

    decision = ScopeEngine().check(scope, target)

    assert decision.state == DecisionState.CONFLICT
    assert decision.winning_rule is None
    assert decision.matched_rules == ["S001", "S002"]


def test_multiple_include_rules_choose_most_specific():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOST_WILDCARD,
                    value="*.example.com",
                ),
            ),
            ScopeRule(
                id="S002",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="admin.example.com",
                ),
            ),
        ]
    )

    target = create_target("admin.example.com")

    decision = ScopeEngine().check(scope, target)

    assert decision.state == DecisionState.IN_SCOPE
    assert decision.winning_rule == "S002"
    assert decision.matched_rules == ["S001", "S002"]


def test_multiple_exclude_rules_choose_most_specific():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.EXCLUDE,
                asset=Asset(
                    type=AssetType.HOST_WILDCARD,
                    value="*.example.com",
                ),
            ),
            ScopeRule(
                id="S002",
                effect=Effect.EXCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="admin.example.com",
                ),
            ),
        ]
    )

    target = create_target("admin.example.com")

    decision = ScopeEngine().check(scope, target)

    assert decision.state == DecisionState.OUT_OF_SCOPE
    assert decision.winning_rule == "S002"


def test_url_exact_rule_beats_path_wildcard():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.URL_PATH_WILDCARD,
                    value="https://example.com/api/*",
                ),
            ),
            ScopeRule(
                id="S002",
                effect=Effect.EXCLUDE,
                asset=Asset(
                    type=AssetType.URL,
                    value="https://example.com/api/admin",
                ),
            ),
        ]
    )

    target = create_target(
        "https://example.com/api/admin",
        target_type="url",
    )

    decision = ScopeEngine().check(scope, target)

    assert decision.state == DecisionState.OUT_OF_SCOPE
    assert decision.winning_rule == "S002"


def test_narrower_cidr_beats_broader_cidr():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.IPV4_CIDR,
                    value="192.168.0.0/16",
                ),
            ),
            ScopeRule(
                id="S002",
                effect=Effect.EXCLUDE,
                asset=Asset(
                    type=AssetType.IPV4_CIDR,
                    value="192.168.1.0/24",
                ),
            ),
        ]
    )

    target = create_target(
        "192.168.1.50",
        target_type="ipv4",
    )

    decision = ScopeEngine().check(scope, target)

    assert decision.state == DecisionState.OUT_OF_SCOPE
    assert decision.winning_rule == "S002"


def test_32_cidr_beats_broader_cidr():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.IPV4_CIDR,
                    value="192.168.1.0/24",
                ),
            ),
            ScopeRule(
                id="S002",
                effect=Effect.EXCLUDE,
                asset=Asset(
                    type=AssetType.IPV4_CIDR,
                    value="192.168.1.10/32",
                ),
            ),
        ]
    )

    target = create_target(
        "192.168.1.10",
        target_type="ipv4",
    )

    decision = ScopeEngine().check(scope, target)

    assert decision.state == DecisionState.OUT_OF_SCOPE
    assert decision.winning_rule == "S002"


def test_decision_contains_specificity_reason():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="example.com",
                ),
            )
        ]
    )

    target = create_target("example.com")

    decision = ScopeEngine().check(scope, target)

    assert "S001" in decision.reason
    assert "specificity" in decision.reason


def test_find_matching_rules_contains_specificity():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="example.com",
                ),
            )
        ]
    )

    target = create_target("example.com")

    matches = ScopeEngine().find_matching_rules(
        scope,
        target,
    )

    assert matches[0]["specificity"] == 100


def test_conditional_matching_rule_produces_unknown():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOST_WILDCARD,
                    value="*.example.com",
                ),
                condition="must be hosted by authorized infrastructure",
            )
        ]
    )

    target = create_target("www.example.com")

    decision = ScopeEngine().check(scope, target)

    assert decision.state == DecisionState.UNKNOWN
    assert decision.winning_rule is None
    assert decision.matched_rules == ["S001"]


def test_unknown_reason_explains_unresolved_condition():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="example.com",
                ),
                condition="ownership must be verified",
            )
        ]
    )

    target = create_target("example.com")

    decision = ScopeEngine().check(scope, target)

    assert decision.state == DecisionState.UNKNOWN
    assert "condition" in decision.reason
    assert "cannot be evaluated" in decision.reason


def test_less_specific_conditional_rule_does_not_override_specific_rule():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOST_WILDCARD,
                    value="*.example.com",
                ),
                condition="ownership must be verified",
            ),
            ScopeRule(
                id="S002",
                effect=Effect.EXCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="admin.example.com",
                ),
            ),
        ]
    )

    target = create_target("admin.example.com")

    decision = ScopeEngine().check(scope, target)

    assert decision.state == DecisionState.OUT_OF_SCOPE
    assert decision.winning_rule == "S002"


def test_highest_specificity_conditional_rule_produces_unknown():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOST_WILDCARD,
                    value="*.example.com",
                ),
            ),
            ScopeRule(
                id="S002",
                effect=Effect.EXCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="admin.example.com",
                ),
                condition="ownership must be verified",
            ),
        ]
    )

    target = create_target("admin.example.com")

    decision = ScopeEngine().check(scope, target)

    assert decision.state == DecisionState.UNKNOWN
    assert decision.winning_rule is None
    assert decision.matched_rules == ["S001", "S002"]


def test_conditional_rule_on_unmatched_asset_has_no_effect():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="example.com",
                ),
                condition="ownership must be verified",
            )
        ]
    )

    target = create_target("example.org")

    decision = ScopeEngine().check(scope, target)

    assert decision.state == DecisionState.OUT_OF_SCOPE
    assert decision.winning_rule is None
    assert decision.matched_rules == []


def test_unconditional_rule_still_works():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="example.com",
                ),
            )
        ]
    )

    target = create_target("example.com")

    decision = ScopeEngine().check(scope, target)

    assert decision.state == DecisionState.IN_SCOPE


def test_invalid_scope_is_rejected_before_matching():
    scope = create_scope(
        [
            ScopeRule(
                id="",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="example.com",
                ),
            )
        ]
    )

    target = create_target("example.com")

    with pytest.raises(ScopeValidationError):
        ScopeEngine().check(scope, target)


def test_invalid_scope_asset_is_rejected_before_matching():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="https://example.com",
                ),
            )
        ]
    )

    target = create_target("example.com")

    with pytest.raises(ScopeValidationError):
        ScopeEngine().check(scope, target)


def test_invalid_target_is_rejected_before_matching():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="example.com",
                ),
            )
        ]
    )

    target = create_target(
        "example.com/login",
        target_type="hostname",
    )

    with pytest.raises(ScopeValidationError):
        ScopeEngine().check(scope, target)


def test_unsupported_target_type_is_rejected_before_matching():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="example.com",
                ),
            )
        ]
    )

    target = create_target(
        "example.com",
        target_type="unknown",
    )

    with pytest.raises(ScopeValidationError):
        ScopeEngine().check(scope, target)


def test_engine_accepts_raw_hostname():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOSTNAME,
                    value="example.com",
                ),
            )
        ]
    )

    decision = ScopeEngine().check(
        scope,
        "Example.COM",
    )

    assert decision.state == DecisionState.IN_SCOPE
    assert decision.target.normalized_value == "example.com"
    assert decision.target.type == "hostname"


def test_engine_accepts_raw_url():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.URL,
                    value="https://example.com/login",
                ),
            )
        ]
    )

    decision = ScopeEngine().check(
        scope,
        "HTTPS://Example.COM/login",
    )

    assert decision.state == DecisionState.IN_SCOPE
    assert decision.target.normalized_value == (
        "https://example.com/login"
    )
    assert decision.target.type == "url"


def test_engine_accepts_raw_ipv4():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.IPV4_CIDR,
                    value="192.168.1.0/24",
                ),
            )
        ]
    )

    decision = ScopeEngine().check(
        scope,
        "192.168.1.10",
    )

    assert decision.state == DecisionState.IN_SCOPE
    assert decision.target.normalized_value == (
        "192.168.1.10"
    )
    assert decision.target.type == "ipv4"


def test_engine_rejects_raw_cidr_target():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.IPV4_CIDR,
                    value="192.168.1.0/24",
                ),
            )
        ]
    )

    with pytest.raises(ValueError):
        ScopeEngine().check(
            scope,
            "192.168.1.0/24",
        )


def test_engine_rejects_raw_wildcard_target():
    scope = create_scope(
        [
            ScopeRule(
                id="S001",
                effect=Effect.INCLUDE,
                asset=Asset(
                    type=AssetType.HOST_WILDCARD,
                    value="*.example.com",
                ),
            )
        ]
    )

    with pytest.raises(ValueError):
        ScopeEngine().check(
            scope,
            "*.example.com",
        )