from scopeguard.matchers.match_result import MatchResult


def test_match_result_can_represent_match():
    result = MatchResult(
        matched=True,
        reason="Exact hostname match"
    )

    assert result.matched is True
    assert result.reason == "Exact hostname match"


def test_match_result_can_represent_no_match():
    result = MatchResult(
        matched=False,
        reason="Hostname does not match"
    )

    assert result.matched is False
    assert result.reason == "Hostname does not match"


def test_match_result_reason_defaults_to_empty_string():
    result = MatchResult(matched=True)

    assert result.matched is True
    assert result.reason == ""


def test_match_result_is_immutable():
    result = MatchResult(
        matched=True,
        reason="Test"
    )

    try:
        result.matched = False
        assert False
    except AttributeError:
        pass