import json

from ..models.decision import Decision


class DecisionSerializer:
    def to_dict(self, decision: Decision) -> dict:
        return {
            "state": decision.state.value,
            "target": {
                "raw_value": decision.target.raw_value,
                "normalized_value": decision.target.normalized_value,
                "type": decision.target.type,
            },
            "matched_rules": list(decision.matched_rules),
            "winning_rule": decision.winning_rule,
            "reason": decision.reason,
        }

    def to_json(self, decision: Decision) -> str:
        return json.dumps(
            self.to_dict(decision),
            indent=2,
        )