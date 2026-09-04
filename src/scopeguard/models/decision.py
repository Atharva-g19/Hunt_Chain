from dataclasses import dataclass, field

from .decision_state import DecisionState
from .target import Target


@dataclass
class Decision:
    state: DecisionState
    target: Target
    matched_rules: list[str] = field(default_factory=list)
    winning_rule: str | None = None
    reason: str = ""