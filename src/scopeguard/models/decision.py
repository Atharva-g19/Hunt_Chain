from dataclasses import dataclass, field

from .target import Target


@dataclass
class Decision:
    state: str
    target: Target
    matched_rules: list[str] = field(default_factory=list)
    winning_rule: str | None = None
    reason: str = ""