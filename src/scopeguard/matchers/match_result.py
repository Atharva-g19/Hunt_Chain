from dataclasses import dataclass


@dataclass(frozen=True)
class MatchResult:
    matched: bool
    reason: str = ""