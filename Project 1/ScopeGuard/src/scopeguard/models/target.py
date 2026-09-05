from dataclasses import dataclass


@dataclass
class Target:
    raw_value: str
    normalized_value: str
    type: str