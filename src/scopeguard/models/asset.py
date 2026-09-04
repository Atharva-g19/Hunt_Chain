from dataclasses import dataclass


@dataclass
class Asset:
    type: str
    value: str
    