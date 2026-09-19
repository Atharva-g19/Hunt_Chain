from dataclasses import dataclass, field

from .program import Program
from .scope_rule import ScopeRule


@dataclass
class Scope:
    program: Program
    rules: list[ScopeRule] = field(default_factory=list)