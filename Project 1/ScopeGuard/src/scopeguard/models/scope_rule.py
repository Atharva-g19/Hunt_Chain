from dataclasses import dataclass
from typing import Optional

from .asset import Asset
from .effect import Effect


@dataclass
class ScopeRule:
    id: str
    effect: Effect
    asset: Asset
    category: Optional[str] = None
    description: Optional[str] = None
    condition: Optional[str] = None