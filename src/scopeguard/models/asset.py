from dataclasses import dataclass

from .asset_type import AssetType


@dataclass
class Asset:
    type: AssetType
    value: str