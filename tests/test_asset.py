from scopeguard.models.asset import Asset
from scopeguard.models.asset_type import AssetType


def test_asset_creation():
    asset = Asset(
        type=AssetType.HOSTNAME,
        value="example.com"
    )

    assert asset.type == AssetType.HOSTNAME
    assert asset.value == "example.com"