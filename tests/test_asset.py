from scopeguard.models.asset import Asset


def test_asset_creation():
    asset = Asset(
        type="hostname",
        value="example.com"
    )

    assert asset.type == "hostname"
    assert asset.value == "example.com"