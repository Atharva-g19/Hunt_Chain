from scopeguard.models.target import Target


def test_target_creation():
    target = Target(
        raw_value="HTTPS://Example.COM/",
        normalized_value="example.com",
        type="hostname"
    )

    assert target.raw_value == "HTTPS://Example.COM/"
    assert target.normalized_value == "example.com"
    assert target.type == "hostname"