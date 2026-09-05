from pathlib import Path

import pytest
import yaml

from scopeguard.loaders.yaml_scope_loader import YamlScopeLoader
from scopeguard.models.asset_type import AssetType
from scopeguard.models.effect import Effect
from scopeguard.validators.errors import ScopeValidationError


def write_yaml(tmp_path: Path, data) -> Path:
    path = tmp_path / "scope.yaml"

    with path.open("w", encoding="utf-8") as file:
        yaml.safe_dump(
            data,
            file,
            sort_keys=False,
        )

    return path


def test_load_valid_scope(tmp_path):
    data = {
        "version": "1",
        "program": {
            "name": "Example Program",
        },
        "scope": {
            "rules": [
                {
                    "id": "S001",
                    "effect": "include",
                    "asset": {
                        "type": "hostname",
                        "value": "example.com",
                    },
                    "description": "Main website",
                }
            ]
        },
    }

    path = write_yaml(tmp_path, data)

    scope = YamlScopeLoader().load(path)

    assert scope.version == "1"
    assert scope.program.name == "Example Program"
    assert len(scope.rules) == 1

    rule = scope.rules[0]

    assert rule.id == "S001"
    assert rule.effect == Effect.INCLUDE
    assert rule.asset.type == AssetType.HOSTNAME
    assert rule.asset.value == "example.com"
    assert rule.description == "Main website"


def test_load_multiple_rules(tmp_path):
    data = {
        "version": "1",
        "program": {
            "name": "Example Program",
        },
        "scope": {
            "rules": [
                {
                    "id": "S001",
                    "effect": "include",
                    "asset": {
                        "type": "hostname",
                        "value": "example.com",
                    },
                },
                {
                    "id": "S002",
                    "effect": "exclude",
                    "asset": {
                        "type": "host_wildcard",
                        "value": "*.internal.example.com",
                    },
                },
                {
                    "id": "S003",
                    "effect": "include",
                    "asset": {
                        "type": "ipv4_cidr",
                        "value": "192.168.1.0/24",
                    },
                },
            ]
        },
    }

    path = write_yaml(tmp_path, data)

    scope = YamlScopeLoader().load(path)

    assert len(scope.rules) == 3
    assert scope.rules[0].effect == Effect.INCLUDE
    assert scope.rules[1].effect == Effect.EXCLUDE
    assert scope.rules[2].asset.type == AssetType.IPV4_CIDR


def test_load_category_and_condition(tmp_path):
    data = {
        "version": "1",
        "program": {
            "name": "Example Program",
        },
        "scope": {
            "rules": [
                {
                    "id": "S001",
                    "effect": "include",
                    "asset": {
                        "type": "hostname",
                        "value": "api.example.com",
                        "category": "api",
                    },
                    "description": "API endpoint",
                    "condition": "manual_review",
                }
            ]
        },
    }

    path = write_yaml(tmp_path, data)

    scope = YamlScopeLoader().load(path)

    rule = scope.rules[0]

    assert rule.category == "api"
    assert rule.description == "API endpoint"
    assert rule.condition == "manual_review"


def test_missing_file_raises_error(tmp_path):
    path = tmp_path / "missing.yaml"

    with pytest.raises(FileNotFoundError):
        YamlScopeLoader().load(path)


def test_missing_version_is_rejected(tmp_path):
    data = {
        "program": {
            "name": "Example Program",
        },
        "scope": {
            "rules": [],
        },
    }

    path = write_yaml(tmp_path, data)

    with pytest.raises(ValueError, match="Scope version is required"):
        YamlScopeLoader().load(path)


def test_missing_program_is_rejected(tmp_path):
    data = {
        "version": "1",
        "scope": {
            "rules": [],
        },
    }

    path = write_yaml(tmp_path, data)

    with pytest.raises(ValueError, match="Program section is required"):
        YamlScopeLoader().load(path)


def test_missing_program_name_is_rejected(tmp_path):
    data = {
        "version": "1",
        "program": {},
        "scope": {
            "rules": [],
        },
    }

    path = write_yaml(tmp_path, data)

    with pytest.raises(ValueError, match="Program name is required"):
        YamlScopeLoader().load(path)


def test_missing_scope_section_is_rejected(tmp_path):
    data = {
        "version": "1",
        "program": {
            "name": "Example Program",
        },
    }

    path = write_yaml(tmp_path, data)

    with pytest.raises(ValueError, match="Scope section is required"):
        YamlScopeLoader().load(path)


def test_rules_must_be_a_list(tmp_path):
    data = {
        "version": "1",
        "program": {
            "name": "Example Program",
        },
        "scope": {
            "rules": {},
        },
    }

    path = write_yaml(tmp_path, data)

    with pytest.raises(ValueError, match="Scope rules must be a list"):
        YamlScopeLoader().load(path)


def test_invalid_effect_is_rejected(tmp_path):
    data = {
        "version": "1",
        "program": {
            "name": "Example Program",
        },
        "scope": {
            "rules": [
                {
                    "id": "S001",
                    "effect": "allow",
                    "asset": {
                        "type": "hostname",
                        "value": "example.com",
                    },
                }
            ]
        },
    }

    path = write_yaml(tmp_path, data)

    with pytest.raises(ValueError, match="Invalid effect"):
        YamlScopeLoader().load(path)


def test_invalid_asset_type_is_rejected(tmp_path):
    data = {
        "version": "1",
        "program": {
            "name": "Example Program",
        },
        "scope": {
            "rules": [
                {
                    "id": "S001",
                    "effect": "include",
                    "asset": {
                        "type": "unknown",
                        "value": "example.com",
                    },
                }
            ]
        },
    }

    path = write_yaml(tmp_path, data)

    with pytest.raises(ValueError, match="Invalid asset type"):
        YamlScopeLoader().load(path)


def test_invalid_asset_value_is_rejected(tmp_path):
    data = {
        "version": "1",
        "program": {
            "name": "Example Program",
        },
        "scope": {
            "rules": [
                {
                    "id": "S001",
                    "effect": "include",
                    "asset": {
                        "type": "hostname",
                        "value": "invalid..example.com",
                    },
                }
            ]
        },
    }

    path = write_yaml(tmp_path, data)

    with pytest.raises(ScopeValidationError):
        YamlScopeLoader().load(path)


def test_rule_must_be_a_mapping(tmp_path):
    data = {
        "version": "1",
        "program": {
            "name": "Example Program",
        },
        "scope": {
            "rules": [
                "not-a-rule",
            ]
        },
    }

    path = write_yaml(tmp_path, data)

    with pytest.raises(ValueError, match="Each scope rule must be a mapping"):
        YamlScopeLoader().load(path)
        