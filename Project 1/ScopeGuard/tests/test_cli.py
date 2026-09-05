import json
from pathlib import Path

import pytest
import yaml

from scopeguard.cli.main import main


def write_scope(tmp_path: Path, data: dict) -> Path:
    path = tmp_path / "scope.yaml"

    with path.open("w", encoding="utf-8") as file:
        yaml.safe_dump(
            data,
            file,
            sort_keys=False,
        )

    return path


def example_scope() -> dict:
    return {
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
                },
                {
                    "id": "S002",
                    "effect": "exclude",
                    "asset": {
                        "type": "host_wildcard",
                        "value": "*.internal.example.com",
                    },
                    "description": "Internal systems",
                },
            ]
        },
    }


def test_cli_check_in_scope(tmp_path, capsys, monkeypatch):
    scope_path = write_scope(
        tmp_path,
        example_scope(),
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "scopeguard",
            "check",
            "--scope",
            str(scope_path),
            "--target",
            "example.com",
        ],
    )

    exit_code = main()

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "State: IN_SCOPE" in captured.out
    assert "Target: example.com" in captured.out
    assert "Rule: S001" in captured.out
    assert "Reason:" in captured.out


def test_cli_check_out_of_scope(tmp_path, capsys, monkeypatch):
    scope_path = write_scope(
        tmp_path,
        example_scope(),
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "scopeguard",
            "check",
            "--scope",
            str(scope_path),
            "--target",
            "test.internal.example.com",
        ],
    )

    exit_code = main()

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "State: OUT_OF_SCOPE" in captured.out
    assert "Target: test.internal.example.com" in captured.out
    assert "Rule: S002" in captured.out


def test_cli_check_unknown_target(tmp_path, capsys, monkeypatch):
    scope_path = write_scope(
        tmp_path,
        example_scope(),
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "scopeguard",
            "check",
            "--scope",
            str(scope_path),
            "--target",
            "google.com",
        ],
    )

    exit_code = main()

    captured = capsys.readouterr()

    assert exit_code == 1
    assert "State: OUT_OF_SCOPE" in captured.out
    assert "Target: google.com" in captured.out
    assert "Reason: No matching scope rule" in captured.out


def test_cli_check_json_in_scope(
    tmp_path,
    capsys,
    monkeypatch,
):
    scope_path = write_scope(
        tmp_path,
        example_scope(),
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "scopeguard",
            "check",
            "--scope",
            str(scope_path),
            "--target",
            "example.com",
            "--json",
        ],
    )

    exit_code = main()

    captured = capsys.readouterr()

    assert exit_code == 0

    result = json.loads(captured.out)

    assert result["state"] == "IN_SCOPE"
    assert result["target"]["normalized_value"] == "example.com"
    assert result["target"]["type"] == "hostname"
    assert result["matched_rules"] == ["S001"]
    assert result["winning_rule"] == "S001"


def test_cli_check_json_out_of_scope(
    tmp_path,
    capsys,
    monkeypatch,
):
    scope_path = write_scope(
        tmp_path,
        example_scope(),
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "scopeguard",
            "check",
            "--scope",
            str(scope_path),
            "--target",
            "google.com",
            "--json",
        ],
    )

    exit_code = main()

    captured = capsys.readouterr()

    assert exit_code == 1

    result = json.loads(captured.out)

    assert result["state"] == "OUT_OF_SCOPE"
    assert result["target"]["normalized_value"] == "google.com"
    assert result["matched_rules"] == []
    assert result["winning_rule"] is None
    assert result["reason"] == "No matching scope rule"


def test_cli_json_errors_go_to_stderr(
    tmp_path,
    capsys,
    monkeypatch,
):
    missing_path = tmp_path / "missing.yaml"

    monkeypatch.setattr(
        "sys.argv",
        [
            "scopeguard",
            "check",
            "--scope",
            str(missing_path),
            "--target",
            "example.com",
            "--json",
        ],
    )

    exit_code = main()

    captured = capsys.readouterr()

    assert exit_code == 2
    assert captured.out == ""
    assert "ERROR:" in captured.err


def test_cli_missing_scope_file(
    tmp_path,
    capsys,
    monkeypatch,
):
    missing_path = tmp_path / "missing.yaml"

    monkeypatch.setattr(
        "sys.argv",
        [
            "scopeguard",
            "check",
            "--scope",
            str(missing_path),
            "--target",
            "example.com",
        ],
    )

    exit_code = main()

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "ERROR:" in captured.err
    assert "Scope file not found" in captured.err


def test_cli_invalid_target(
    tmp_path,
    capsys,
    monkeypatch,
):
    scope_path = write_scope(
        tmp_path,
        example_scope(),
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "scopeguard",
            "check",
            "--scope",
            str(scope_path),
            "--target",
            "*.example.com",
        ],
    )

    exit_code = main()

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "ERROR:" in captured.err
    assert "Wildcard targets are not supported" in captured.err


def test_cli_unknown_command(monkeypatch):
    monkeypatch.setattr(
        "sys.argv",
        [
            "scopeguard",
            "unknown",
        ],
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 2