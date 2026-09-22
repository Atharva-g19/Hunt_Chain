from pathlib import Path

import pytest

from hunt_chain_core.scope_manager import (
    ScopeManager,
)


def test_create_scope(tmp_path: Path):
    manager = ScopeManager(tmp_path)

    path = manager.create("Client_A_Scope")

    assert path == (
        tmp_path / "Client_A_Scope.yaml"
    )
    assert path.is_file()

    content = path.read_text(
        encoding="utf-8"
    )

    assert 'version: "1"' in content
    assert "program:" in content
    assert "scope:" in content
    assert "rules:" in content


def test_scope_names_are_listed(tmp_path: Path):
    manager = ScopeManager(tmp_path)

    manager.create("Client_A")
    manager.create("Client_B")

    assert manager.list_scopes() == (
        "Client_A",
        "Client_B",
    )


def test_duplicate_scope_rejected(tmp_path: Path):
    manager = ScopeManager(tmp_path)

    manager.create("Client_A")

    with pytest.raises(FileExistsError):
        manager.create("Client_A")


@pytest.mark.parametrize(
    "name",
    [
        "",
        " ",
        "../escape",
        "scope/name",
        "scope name",
    ],
)
def test_invalid_scope_name(
    tmp_path: Path,
    name: str,
):
    manager = ScopeManager(tmp_path)

    with pytest.raises(ValueError):
        manager.create(name)


def test_scope_lookup_by_name(tmp_path: Path):
    manager = ScopeManager(tmp_path)

    manager.create("Client_A")

    assert manager.exists("Client_A")
    assert not manager.exists("Unknown")
    assert manager.path_for("Client_A").name == (
        "Client_A.yaml"
    )
