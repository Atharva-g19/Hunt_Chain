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


def test_open_in_editor_missing_file_raises(tmp_path: Path):
    manager = ScopeManager(tmp_path)
    with pytest.raises(FileNotFoundError):
        manager.open_in_editor("NonExistent")


def test_open_in_editor_honors_env_editor(tmp_path: Path, monkeypatch):
    manager = ScopeManager(tmp_path)
    manager.create("Client_Test")

    called_cmds = []

    def fake_which(cmd):
        return f"/usr/bin/{cmd}"

    def fake_run(cmd, *args, **kwargs):
        called_cmds.append(("run", cmd))

    def fake_popen(cmd, *args, **kwargs):
        called_cmds.append(("popen", cmd))

    monkeypatch.setenv("EDITOR", "nano")
    monkeypatch.setattr("shutil.which", fake_which)
    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("subprocess.Popen", fake_popen)

    path = manager.open_in_editor("Client_Test")
    assert path.is_file()
    assert len(called_cmds) == 1
    assert called_cmds[0][0] == "run"
    assert called_cmds[0][1] == ["nano", str(path)]


def test_open_in_editor_honors_gui_env_editor(tmp_path: Path, monkeypatch):
    manager = ScopeManager(tmp_path)
    manager.create("Client_Test")

    called_cmds = []

    def fake_which(cmd):
        return f"/usr/bin/{cmd}"

    def fake_popen(cmd, *args, **kwargs):
        called_cmds.append(("popen", cmd))

    monkeypatch.setenv("EDITOR", "code -w")
    monkeypatch.setattr("shutil.which", fake_which)
    monkeypatch.setattr("subprocess.Popen", fake_popen)

    path = manager.open_in_editor("Client_Test")
    assert len(called_cmds) == 1
    assert called_cmds[0][0] == "popen"
    assert called_cmds[0][1] == ["code", "-w", str(path)]


def test_open_in_editor_linux_xdg_open(tmp_path: Path, monkeypatch):
    manager = ScopeManager(tmp_path)
    manager.create("Client_Test")

    called_cmds = []

    def fake_which(cmd):
        if cmd == "xdg-open":
            return "/usr/bin/xdg-open"
        return None

    def fake_popen(cmd, *args, **kwargs):
        called_cmds.append(("popen", cmd))

    monkeypatch.delenv("EDITOR", raising=False)
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr("shutil.which", fake_which)
    monkeypatch.setattr("subprocess.Popen", fake_popen)

    path = manager.open_in_editor("Client_Test")
    assert len(called_cmds) == 1
    assert called_cmds[0][1] == ["xdg-open", str(path)]


def test_open_in_editor_macos_open(tmp_path: Path, monkeypatch):
    manager = ScopeManager(tmp_path)
    manager.create("Client_Test")

    called_cmds = []

    def fake_which(cmd):
        if cmd == "open":
            return "/usr/bin/open"
        return None

    def fake_popen(cmd, *args, **kwargs):
        called_cmds.append(("popen", cmd))

    monkeypatch.delenv("EDITOR", raising=False)
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.setattr("sys.platform", "darwin")
    monkeypatch.setattr("shutil.which", fake_which)
    monkeypatch.setattr("subprocess.Popen", fake_popen)

    path = manager.open_in_editor("Client_Test")
    assert len(called_cmds) == 1
    assert called_cmds[0][1] == ["open", "-t", str(path)]


def test_open_in_editor_no_editor_found_raises_oserror(tmp_path: Path, monkeypatch):
    manager = ScopeManager(tmp_path)
    manager.create("Client_Test")

    monkeypatch.delenv("EDITOR", raising=False)
    monkeypatch.delenv("VISUAL", raising=False)
    monkeypatch.setattr("sys.platform", "linux")
    monkeypatch.setattr("shutil.which", lambda _: None)

    with pytest.raises(OSError, match="No suitable text editor"):
        manager.open_in_editor("Client_Test")

