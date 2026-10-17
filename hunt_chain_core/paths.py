"""Centralized cross-platform path and directory resolution for Hunt_Chain."""
from __future__ import annotations

import os
import sys
from pathlib import Path


def get_repo_root() -> Path:
    """Return the absolute Path to the Hunt_Chain repository root."""
    return Path(__file__).resolve().parents[1]


def get_runs_directory(override: str | Path | None = None) -> Path:
    """
    Resolve the assessment runs directory cross-platform.

    Order of precedence:
    1. Explicit override argument passed by caller.
    2. HUNT_CHAIN_RUNS_DIR environment variable.
    3. <repo_root>/Hunt_Chain_Runs.
    """
    if override:
        path = Path(override)
        if not path.is_absolute():
            path = (get_repo_root() / path).resolve()
        return path

    env_dir = os.environ.get("HUNT_CHAIN_RUNS_DIR")
    if env_dir:
        return Path(env_dir).expanduser().resolve()

    return (get_repo_root() / "Hunt_Chain_Runs").resolve()


def get_scopes_directory() -> Path:
    """Return the standard ScopeGuard scopes directory."""
    return (get_repo_root() / "Project 1" / "ScopeGuard" / "scopes").resolve()


def resolve_repo_path(path_input: str | Path) -> Path:
    """
    Resolve a path portably.

    If the path exists as-is (e.g. absolute or relative to CWD), return it.
    Otherwise, attempt to resolve it relative to the repository root.
    """
    path = Path(path_input)
    if path.exists():
        return path.resolve()

    from_repo = (get_repo_root() / path).resolve()
    if from_repo.exists():
        return from_repo

    return path.resolve()


def secure_mkdir(path: Path, exist_ok: bool = True) -> Path:
    """
    Create a directory ensuring secure permissions (0o700) on POSIX systems.
    Safe no-op on Windows.
    """
    path = Path(path)
    path.mkdir(parents=True, exist_ok=exist_ok)
    if os.name != "nt" and hasattr(os, "chmod"):
        try:
            os.chmod(path, 0o700)
        except OSError:
            pass
    return path


def secure_write_text(
    path: Path,
    content: str,
    *,
    is_sensitive: bool = False,
    encoding: str = "utf-8",
) -> Path:
    """
    Write text to a file using UTF-8 encoding.
    Applies restrictive permissions (0o600) on POSIX if marked sensitive.
    """
    path = Path(path)
    secure_mkdir(path.parent, exist_ok=True)
    path.write_text(content, encoding=encoding)
    if is_sensitive and os.name != "nt" and hasattr(os, "chmod"):
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    return path
