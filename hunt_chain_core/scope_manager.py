from __future__ import annotations

import os
import re
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from scopeguard.loaders.yaml_scope_loader import YamlScopeLoader


PROJECT_ROOT = Path(__file__).resolve().parents[1]

SCOPE_DIRECTORY = (
    PROJECT_ROOT
    / "Project 1"
    / "ScopeGuard"
    / "scopes"
)

SCOPE_TEMPLATE = '''version: "1"

program:
  name: "Example Program"

scope:
  rules:
    - id: "S001"
      effect: "include"
      asset:
        type: "hostname"
        value: "example.com"
      description: "Explicitly listed production hostname"
'''


class ScopeManager:
    """Manage user-created ScopeGuard YAML definitions by name."""

    def __init__(
        self,
        scope_directory: str | Path = SCOPE_DIRECTORY,
    ) -> None:
        self.scope_directory = Path(scope_directory)

    @staticmethod
    def validate_name(name: str) -> str:
        name = name.strip()

        if not name:
            raise ValueError("Scope name must not be empty.")

        if len(name) > 100:
            raise ValueError(
                "Scope name must not exceed 100 characters."
            )

        if not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]*",
            name,
        ):
            raise ValueError(
                "Scope name may contain only letters, "
                "numbers, underscore, hyphen, and dot."
            )

        return name

    def path_for(self, name: str) -> Path:
        name = self.validate_name(name)
        return self.scope_directory / f"{name}.yaml"

    def exists(self, name: str) -> bool:
        try:
            return self.path_for(name).is_file()
        except ValueError:
            return False

    def list_scopes(self) -> tuple[str, ...]:
        if not self.scope_directory.is_dir():
            return ()

        return tuple(
            sorted(
                (
                    path.stem
                    for path in self.scope_directory.glob("*.yaml")
                    if path.is_file()
                ),
                key=str.lower,
            )
        )

    def create(
        self,
        name: str,
    ) -> Path:
        path = self.path_for(name)

        if path.exists():
            raise FileExistsError(
                f"Scope already exists: {name}"
            )

        self.scope_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        path.write_text(
            SCOPE_TEMPLATE,
            encoding="utf-8",
            newline="\n",
        )

        return path

    def open_in_editor(
        self,
        name: str,
    ) -> Path:
        path = self.path_for(name)

        if not path.is_file():
            raise FileNotFoundError(
                f"Scope does not exist: {name}"
            )

        self._launch_editor(path)
        return path

    @staticmethod
    def _launch_editor(path: Path) -> None:
        """
        Cross-platform editor launcher.

        1. Honors user-defined $VISUAL or $EDITOR environment variables.
        2. On Windows: uses notepad.exe or os.startfile.
        3. On macOS: uses 'open -t' (TextEdit/default editor) or terminal editors.
        4. On Linux/Unix: uses 'xdg-open' (desktop default) or terminal editors (nano, vim, etc.).
        5. Raises an OSError with helpful instructions if no editor could be found.
        """
        str_path = str(path)

        # 1. User-configured editor via VISUAL or EDITOR
        editor_env = os.environ.get("VISUAL") or os.environ.get("EDITOR")
        if editor_env:
            try:
                cmd_parts = shlex.split(editor_env)
                if cmd_parts:
                    binary = cmd_parts[0]
                    if shutil.which(binary) or Path(binary).is_file():
                        cli_editors = {
                            "vim", "vi", "nvim", "nano", "pico",
                            "emacs", "micro", "helix", "hx", "joe", "kak",
                        }
                        is_cli = Path(binary).stem.lower() in cli_editors
                        if is_cli:
                            subprocess.run(cmd_parts + [str_path])
                        else:
                            subprocess.Popen(cmd_parts + [str_path])
                        return
            except Exception:
                pass

        # 2. Windows platform defaults
        if sys.platform.startswith("win"):
            notepad = shutil.which("notepad.exe") or shutil.which("notepad")
            if notepad:
                subprocess.Popen([notepad, str_path])
                return
            if hasattr(os, "startfile"):
                try:
                    os.startfile(str_path)
                    return
                except OSError:
                    pass

        # 3. macOS platform defaults
        if sys.platform == "darwin":
            if shutil.which("open"):
                try:
                    subprocess.Popen(["open", "-t", str_path])
                    return
                except OSError:
                    pass

        # 4. Linux and other Unix defaults (xdg-open for GUI, then GUI editors, then CLI editors)
        if shutil.which("xdg-open"):
            try:
                subprocess.Popen(["xdg-open", str_path])
                return
            except OSError:
                pass

        for gui_editor in ("gedit", "kate", "mousepad", "xed", "pluma"):
            if shutil.which(gui_editor):
                try:
                    subprocess.Popen([gui_editor, str_path])
                    return
                except OSError:
                    pass

        for cli_editor in ("nano", "micro", "vim", "vi"):
            if shutil.which(cli_editor):
                try:
                    subprocess.run([cli_editor, str_path])
                    return
                except OSError:
                    pass

        raise OSError(
            f"No suitable text editor could be launched on {sys.platform}. "
            f"Please set your $EDITOR environment variable or edit '{str_path}' directly."
        )

    def load(self, name: str):
        """Load and validate a ScopeGuard definition."""
        path = self.path_for(name)

        if not path.is_file():
            raise FileNotFoundError(
                f"Scope does not exist: {name}"
            )

        return YamlScopeLoader().load(path)

    def included_targets(
        self,
        name: str,
    ) -> tuple[dict[str, str], ...]:
        """
        Return explicitly included scope assets.

        The returned records contain:
        - type
        - value
        - rule_id
        - description
        """
        scope = self.load(name)
        targets: list[dict[str, str]] = []

        for rule in scope.rules:
            effect = getattr(rule.effect, "value", rule.effect)

            if str(effect).lower() != "include":
                continue

            asset = rule.asset
            asset_type = getattr(
                asset.type,
                "value",
                asset.type,
            )

            targets.append(
                {
                    "type": str(asset_type).lower(),
                    "value": str(asset.value),
                    "rule_id": str(rule.id),
                    "description": str(
                        getattr(rule, "description", "")
                        or ""
                    ),
                }
            )

        return tuple(targets)
