from __future__ import annotations

import re
import subprocess
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

        subprocess.Popen(
            ["notepad.exe", str(path)]
        )

        return path

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
