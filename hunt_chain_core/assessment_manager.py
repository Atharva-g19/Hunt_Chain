from __future__ import annotations

import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class AssessmentManager:
    """Create and manage generic Hunt_Chain assessment workspaces."""

    def __init__(
        self,
        runs_directory: str | Path = "Hunt_Chain_Runs",
    ) -> None:
        self.runs_directory = Path(runs_directory)

    @staticmethod
    def _validate_name(name: str) -> str:
        name = name.strip()

        if not name:
            raise ValueError("Assessment name must not be empty.")

        if len(name) > 100:
            raise ValueError(
                "Assessment name must not exceed 100 characters."
            )

        if name in {".", ".."}:
            raise ValueError("Invalid assessment name.")

        if not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9_.-]*",
            name,
        ):
            raise ValueError(
                "Assessment name may contain only letters, "
                "numbers, underscore, hyphen, and dot."
            )

        return name

    def create(self, name: str) -> Path:
        name = self._validate_name(name)

        assessment_directory = self.runs_directory / name

        if assessment_directory.exists():
            raise FileExistsError(
                f"Assessment already exists: {name}"
            )

        assessment_directory.mkdir(parents=True)

        manifest: dict[str, Any] = {
            "schema_version": "v1",
            "run_name": name,
            "status": "NEW",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "projects": {},
        }

        self._write_manifest(
            assessment_directory,
            manifest,
        )

        return assessment_directory

    def get(self, name: str) -> Path:
        name = self._validate_name(name)

        path = self.runs_directory / name

        if not path.is_dir():
            raise FileNotFoundError(
                f"Assessment does not exist: {name}"
            )

        return path

    def exists(self, name: str) -> bool:
        try:
            return self.get(name).is_dir()
        except (ValueError, FileNotFoundError):
            return False

    def list_assessments(self) -> tuple[str, ...]:
        if not self.runs_directory.is_dir():
            return ()

        assessments = []

        for path in self.runs_directory.iterdir():
            if not path.is_dir():
                continue

            if not (path / "run.json").is_file():
                continue

            assessments.append(path.name)

        return tuple(sorted(assessments, key=str.lower))

    def add_project(
        self,
        assessment_name: str,
        *,
        project_id: str,
        project_name: str,
        source_file: str | Path,
        result_filename: str,
    ) -> Path:
        assessment_directory = self.get(assessment_name)

        if not project_id.strip():
            raise ValueError("project_id must not be empty.")

        if not project_name.strip():
            raise ValueError("project_name must not be empty.")

        source = Path(source_file)

        if not source.is_file():
            raise FileNotFoundError(
                f"Source result does not exist: {source}"
            )

        result_filename = Path(result_filename).name

        destination = assessment_directory / result_filename

        shutil.copy2(source, destination)

        manifest = self._read_manifest(
            assessment_directory
        )

        manifest["projects"][project_id] = {
            "name": project_name,
            "status": "COMPLETED",
            "result": result_filename,
        }

        manifest["status"] = "IN_PROGRESS"

        self._write_manifest(
            assessment_directory,
            manifest,
        )

        return destination

    def complete(self, assessment_name: str) -> Path:
        assessment_directory = self.get(assessment_name)

        manifest = self._read_manifest(
            assessment_directory
        )

        if not manifest["projects"]:
            raise ValueError(
                "Cannot complete an assessment with no projects."
            )

        manifest["status"] = "COMPLETED"

        self._write_manifest(
            assessment_directory,
            manifest,
        )

        return assessment_directory

    def manifest(
        self,
        assessment_name: str,
    ) -> dict[str, Any]:
        return self._read_manifest(
            self.get(assessment_name)
        )

    def _read_manifest(
        self,
        assessment_directory: Path,
    ) -> dict[str, Any]:
        manifest_path = assessment_directory / "run.json"

        with manifest_path.open(
            "r",
            encoding="utf-8",
        ) as handle:
            return json.load(handle)

    def _write_manifest(
        self,
        assessment_directory: Path,
        manifest: dict[str, Any],
    ) -> None:
        manifest_path = assessment_directory / "run.json"

        with manifest_path.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            json.dump(
                manifest,
                handle,
                indent=2,
            )
            handle.write("\n")
