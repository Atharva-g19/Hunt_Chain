from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .generator import generate_report
from .markdown_renderer import render_markdown_report
from .json_renderer import render_json_report
from .models import ReportData
from .redaction_guard import assert_no_unredacted_secrets


def write_report_artifacts(
    output_directory: str | Path,
    authorization_data: dict[str, Any] | str | Path,
    attack_surface_data: dict[str, Any] | str | Path | None = None,
    vulnerability_data: dict[str, Any] | str | Path | None = None,
    validation_data: dict[str, Any] | str | Path | None = None,
) -> tuple[Path, Path, ReportData]:
    """
    Generate and write both report.md and report.json into output_directory.
    Applies the fail-loud secret safety net prior to writing files.
    """
    out_dir = Path(output_directory)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Helper to resolve file paths or dicts
    def _resolve(val: dict[str, Any] | str | Path | None) -> dict[str, Any]:
        if val is None:
            return {}
        if isinstance(val, dict):
            return val
        p = Path(val)
        if p.is_file():
            with p.open("r", encoding="utf-8-sig") as f:
                return json.load(f)
        return {}

    auth_dict = _resolve(authorization_data)
    recon_dict = _resolve(attack_surface_data)
    vuln_dict = _resolve(vulnerability_data)
    val_dict = _resolve(validation_data)

    # 1. Generate ReportData model (enforces ScopeGuard gate)
    report_data = generate_report(
        authorization_data=auth_dict,
        attack_surface_data=recon_dict,
        vulnerability_data=vuln_dict,
        validation_data=val_dict,
    )

    # 2. Render Markdown and JSON representations
    md_content = render_markdown_report(report_data)
    json_content = render_json_report(report_data)

    # 3. Fail-Loud Safety Net: Assert zero unredacted secrets before writing
    assert_no_unredacted_secrets(md_content, "report.md")
    assert_no_unredacted_secrets(json_content, "report.json")

    # 4. Write files
    md_path = out_dir / "report.md"
    json_path = out_dir / "report.json"

    md_path.write_text(md_content, encoding="utf-8")
    json_path.write_text(json_content, encoding="utf-8")

    import os
    if os.name != "nt" and hasattr(os, "chmod"):
        try:
            os.chmod(out_dir, 0o700)
            os.chmod(md_path, 0o600)
            os.chmod(json_path, 0o600)
        except OSError:
            pass

    return md_path, json_path, report_data
