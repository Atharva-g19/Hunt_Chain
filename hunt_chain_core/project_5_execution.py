from __future__ import annotations

import json
import os
import sys
from pathlib import Path

from hunt_chain_core.workflow import AssessmentWorkflow

PROJECT_ROOT = Path(__file__).resolve().parents[1]
PROJECT_5_ROOT = PROJECT_ROOT / "Project_5_Reporting"
PROJECT_5_SRC = PROJECT_5_ROOT / "src"

# Add Project 5 to sys.path so we can import hunt_chain_reporting directly
if str(PROJECT_5_SRC) not in sys.path:
    sys.path.insert(0, str(PROJECT_5_SRC))

from hunt_chain_reporting.writer import write_report_artifacts
from hunt_chain_reporting.models import ReportData


def run_project_5(
    assessment_name: str,
    runs_directory: str | Path = "Hunt_Chain_Runs",
) -> tuple[Path, Path, ReportData]:
    """
    Execute Project 5 Reporting against an assessment run directory.
    Consumes Project 1 authorization, Project 2 attack surface, Project 3 findings,
    and Project 4 validation proofs, then produces report.md and report.json.
    """
    runs_path = Path(runs_directory)
    if not runs_path.is_absolute():
        runs_path = (PROJECT_ROOT / runs_path).resolve()

    workflow = AssessmentWorkflow(runs_directory=runs_path)
    assessment_dir = workflow.assessment_path(assessment_name)

    # 1. Resolve required ScopeGuard authorization result
    auth_file = assessment_dir / "authorization_result.json"
    if not auth_file.is_file():
        raise FileNotFoundError(
            f"ScopeGuard authorization artifact not found in assessment '{assessment_name}'. "
            "Run Stage 1 (ScopeGuard) first."
        )

    # 2. Resolve optional upstream artifacts
    recon_file = assessment_dir / "attack_surface.json"
    vuln_file = assessment_dir / "vulnerability_result.json"
    val_file = assessment_dir / "project4_validation.json"

    # 3. Generate and write report.md and report.json
    md_path, json_path, report_data = write_report_artifacts(
        output_directory=assessment_dir,
        authorization_data=auth_file,
        attack_surface_data=recon_file if recon_file.is_file() else None,
        vulnerability_data=vuln_file if vuln_file.is_file() else None,
        validation_data=val_file if val_file.is_file() else None,
    )

    # 4. Register Project 5 result with the workflow
    workflow.register_project_5(
        assessment_name,
        json_path,
    )

    return md_path, json_path, report_data
