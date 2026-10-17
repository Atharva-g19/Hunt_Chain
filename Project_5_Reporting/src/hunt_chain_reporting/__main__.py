from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .writer import write_report_artifacts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hunt-chain-reporting",
        description="Project 5 — Findings & Reporting Manager for Hunt_Chain",
    )
    parser.add_argument(
        "-a",
        "--assessment",
        type=str,
        default=None,
        help="Name of the assessment inside the runs directory",
    )
    parser.add_argument(
        "-r",
        "--runs-dir",
        type=str,
        default="Hunt_Chain_Runs",
        help="Path to Hunt_Chain_Runs directory",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=str,
        default=None,
        help="Directory where report.md and report.json will be saved (defaults to assessment dir)",
    )
    parser.add_argument(
        "--auth-file",
        type=str,
        default=None,
        help="Direct path to authorization_result.json",
    )
    parser.add_argument(
        "--recon-file",
        type=str,
        default=None,
        help="Direct path to attack_surface.json",
    )
    parser.add_argument(
        "--vuln-file",
        type=str,
        default=None,
        help="Direct path to vulnerability_result.json",
    )
    parser.add_argument(
        "--val-file",
        type=str,
        default=None,
        help="Direct path to project4_validation.json",
    )

    args = parser.parse_args(argv)

    runs_path = Path(args.runs_dir).resolve()

    if args.assessment:
        assessment_dir = runs_path / args.assessment
        if not assessment_dir.is_dir():
            print(f"Error: Assessment directory not found: {assessment_dir}", file=sys.stderr)
            return 1

        auth_path = Path(args.auth_file) if args.auth_file else assessment_dir / "authorization_result.json"
        recon_path = Path(args.recon_file) if args.recon_file else assessment_dir / "attack_surface.json"
        vuln_path = Path(args.vuln_file) if args.vuln_file else assessment_dir / "vulnerability_result.json"
        val_path = Path(args.val_file) if args.val_file else assessment_dir / "project4_validation.json"

        out_dir = Path(args.output_dir) if args.output_dir else assessment_dir
    else:
        if not args.auth_file or not args.output_dir:
            print("Error: Either specify --assessment or provide both --auth-file and --output-dir.", file=sys.stderr)
            return 1
        auth_path = Path(args.auth_file)
        recon_path = Path(args.recon_file) if args.recon_file else None
        vuln_path = Path(args.vuln_file) if args.vuln_file else None
        val_path = Path(args.val_file) if args.val_file else None
        out_dir = Path(args.output_dir)

    try:
        md_file, json_file, report_data = write_report_artifacts(
            output_directory=out_dir,
            authorization_data=auth_path,
            attack_surface_data=recon_path,
            vulnerability_data=vuln_path,
            validation_data=val_path,
        )
        print(f"Report generation successful:")
        print(f"  Markdown: {md_file}")
        print(f"  JSON:     {json_file}")
        print(f"  Total Confirmed: {report_data.executive_summary.confirmed_count}")
        print(f"  Candidates:      {report_data.executive_summary.not_confirmed_count}")
        print(f"  Manual Items:    {report_data.executive_summary.manual_only_count}")
        return 0
    except Exception as exc:
        print(f"Report generation failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
