"""Command-line interface for Hunt_Chain Project 2."""

from __future__ import annotations

import argparse
from pathlib import Path

from hunt_chain_recon import __version__
from hunt_chain_recon.application.runner import (
    ApplicationRunner,
    ApplicationRunnerError,
)
from hunt_chain_recon.authorization.adapter import (
    AuthorizationError,
    ScopeGuardAdapter,
)
from hunt_chain_recon.config.loader import (
    ConfigurationError,
    load_config,
)


def build_parser() -> argparse.ArgumentParser:
    """Build and return the Project 2 argument parser."""
    parser = argparse.ArgumentParser(
        prog="hunt-chain-recon",
        description=(
            "Hunt_Chain Project 2 - "
            "Recon & Attack Surface Suite"
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version=__version__,
        help="Display the Project 2 version and exit.",
    )

    parser.add_argument(
        "--config",
        metavar="PATH",
        required=True,
        help="Path to the YAML reconnaissance configuration.",
    )

    parser.add_argument(
        "--output",
        metavar="PATH",
        help=(
            "Override the output directory configured in YAML."
        ),
    )

    parser.add_argument(
        "--no-json",
        action="store_true",
        help="Disable JSON Attack Surface output.",
    )

    parser.add_argument(
        "--no-report",
        action="store_true",
        help="Disable human-readable reconnaissance report.",
    )

    return parser


def run_cli(args: argparse.Namespace) -> int:
    """Execute the CLI using parsed arguments."""
    try:
        config = load_config(args.config)
    except ConfigurationError as exc:
        print(f"Configuration error: {exc}")
        return 2

    target = (
        config.target.value.strip().lower().rstrip(".")
    )

    print("Hunt_Chain Project 2")
    print("--------------------")
    print(f"Target: {target}")
    print(f"Target type: {config.target.type}")
    print(f"Execution mode: {config.execution.mode}")
    print()

    authorization_provider = ScopeGuardAdapter()

    try:
        authorization = authorization_provider.evaluate(
            target,
            config.authorization,
        )
    except AuthorizationError as exc:
        print(f"Authorization blocked: {exc}")
        return 3

    if not authorization.is_authorized:
        print(
            "Authorization blocked: "
            f"{authorization.decision.value}"
        )
        return 3

    output_directory: str | Path | None = args.output

    if output_directory is None:
        output_directory = config.output.directory

    try:
        result = ApplicationRunner().run(
            config,
            authorization,
            output_directory=output_directory,
            json_enabled=not args.no_json,
            report_enabled=not args.no_report,
        )
    except ApplicationRunnerError as exc:
        print(f"Application error: {exc}")
        return 4

    if result.pipeline_blocked:
        print("Reconnaissance blocked by execution policy.")
        return 3

    if not result.pipeline_completed:
        print("Reconnaissance did not complete.")
        return 4

    print("Reconnaissance completed successfully.")

    if result.output is not None:
        if result.output.json_path is not None:
            print(f"JSON output: {result.output.json_path}")

        if result.output.report_path is not None:
            print(f"Report output: {result.output.report_path}")

    return 0


def main() -> None:
    """Parse command-line arguments and execute the CLI."""
    parser = build_parser()
    args = parser.parse_args()
    raise SystemExit(run_cli(args))


if __name__ == "__main__":
    main()