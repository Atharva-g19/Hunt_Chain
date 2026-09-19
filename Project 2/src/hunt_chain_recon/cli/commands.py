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
from hunt_chain_recon.authorization.artifact import (
    AuthorizationArtifactError,
    ScopeGuardArtifactLoader,
)
from hunt_chain_recon.authorization.models import AuthorizationResult
from hunt_chain_recon.config.loader import (
    ConfigurationError,
    load_config,
)
from hunt_chain_recon.config.models import (
    AuthorizationConfig,
    ReconConfig,
    TargetConfig,
)


DEFAULT_CONFIG_PATH = (
    Path(__file__).resolve().parents[3] / "config" / "default.yaml"
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
        "authorization_artifact_positional",
        nargs="?",
        metavar="AUTHORIZATION_ARTIFACT",
        help=(
            "Path to the Project 1 ScopeGuard "
            "authorization_result.json artifact."
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
        help=(
            "Optional path to the YAML reconnaissance configuration. "
            "The default recon configuration is used when omitted."
        ),
    )

    parser.add_argument(
        "--authorization-artifact",
        metavar="PATH",
        help=(
            "Path to the Project 1 ScopeGuard "
            "authorization_result.json artifact."
        ),
    )

    parser.add_argument(
        "--output",
        metavar="PATH",
        help="Override the output directory configured in YAML.",
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


def _artifact_target_type(
    authorization: AuthorizationResult,
) -> str:
    """Return the Project 2 target type represented by an artifact."""
    artifact_type = authorization.metadata.get("target_type")

    if not isinstance(artifact_type, str):
        raise AuthorizationArtifactError(
            "Authorization artifact target.type must be a string."
        )

    normalized_type = artifact_type.strip().upper()

    type_mapping = {
        "DOMAIN": "DOMAIN",
        "HOSTNAME": "HOSTNAME",
        "IP_ADDRESS": "IP_ADDRESS",
        "IP": "IP_ADDRESS",
        "IPV4": "IP_ADDRESS",
        "IPV6": "IP_ADDRESS",
        "URL": "URL",
    }

    try:
        return type_mapping[normalized_type]
    except KeyError as exc:
        raise AuthorizationArtifactError(
            "Authorization artifact target.type is unsupported: "
            f"{artifact_type!r}."
        ) from exc


def _apply_artifact_context(
    config: ReconConfig,
    authorization: AuthorizationResult,
    *,
    explicit_config: bool,
) -> ReconConfig:
    """Bind artifact authorization and target context to recon config."""
    target_type = _artifact_target_type(authorization)

    configured_target = (
        config.target.value.strip().lower().rstrip(".")
    )

    authorized_target = (
        authorization.target.strip().lower().rstrip(".")
    )

    if explicit_config and configured_target != authorized_target:
        raise ConfigurationError(
            "Configured target does not match authorization artifact target."
        )

    if explicit_config and config.target.type != target_type:
        raise ConfigurationError(
            "Configured target type does not match authorization artifact "
            "target type."
        )

    return config.model_copy(
        update={
            "target": TargetConfig(
                value=authorization.target,
                type=target_type,
            ),
            "authorization": AuthorizationConfig(
                provider=authorization.provider,
                reference=authorization.reference,
            ),
        }
    )


def run_cli(args: argparse.Namespace) -> int:
    """Execute the CLI using parsed arguments."""

    positional_artifact = getattr(
        args,
        "authorization_artifact_positional",
        None,
    )

    flagged_artifact = getattr(
        args,
        "authorization_artifact",
        None,
    )

    if (
        positional_artifact is not None
        and flagged_artifact is not None
    ):
        print(
            "Configuration error: authorization artifact was supplied "
            "both positionally and with --authorization-artifact."
        )
        return 2

    authorization_artifact = (
        positional_artifact
        if positional_artifact is not None
        else flagged_artifact
    )

    config_path = (
        Path(args.config)
        if args.config
        else DEFAULT_CONFIG_PATH
    )

    explicit_config = args.config is not None

    try:
        config = load_config(config_path)

        if authorization_artifact is not None:
            artifact_path = Path(authorization_artifact)

            authorization = ScopeGuardArtifactLoader().load(
                artifact_path
            )

            config = _apply_artifact_context(
                config,
                authorization,
                explicit_config=explicit_config,
            )

        else:
            if not explicit_config:
                print(
                    "Configuration error: no authorization artifact was "
                    "provided and no explicit --config was supplied."
                )
                return 2

            authorization = ScopeGuardAdapter().evaluate(
                config.target.value,
                config.authorization,
            )

            if not authorization.is_authorized:
                print(
                    "Authorization denied: target is not authorized."
                )
                return 3

        output_directory = (
            str(args.output)
            if args.output is not None
            else str(config.output.directory)
        )

        runner = ApplicationRunner()

        result = runner.run(
            config,
            authorization,
            output_directory=output_directory,
            json_enabled=not args.no_json,
            report_enabled=not args.no_report,
        )

        if result.pipeline_blocked:
            print(
                "Pipeline blocked by execution policy."
            )
            return 3

        if not result.pipeline_completed:
            print(
                "Project 2 pipeline did not complete."
            )
            return 4

        if result.output is not None:
            print("Reconnaissance completed successfully.")
            print(
                f"JSON output: {result.output.json_path}"
                if result.output.json_path is not None
                else "JSON output: disabled"
            )
            print(
                f"Report output: {result.output.report_path}"
                if result.output.report_path is not None
                else "Report output: disabled"
            )
        else:
            print("Reconnaissance completed successfully.")

        return 0

    except ConfigurationError as exc:
        print(f"Configuration error: {exc}")
        return 2

    except AuthorizationError as exc:
        print(f"Authorization error: {exc}")
        return 3

    except AuthorizationArtifactError as exc:
        print(f"Authorization artifact error: {exc}")
        return 2

    except ApplicationRunnerError as exc:
        print(f"Application error: {exc}")
        return 4


def main() -> None:
    """Parse command-line arguments and execute the CLI."""
    parser = build_parser()
    args = parser.parse_args()
    raise SystemExit(run_cli(args))


if __name__ == "__main__":
    main()
