import argparse
import sys

from ..engine.scope_engine import ScopeEngine
from ..loaders.yaml_scope_loader import YamlScopeLoader
from ..serializers.decision_serializer import DecisionSerializer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="scopeguard",
        description="Deterministic target authorization engine",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
    )

    check_parser = subparsers.add_parser(
        "check",
        help="Check whether a target is in scope",
    )

    check_parser.add_argument(
        "--scope",
        required=True,
        help="Path to the YAML scope definition",
    )

    check_parser.add_argument(
        "--target",
        required=True,
        help="Target to authorize",
    )

    check_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the decision as JSON",
    )

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "check":
        return _handle_check(
            scope_path=args.scope,
            target=args.target,
            json_output=args.json,
        )

    parser.error("Unknown command")
    return 2


def _handle_check(
    scope_path: str,
    target: str,
    json_output: bool = False,
) -> int:
    try:
        loader = YamlScopeLoader()
        scope = loader.load(scope_path)

        engine = ScopeEngine()
        decision = engine.check(
            scope,
            target,
        )

    except (FileNotFoundError, ValueError) as exc:
        print(
            f"ERROR: {exc}",
            file=sys.stderr,
        )
        return 2

    if json_output:
        serializer = DecisionSerializer()
        print(serializer.to_json(decision))
    else:
        _print_human_readable(decision)

    if decision.state.value == "IN_SCOPE":
        return 0

    return 1


def _print_human_readable(decision) -> None:
    print(f"State: {decision.state.value}")
    print(f"Target: {decision.target.normalized_value}")

    if decision.winning_rule is not None:
        print(f"Rule: {decision.winning_rule}")

    print(f"Reason: {decision.reason}")


if __name__ == "__main__":
    raise SystemExit(main())