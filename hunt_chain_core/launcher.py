from __future__ import annotations

from pathlib import Path

from hunt_chain_core import AssessmentManager
from hunt_chain_core.project_1_runner import run_project_1
from hunt_chain_core.project_2_ui import _run_project_2
from hunt_chain_core.project_3_ui import _run_project_3
from hunt_chain_core.scope_manager import ScopeManager


BANNER = r"""
╔══════════════════════════════════════════════════════╗
║                  H U N T _ C H A I N                 ║
║              Authorized Security Toolkit             ║
╚══════════════════════════════════════════════════════╝
"""

PROJECTS = {
    "1": "ScopeGuard",
    "2": "Reconnaissance",
    "3": "Vulnerability Testing",
    "4": "Validation",
    "5": "Reporting",
}


def _pause() -> None:
    input("\nPress Enter to continue...")


def _print_main_menu() -> None:
    print("\n" + "=" * 54)
    print("Hunt_Chain")
    print("=" * 54)
    print("  1. New Assessment")
    print("  2. Open Assessment")
    print("  3. List Assessments")
    print("  4. Assessment Details")
    print("  0. Exit")
    print("=" * 54)


def _print_assessment_header(
    manager: AssessmentManager,
    name: str,
) -> None:
    try:
        manifest = manager.manifest(name)
    except Exception:
        manifest = {}

    projects = manifest.get("projects", {})

    def stage_status(project_id: str) -> str:
        project = projects.get(project_id)

        if not project:
            return "NOT RUN"

        return str(
            project.get("status", "UNKNOWN")
        ).upper()

    authorization_status = "NOT RUN"

    if "project_1" in projects:
        try:
            result_path = (
                manager.get(name)
                / "authorization_result.json"
            )

            if result_path.is_file():
                import json

                with result_path.open(
                    "r",
                    encoding="utf-8-sig",
                ) as handle:
                    authorization = json.load(handle)

                authorization_status = str(
                    authorization.get(
                        "state",
                        "UNKNOWN",
                    )
                ).upper()
        except (OSError, ValueError, TypeError):
            authorization_status = "UNKNOWN"

    print("\n" + "=" * 60)
    print(f"Assessment: {name}")
    print("=" * 60)

    print(
        f"  Authorization : {authorization_status}"
    )
    print(
        f"  Recon         : {stage_status('project_2')}"
    )
    print(
        f"  Security Test : {stage_status('project_3')}"
    )

    print()
    print("  1. Scope")
    print("  2. Reconnaissance")
    print("  3. Security Testing")
    print("  4. Validation")
    print("  5. Reporting")
    print("  0. Back")
    print("=" * 60)

def _create_assessment(
    manager: AssessmentManager,
) -> None:
    print("\n" + "=" * 54)
    print("New Assessment")
    print("=" * 54)

    name = input("Assessment name: ").strip()

    if not name:
        print("Assessment name is required.")
        return

    try:
        manager.create(name)
    except (ValueError, FileExistsError) as exc:
        print(f"\nCannot create assessment: {exc}")
        return

    print(f"\nAssessment '{name}' created.")
    _open_assessment(manager, name)


def _list_assessments(
    manager: AssessmentManager,
) -> None:
    print("\n" + "=" * 54)
    print("Assessments")
    print("=" * 54)

    assessments = manager.list_assessments()

    if not assessments:
        print("No assessments found.")
        return

    for index, name in enumerate(assessments, start=1):
        try:
            manifest = manager.manifest(name)
            status = manifest.get("status", "UNKNOWN")
        except Exception:
            status = "UNKNOWN"

        print(f"  {index}. {name} [{status}]")

    print("\n  0. Back")


def _show_assessment_details(
    manager: AssessmentManager,
) -> None:
    assessments = manager.list_assessments()

    if not assessments:
        print("\nNo assessments found.")
        return

    print("\n" + "=" * 54)
    print("Assessment Details")
    print("=" * 54)

    for index, name in enumerate(assessments, start=1):
        try:
            manifest = manager.manifest(name)
        except Exception:
            continue

        projects = manifest.get("projects", {})

        print()
        print(f"{index}. {name}")
        print(
            f"   Status : "
            f"{manifest.get('status', 'UNKNOWN')}"
        )
        print(
            f"   Created: "
            f"{manifest.get('created_at', 'UNKNOWN')}"
        )

        authorization = "NOT RUN"

        try:
            result_path = (
                manager.get(name)
                / "authorization_result.json"
            )

            if result_path.is_file():
                import json

                with result_path.open(
                    "r",
                    encoding="utf-8-sig",
                ) as handle:
                    result = json.load(handle)

                authorization = str(
                    result.get(
                        "state",
                        "UNKNOWN",
                    )
                ).upper()
        except (
            OSError,
            ValueError,
            TypeError,
        ):
            authorization = "UNKNOWN"

        print(
            f"   ScopeGuard      : {authorization}"
        )
        print(
            f"   Reconnaissance  : "
            f"{'COMPLETED' if 'project_2' in projects else 'NOT RUN'}"
        )
        print(
            f"   Security Testing: "
            f"{'COMPLETED' if 'project_3' in projects else 'NOT RUN'}"
        )

    print("\n" + "=" * 54)
    _pause()

def _choose_assessment(
    manager: AssessmentManager,
) -> str | None:
    assessments = manager.list_assessments()

    if not assessments:
        print("\nNo assessments found.")
        return None

    print("\n" + "=" * 54)
    print("Open Assessment")
    print("=" * 54)

    for index, name in enumerate(assessments, start=1):
        try:
            manifest = manager.manifest(name)
            status = manifest.get("status", "UNKNOWN")
        except Exception:
            status = "UNKNOWN"

        print(f"  {index}. {name} [{status}]")

    print("  0. Back")
    print("=" * 54)

    choice = input("Select assessment: ").strip()

    if choice == "0":
        return None

    try:
        index = int(choice)
    except ValueError:
        print("Invalid selection.")
        return None

    if not 1 <= index <= len(assessments):
        print("Invalid selection.")
        return None

    return assessments[index - 1]


def _scope_menu(
    scope_manager: ScopeManager,
) -> Path | None:
    while True:
        print("\n" + "=" * 54)
        print("ScopeGuard")
        print("=" * 54)
        print("  1. Create New Scope")
        print("  2. Edit Existing Scope")
        print("  0. Back")
        print("=" * 54)

        choice = input("ScopeGuard> ").strip()

        if choice == "0":
            return None

        if choice == "1":
            return _create_scope(scope_manager)

        if choice == "2":
            return _edit_scope(scope_manager)

        print("Invalid selection.")


def _create_scope(
    scope_manager: ScopeManager,
) -> Path | None:
    print("\nCreate New Scope")
    print("-" * 54)

    name = input("Scope name: ").strip()

    try:
        path = scope_manager.create(name)
    except (ValueError, FileExistsError) as exc:
        print(f"\nCannot create scope: {exc}")
        return None

    print(f"\nScope '{name}' created.")
    print("Opening scope definition...")

    try:
        scope_manager.open_in_editor(name)
    except (FileNotFoundError, OSError) as exc:
        print(f"Could not open editor: {exc}")
        print(f"Scope created successfully: {path}")
        return path

    input(
        "\nEdit and save the YAML, then press Enter to continue..."
    )

    return path


def _edit_scope(
    scope_manager: ScopeManager,
) -> Path | None:
    scopes = scope_manager.list_scopes()

    if not scopes:
        print("\nNo scopes available.")
        return None

    print("\nAvailable Scopes")
    print("-" * 54)

    for index, name in enumerate(scopes, start=1):
        print(f"  {index}. {name}")

    print("  0. Back")

    choice = input("Select scope: ").strip()

    if choice == "0":
        return None

    try:
        index = int(choice)
    except ValueError:
        print("Invalid selection.")
        return None

    if not 1 <= index <= len(scopes):
        print("Invalid selection.")
        return None

    name = scopes[index - 1]

    try:
        scope_manager.open_in_editor(name)
    except (FileNotFoundError, OSError) as exc:
        print(f"Could not open scope editor: {exc}")
        return None

    input(
        "\nEdit and save the YAML, then press Enter to continue..."
    )

    return scope_manager.path_for(name)


def _run_project_1(
    manager: AssessmentManager,
    assessment_name: str,
) -> None:
    print("\n" + "=" * 54)
    print("ScopeGuard")
    print("=" * 54)

    scope_manager = ScopeManager()

    # Select an existing scope or create/edit one.
    scope_path = _scope_menu(scope_manager)

    if scope_path is None:
        return

    scope_name = scope_path.stem

    try:
        targets = scope_manager.included_targets(scope_name)
    except (
        FileNotFoundError,
        ValueError,
        OSError,
    ) as exc:
        print(f"\nCould not load scope: {exc}")
        return

    if not targets:
        print("\nThe selected scope contains no included assets.")
        print("Add at least one include rule before running ScopeGuard.")
        return

    print("\nAuthorized Scope Assets")
    print("-" * 54)

    for index, item in enumerate(targets, start=1):
        print(
            f"  {index}. "
            f"[{item['type']}] "
            f"{item['value']}"
        )

    print("  0. Back")

    if len(targets) == 1:
        selected = targets[0]

        print(
            "\nSelected target:"
            f"\n  {selected['value']}"
        )
    else:
        choice = input(
            "\nSelect target: "
        ).strip()

        if choice == "0":
            return

        try:
            index = int(choice)
        except ValueError:
            print("Invalid selection.")
            return

        if not 1 <= index <= len(targets):
            print("Invalid selection.")
            return

        selected = targets[index - 1]

    target = selected["value"].strip()

    if not target:
        print("Selected scope asset has an empty target.")
        return

    print("\n" + "-" * 54)
    print(f"Scope : {scope_name}")
    print(f"Target: {target}")
    print("-" * 54)

    confirm = input(
        "Run ScopeGuard against this target? [y/N]: "
    ).strip().lower()

    if confirm != "y":
        print("ScopeGuard cancelled.")
        return

    print("\nRunning ScopeGuard...")

    try:
        run_project_1(
            assessment_name,
            scope_path,
            target,
            manager.runs_directory,
        )
    except (
        FileNotFoundError,
        ValueError,
        RuntimeError,
        OSError,
        PermissionError,
    ) as exc:
        print(f"\nScopeGuard failed: {exc}")
        return

    print("\nScopeGuard completed.")
    print("Authorization result registered in the assessment history.")
def _run_project_2_safe(
    manager: AssessmentManager,
    assessment_name: str,
) -> None:
    print("\n" + "=" * 54)
    print("Reconnaissance")
    print("=" * 54)

    try:
        _run_project_2(manager, assessment_name)
    except (
        FileNotFoundError,
        ValueError,
        RuntimeError,
        OSError,
    ) as exc:
        print(f"\nReconnaissance failed: {exc}")
        return

    print("\nReconnaissance stage finished.")


def _run_project_3_safe(
    manager: AssessmentManager,
    assessment_name: str,
) -> None:
    print("\n" + "=" * 54)
    print("Vulnerability Testing")
    print("=" * 54)

    try:
        _run_project_3(manager, assessment_name)
    except (
        FileNotFoundError,
        ValueError,
        RuntimeError,
        OSError,
    ) as exc:
        print(f"\nVulnerability Testing failed: {exc}")
        return

    print("\nVulnerability Testing stage finished.")


def _authorization_state(
    manager: AssessmentManager,
    assessment_name: str,
) -> str | None:
    try:
        result_path = (
            manager.get(assessment_name)
            / "authorization_result.json"
        )

        if not result_path.is_file():
            return None

        import json

        with result_path.open(
            "r",
            encoding="utf-8-sig",
        ) as handle:
            result = json.load(handle)

        state = result.get("state")

        if state is None:
            return None

        return str(state).upper()

    except (
        OSError,
        ValueError,
        TypeError,
    ):
        return None


def _project_available(
    manager: AssessmentManager,
    assessment_name: str,
    project_id: str,
) -> bool:
    try:
        manifest = manager.manifest(assessment_name)
    except Exception:
        return False

    return project_id in manifest.get(
        "projects",
        {},
    )


def _authorization_allows_testing(
    manager: AssessmentManager,
    assessment_name: str,
) -> bool:
    return (
        _authorization_state(
            manager,
            assessment_name,
        )
        == "IN_SCOPE"
    )

def _open_assessment(
    manager: AssessmentManager,
    name: str,
) -> None:
    while True:
        if not manager.exists(name):
            print(f"\nAssessment does not exist: {name}")
            return

        _print_assessment_header(manager, name)

        choice = input(f"{name}> ").strip()

        if choice == "0":
            return

        if choice == "1":
            _run_project_1(manager, name)
            continue

        if choice == "2":
            if not _project_available(
                manager,
                name,
                "project_1",
            ):
                print(
                    "\nCannot run Reconnaissance."
                    "\nRun ScopeGuard first."
                )
                continue

            if not _authorization_allows_testing(
                manager,
                name,
            ):
                state = _authorization_state(
                    manager,
                    name,
                )

                print(
                    "\nCannot run Reconnaissance."
                )
                print(
                    "ScopeGuard authorization is not IN_SCOPE."
                )
                print(
                    f"Current authorization state: {state or 'UNKNOWN'}"
                )
                continue

            _run_project_2_safe(manager, name)
            continue

        if choice == "3":
            if not _project_available(
                manager,
                name,
                "project_1",
            ):
                print(
                    "\nCannot run Vulnerability Testing."
                    "\nRun ScopeGuard first."
                )
                continue

            if not _project_available(
                manager,
                name,
                "project_2",
            ):
                print(
                    "\nCannot run Vulnerability Testing."
                    "\nRun Reconnaissance first."
                )
                continue

            _run_project_3_safe(manager, name)
            continue

        if choice == "4":
            print(
                "\nValidation is not available yet."
                "\nThe toolkit will not perform a fake execution."
            )
            continue

        if choice == "5":
            print(
                "\nReporting is not available yet."
                "\nThe toolkit will not perform a fake execution."
            )
            continue

        print("\nInvalid selection.")


def main() -> None:
    manager = AssessmentManager()

    print(BANNER)
    print("Authorized Security Testing Toolkit")
    print("Assessment → Scope → Recon → Testing → Validation → Reporting")

    while True:
        _print_main_menu()

        choice = input("hunt-chain> ").strip()

        if choice == "1":
            _create_assessment(manager)

        elif choice == "2":
            name = _choose_assessment(manager)

            if name is not None:
                _open_assessment(manager, name)

        elif choice == "3":
            _list_assessments(manager)
            _pause()

        elif choice == "4":
            _show_assessment_details(manager)

        elif choice == "0":
            print("\nExiting Hunt_Chain.")
            return

        else:
            print("\nInvalid selection.")


if __name__ == "__main__":
    main()
