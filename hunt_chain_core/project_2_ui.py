from __future__ import annotations

from pathlib import Path

from hunt_chain_core.project_2_execution import (
    run_project_2,
)


def _run_project_2(
    manager,
    assessment_name: str,
) -> None:
    print()
    print("Project 2 — Recon")
    print("----------------------------------------")

    runs_directory = Path(
        manager.runs_directory
    ).resolve()

    assessment_directory = (
        runs_directory / assessment_name
    ).resolve()

    authorization_artifact = (
        assessment_directory
        / "authorization_result.json"
    )

    if not authorization_artifact.is_file():
        print(
            "Cannot run Project 2:"
        )
        print(
            "Project 1 authorization result "
            "does not exist for this assessment."
        )
        print(
            "Run Project 1 first."
        )
        return

    try:
        result = run_project_2(
            assessment_name,
            runs_directory=runs_directory,
        )
    except FileNotFoundError as exc:
        print(f"Project 2 failed: {exc}")
        return
    except RuntimeError as exc:
        print(f"Project 2 failed: {exc}")
        return

    print()
    print("=" * 60)
    print("Project 2 Reconnaissance COMPLETED")
    print("=" * 60)
    try:
        import json
        from urllib.parse import urlsplit
        with result.open("r", encoding="utf-8-sig") as h:
            doc = json.load(h)

        target_obj = doc.get("target", {})
        target_val = target_obj.get("value") or target_obj.get("host") or ""
        target_host = urlsplit(target_val).hostname or target_val or "N/A"

        endpoints = doc.get("endpoints")
        if not endpoints and isinstance(target_obj, dict):
            endpoints = target_obj.get("endpoints", [])
        if not endpoints:
            endpoints = []

        hosts = set()
        for asset in doc.get("assets", []):
            val = asset.get("value") or asset.get("normalized_value")
            if val:
                hosts.add(val)
        for ep in endpoints:
            hname = ep.get("hostname")
            if not hname:
                u = ep.get("url", "")
                hname = urlsplit(u).hostname
            if hname:
                hosts.add(hname)
        for dns in doc.get("dns_observations", []):
            hname = dns.get("hostname")
            if hname:
                hosts.add(hname)
        if target_host and target_host != "N/A":
            hosts.add(target_host)

        print(f"Target Host       : {target_host}")
        print(f"Subdomains/Hosts  : {len(hosts)}")
        for h in sorted(hosts)[:5]:
            print(f"  - {h}")
        if len(hosts) > 5:
            print(f"  ... and {len(hosts) - 5} more")
        print(f"Total Endpoints   : {len(endpoints)}")
    except Exception:
        pass
    print(f"Output: {result}")
    print()
    print("=" * 60)
    print("--> NEXT STEP: Proceed to Option 3 (Security Testing)")
    print("    to run vulnerability checks across 22 categories.")
    print("=" * 60)
