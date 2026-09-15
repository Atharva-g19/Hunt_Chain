from pathlib import Path

from hunt_chain_recon.application.runner import ApplicationRunner
from hunt_chain_recon.authorization.models import (
    AuthorizationDecision,
    AuthorizationResult,
)
from hunt_chain_recon.config.loader import load_config


config = load_config(
    Path("config/lab.yaml")
)

authorization = AuthorizationResult(
    target=config.target.value.strip().lower().rstrip("."),
    decision=AuthorizationDecision.IN_SCOPE,
    provider="scopeguard",
    reference="LOCAL_LAB_TEST",
    reason="Explicitly authorized local laboratory target.",
)

result = ApplicationRunner().run(
    config,
    authorization,
    output_directory=Path("output/lab"),
)

print()
print("=== Hunt_Chain Project 2 Lab Test ===")
print(f"Pipeline completed: {result.pipeline_completed}")
print(f"Pipeline blocked:   {result.pipeline_blocked}")
print()

if result.attack_surface is not None:
    surface = result.attack_surface

    print(f"Assets:          {len(surface.assets)}")
    print(f"DNS observations:{len(surface.dns_observations)}")
    print(f"Services:        {len(surface.services)}")
    print(f"Endpoints:       {len(surface.endpoints)}")
    print(f"HTTP observations:{len(surface.http_observations)}")
    print(f"Technologies:    {len(surface.technologies)}")
    print(f"Indicators:      {len(surface.indicators)}")
    print(f"Relationships:   {len(surface.relationships)}")

if result.output is not None:
    print()
    print(f"JSON:   {result.output.json_path}")
    print(f"Report: {result.output.report_path}")