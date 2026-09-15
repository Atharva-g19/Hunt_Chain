from __future__ import annotations

from pathlib import Path

from hunt_chain_recon.authorization.models import AuthorizationResult
from hunt_chain_recon.config.loader import load_config
from hunt_chain_recon.models.run import ReconRun
from hunt_chain_recon.pipeline.context import PipelineContext
from hunt_chain_recon.pipeline.engine import PipelineEngine
from hunt_chain_recon.policy.execution import ExecutionPolicy
from hunt_chain_recon.policy.politeness import PolitenessController


CONFIG_PATH = Path("config/lab.yaml")


def main() -> None:
    config = load_config(CONFIG_PATH)

    authorization = AuthorizationResult(
        target=config.target.value.strip().lower().rstrip("."),
        provider="debug",
        reference="local-lab",
        status="IN_SCOPE",
    )

    execution_policy = ExecutionPolicy(
        config.execution
    )

    politeness = PolitenessController(
        config.politeness
    )

    run = ReconRun.create(
        target=config.target.value,
        execution_mode=config.execution.mode,
    )

    context = PipelineContext(
        config=config,
        authorization=authorization,
        execution_policy=execution_policy,
        politeness=politeness,
        run=run,
    )

    engine = PipelineEngine(
        context,
        include_default_stages=True,
    )

    print("=== REGISTERED STAGES ===")

    for index, stage in enumerate(engine.stages, start=1):
        print(f"{index}. {stage.name}")

    print("\n=== RUNNING PIPELINE ===")

    result = engine.run()

    print(f"Pipeline completed: {result.completed}")
    print(f"Pipeline blocked:   {result.blocked}")
    print(f"Failed stage:       {getattr(result, 'failed_stage', None)}")
    print(f"Error:              {getattr(result, 'error', None)}")

    print("\n=== PIPELINE RESULT ATTRIBUTES ===")

    print(
        [
            name
            for name in dir(result)
            if not name.startswith("_")
        ]
    )

    print("\n=== STAGE RESULTS ===")

    for name, stage_result in result.stage_results.items():
        print(f"\n[{name}]")
        print(f"type: {type(stage_result).__name__}")
        print(f"value: {stage_result}")

    print("\n=== PIPELINE STATE ===")

    for key, value in context.state.items():
        print(f"\n[{key}]")
        print(f"type: {type(value).__name__}")
        print(f"value: {value}")


if __name__ == "__main__":
    main()