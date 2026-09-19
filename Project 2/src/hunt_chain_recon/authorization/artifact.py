"""Loader for Project 1 ScopeGuard authorization artifacts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from hunt_chain_recon.authorization.models import (
    AuthorizationDecision,
    AuthorizationResult,
)


class AuthorizationArtifactError(Exception):
    """Raised when a ScopeGuard authorization artifact is invalid."""


class ScopeGuardArtifactLoader:
    """Load a serialized Project 1 ScopeGuard decision."""

    provider = "scopeguard"

    def load(self, path: str | Path) -> AuthorizationResult:
        """Load and translate a Project 1 authorization artifact."""
        artifact_path = Path(path)

        if not artifact_path.exists():
            raise AuthorizationArtifactError(
                f"Authorization artifact not found: {artifact_path}"
            )

        if not artifact_path.is_file():
            raise AuthorizationArtifactError(
                f"Authorization artifact path is not a file: "
                f"{artifact_path}"
            )

        try:
            data = json.loads(
                artifact_path.read_text(encoding="utf-8-sig")
            )
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AuthorizationArtifactError(
                f"Unable to read authorization artifact: "
                f"{artifact_path}"
            ) from exc

        if not isinstance(data, dict):
            raise AuthorizationArtifactError(
                "Authorization artifact must contain a JSON object."
            )

        return self._convert(data, artifact_path)

    def _convert(
        self,
        data: dict[str, Any],
        artifact_path: Path,
    ) -> AuthorizationResult:
        """Convert the Project 1 schema into Project 2's model."""
        required_fields = {
            "state",
            "target",
            "matched_rules",
            "winning_rule",
            "reason",
        }

        missing = sorted(
            field
            for field in required_fields
            if field not in data
        )

        if missing:
            raise AuthorizationArtifactError(
                "Authorization artifact is missing required fields: "
                + ", ".join(missing)
            )

        target = data["target"]

        if not isinstance(target, dict):
            raise AuthorizationArtifactError(
                "Authorization artifact target must be an object."
            )

        normalized_target = target.get("normalized_value")

        if not isinstance(normalized_target, str):
            raise AuthorizationArtifactError(
                "Authorization artifact target.normalized_value "
                "must be a string."
            )

        normalized_target = (
            normalized_target.strip().lower().rstrip(".")
        )

        if not normalized_target:
            raise AuthorizationArtifactError(
                "Authorization artifact target must not be empty."
            )

        target_type = target.get("type")

        if not isinstance(target_type, str) or not target_type.strip():
            raise AuthorizationArtifactError(
                "Authorization artifact target.type must be a non-empty "
                "string."
            )

        try:
            decision = AuthorizationDecision(
                str(data["state"]).strip().upper()
            )
        except ValueError as exc:
            raise AuthorizationArtifactError(
                "Authorization artifact state must be one of: "
                "IN_SCOPE, OUT_OF_SCOPE, UNKNOWN, CONFLICT."
            ) from exc

        matched_rules = data["matched_rules"]

        if not isinstance(matched_rules, list):
            raise AuthorizationArtifactError(
                "Authorization artifact matched_rules must be a list."
            )

        winning_rule = data["winning_rule"]

        if winning_rule is not None and not isinstance(
            winning_rule,
            str,
        ):
            raise AuthorizationArtifactError(
                "Authorization artifact winning_rule must be "
                "a string or null."
            )

        reason = data["reason"]

        if reason is not None and not isinstance(reason, str):
            raise AuthorizationArtifactError(
                "Authorization artifact reason must be "
                "a string or null."
            )

        return AuthorizationResult(
            target=normalized_target,
            decision=decision,
            provider=self.provider,
            reference=winning_rule or "scopeguard-artifact",
            reason=reason,
            metadata={
                "scopeguard_artifact": True,
                "scopeguard_artifact_path": str(
                    artifact_path.resolve()
                ),
                "matched_rules": list(matched_rules),
                "winning_rule": winning_rule,
                "target_type": target_type.strip(),
                "raw_target": target.get("raw_value"),
            },
        )
