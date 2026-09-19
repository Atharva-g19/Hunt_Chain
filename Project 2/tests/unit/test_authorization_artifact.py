"""Tests for Project 1 authorization artifact consumption."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from hunt_chain_recon.authorization.artifact import (
    AuthorizationArtifactError,
    ScopeGuardArtifactLoader,
)
from hunt_chain_recon.authorization.models import AuthorizationDecision


def artifact_document(*, state: str = "IN_SCOPE") -> dict:
    return {
        "state": state,
        "target": {
            "raw_value": "https://example.com",
            "normalized_value": "https://example.com",
            "type": "url",
        },
        "matched_rules": ["TEST-WEB-001"],
        "winning_rule": "TEST-WEB-001",
        "reason": "Test authorization",
    }


@pytest.mark.parametrize("encoding", ["utf-8", "utf-8-sig"])
def test_loader_reads_utf8_and_bom_artifacts(
    tmp_path: Path,
    encoding: str,
) -> None:
    path = tmp_path / "authorization_result.json"
    path.write_text(json.dumps(artifact_document()), encoding=encoding)

    result = ScopeGuardArtifactLoader().load(path)

    assert result.decision is AuthorizationDecision.IN_SCOPE
    assert result.is_authorized is True
    assert result.target == "https://example.com"
    assert result.provider == "scopeguard"
    assert result.reference == "TEST-WEB-001"
    assert result.metadata["target_type"] == "url"


def test_loader_rejects_missing_artifact(tmp_path: Path) -> None:
    with pytest.raises(AuthorizationArtifactError, match="not found"):
        ScopeGuardArtifactLoader().load(tmp_path / "missing.json")


def test_loader_rejects_invalid_json(tmp_path: Path) -> None:
    path = tmp_path / "authorization_result.json"
    path.write_text("not json", encoding="utf-8")

    with pytest.raises(AuthorizationArtifactError, match="Unable to read"):
        ScopeGuardArtifactLoader().load(path)


def test_loader_rejects_invalid_state(tmp_path: Path) -> None:
    path = tmp_path / "authorization_result.json"
    path.write_text(json.dumps(artifact_document(state="AUTHORIZED")), encoding="utf-8")

    with pytest.raises(AuthorizationArtifactError, match="state must be one of"):
        ScopeGuardArtifactLoader().load(path)


def test_loader_rejects_missing_required_fields(tmp_path: Path) -> None:
    path = tmp_path / "authorization_result.json"
    path.write_text('{"state": "IN_SCOPE"}', encoding="utf-8")

    with pytest.raises(AuthorizationArtifactError, match="missing required fields"):
        ScopeGuardArtifactLoader().load(path)


def test_loader_rejects_missing_target_type(tmp_path: Path) -> None:
    path = tmp_path / "authorization_result.json"
    document = artifact_document()
    del document["target"]["type"]
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(AuthorizationArtifactError, match="target.type"):
        ScopeGuardArtifactLoader().load(path)


def test_loader_preserves_out_of_scope_decision(tmp_path: Path) -> None:
    path = tmp_path / "authorization_result.json"
    path.write_text(json.dumps(artifact_document(state="OUT_OF_SCOPE")), encoding="utf-8")

    result = ScopeGuardArtifactLoader().load(path)

    assert result.decision is AuthorizationDecision.OUT_OF_SCOPE
    assert result.is_authorized is False
