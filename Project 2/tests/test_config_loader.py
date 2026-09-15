from pathlib import Path

from hunt_chain_recon.config.loader import load_config


def test_load_config_from_project_root_default_path(monkeypatch):
    project_root = Path(__file__).resolve().parents[1]
    monkeypatch.chdir(project_root)

    config = load_config("config/default.yaml")

    assert config.target.value == "example.com"
    assert config.target.type == "DOMAIN"
    assert config.execution.mode == "active"
