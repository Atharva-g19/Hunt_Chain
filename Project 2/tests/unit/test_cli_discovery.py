"""Offline tests for optional passive discovery CLI adapters."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from hunt_chain_recon.providers.discovery.cli import AmassProvider, SubfinderProvider


@pytest.mark.parametrize(("provider", "expected"), [
    (SubfinderProvider(), ["subfinder", "-silent", "-d", "example.com"]),
    (AmassProvider(), ["amass", "enum", "-passive", "-norecursive", "-silent", "-d", "example.com"]),
])
def test_cli_discovery_commands_are_fixed(provider, expected) -> None:
    assert provider.command("example.com") == expected


def test_subfinder_parses_in_scope_hostnames_only() -> None:
    result = SubfinderProvider().parse("API.Example.COM.\n*.www.example.com\nother.example.net", "example.com")
    assert [item["value"] for item in result] == ["api.example.com", "www.example.com"]


def test_tool_unavailable_is_not_no_results(monkeypatch) -> None:
    provider = SubfinderProvider()
    monkeypatch.setattr(provider, "available", lambda: False)
    result = provider.discover("example.com")
    assert result.status.value == "FAILED"
    assert result.errors[0].type.value == "NOT_INSTALLED"


def test_cli_execution_and_parse(monkeypatch) -> None:
    provider = AmassProvider()
    monkeypatch.setattr(provider, "available", lambda: True)
    monkeypatch.setattr("hunt_chain_recon.providers.discovery.cli.subprocess.run", lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="api.example.com\n", stderr=""))
    result = provider.discover("example.com")
    assert result.status.value == "SUCCESS"
    assert result.observations[0]["source"] == "amass"
