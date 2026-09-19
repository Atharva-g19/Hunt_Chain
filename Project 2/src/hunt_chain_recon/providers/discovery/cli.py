"""Optional CLI-backed passive hostname discovery providers."""

from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from typing import Any

from hunt_chain_recon.providers.base import ProviderError, ProviderResult
from hunt_chain_recon.providers.discovery.base import DiscoveryProvider


class CLIHostnameDiscoveryProvider(DiscoveryProvider, ABC):
    """Shared controlled adapter for optional passive discovery CLIs."""

    binary: str
    timeout_seconds = 60.0

    @property
    def capabilities(self) -> tuple[str, ...]:
        return ("passive_discovery", "hostname_discovery", "cli_adapter")

    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    @abstractmethod
    def command(self, domain: str) -> list[str]:
        """Return a fixed-argument command for an already normalized domain."""

    def discover(self, target: Any) -> ProviderResult[dict[str, Any]]:
        domain = self._normalize_domain(target)
        if domain is None:
            return self._failure("CONFIGURATION_ERROR", "Discovery requires a domain target.")
        if not self.available():
            return self._failure("NOT_INSTALLED", f"Optional tool is unavailable: {self.binary}")
        try:
            completed = subprocess.run(
                self.command(domain),
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return self._failure("TIMEOUT", f"{self.binary} timed out.", retryable=True)
        except OSError as exc:
            return self._failure("EXECUTION_ERROR", f"Unable to execute {self.binary}: {exc}")
        if completed.returncode != 0:
            return self._failure("EXECUTION_ERROR", f"{self.binary} exited with code {completed.returncode}.", details={"stderr": completed.stderr.strip()})
        try:
            observations = self.parse(completed.stdout, domain)
        except ValueError as exc:
            return self._failure("INVALID_RESPONSE", f"Unable to parse {self.binary} output: {exc}")
        return ProviderResult(status="SUCCESS", observations=observations, provider=self.name, version=self.version, metadata={"tool": self.binary, "availability": "AVAILABLE", "result_state": "NO_RESULTS" if not observations else "RESULTS"})

    def parse(self, output: str, domain: str) -> list[dict[str, Any]]:
        if not isinstance(output, str):
            raise ValueError("stdout must be text")
        suffix = f".{domain}"
        observations: list[dict[str, Any]] = []
        for line in output.splitlines():
            hostname = line.strip().lower().rstrip(".")
            if hostname.startswith("*."):
                hostname = hostname[2:]
            if hostname == domain or hostname.endswith(suffix):
                observations.append({"value": hostname, "type": "HOSTNAME", "source": self.name})
        return observations

    @staticmethod
    def _normalize_domain(target: Any) -> str | None:
        if not isinstance(target, str):
            return None
        domain = target.strip().lower().rstrip(".")
        return domain or None

    def _failure(self, error_type: str, message: str, *, retryable: bool = False, details: dict[str, Any] | None = None) -> ProviderResult[dict[str, Any]]:
        return ProviderResult(status="FAILED", provider=self.name, version=self.version, errors=[ProviderError(type=error_type, message=message, retryable=retryable, details=details or {})], metadata={"tool": self.binary, "availability": "UNAVAILABLE" if error_type == "NOT_INSTALLED" else "AVAILABLE"})


class SubfinderProvider(CLIHostnameDiscoveryProvider):
    name = "subfinder"
    version = "1.0.0"
    binary = "subfinder"

    def command(self, domain: str) -> list[str]:
        return [self.binary, "-silent", "-d", domain]


class AmassProvider(CLIHostnameDiscoveryProvider):
    name = "amass"
    version = "1.0.0"
    binary = "amass"

    def command(self, domain: str) -> list[str]:
        return [self.binary, "enum", "-passive", "-norecursive", "-silent", "-d", domain]
