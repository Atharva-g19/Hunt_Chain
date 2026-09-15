"""Configuration loading and validation for Hunt_Chain Project 2."""

from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from hunt_chain_recon.config.models import ReconConfig


class ConfigurationError(Exception):
    """Raised when Project 2 configuration cannot be loaded or validated."""


def load_config(path: str | Path) -> ReconConfig:
    """Load and validate a reconnaissance configuration from a YAML file.

    Args:
        path: Path to the YAML configuration file.

    Returns:
        A validated ReconConfig instance.

    Raises:
        ConfigurationError: If the file cannot be read, parsed, or validated.
    """
    config_path = Path(path)

    if not config_path.is_file():
        raise ConfigurationError(
            f"Configuration file not found: {config_path}"
        )

    try:
        with config_path.open("r", encoding="utf-8") as config_file:
            raw_config: Any = yaml.safe_load(config_file)
    except OSError as exc:
        raise ConfigurationError(
            f"Unable to read configuration file: {config_path}"
        ) from exc
    except yaml.YAMLError as exc:
        raise ConfigurationError(
            f"Invalid YAML syntax in configuration file: {config_path}"
        ) from exc

    if raw_config is None:
        raise ConfigurationError(
            f"Configuration file is empty: {config_path}"
        )

    if not isinstance(raw_config, dict):
        raise ConfigurationError(
            "Configuration root must be a YAML mapping/object."
        )

    try:
        return ReconConfig.model_validate(raw_config)
    except ValidationError as exc:
        raise ConfigurationError(
            f"Configuration validation failed: {exc}"
        ) from exc