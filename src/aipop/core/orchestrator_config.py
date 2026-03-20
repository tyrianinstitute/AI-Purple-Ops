"""Configuration system for orchestrators with hierarchy support."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class OrchestratorConfig:
    """Configuration for orchestrator behavior with hierarchy support.

    Supports configuration hierarchy:
    1. Test case metadata (highest priority)
    2. CLI/config file parameters
    3. Default values
    """

    orchestrator_type: str = "simple"
    debug: bool = False
    verbose: bool = False
    max_retries: int = 0
    timeout_seconds: float | None = None
    custom_params: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_file(cls, config_path: Path) -> OrchestratorConfig:
        """Load config from YAML file.

        Args:
            config_path: Path to YAML config file

        Returns:
            OrchestratorConfig instance (defaults if file doesn't exist)
        """
        if not config_path.exists():
            return cls()

        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        return cls(
            orchestrator_type=data.get("orchestrator_type", "simple"),
            debug=data.get("debug", False),
            verbose=data.get("verbose", False),
            max_retries=data.get("max_retries", 0),
            timeout_seconds=data.get("timeout_seconds"),
            custom_params=data.get("custom_params", {}),
        )

    @classmethod
    def from_test_metadata(cls, metadata: dict[str, Any]) -> OrchestratorConfig | None:
        """Extract orchestrator config from test case metadata.

        Looks for 'orchestrator_config' key in metadata.

        Args:
            metadata: Test case metadata dictionary

        Returns:
            OrchestratorConfig if found, None otherwise
        """
        if "orchestrator_config" not in metadata:
            return None

        config_data = metadata["orchestrator_config"]
        return cls(
            orchestrator_type=config_data.get("orchestrator_type", "simple"),
            debug=config_data.get("debug", False),
            verbose=config_data.get("verbose", False),
            max_retries=config_data.get("max_retries", 0),
            timeout_seconds=config_data.get("timeout_seconds"),
            custom_params=config_data.get("custom_params", {}),
        )

    def merge(self, override: OrchestratorConfig) -> OrchestratorConfig:
        """Merge override config into this config (override wins).

        Args:
            override: Config to merge in (takes precedence)

        Returns:
            New OrchestratorConfig with merged values
        """
        return OrchestratorConfig(
            orchestrator_type=override.orchestrator_type or self.orchestrator_type,
            debug=override.debug if override.debug is not None else self.debug,
            verbose=override.verbose if override.verbose is not None else self.verbose,
            max_retries=(
                override.max_retries if override.max_retries is not None else self.max_retries
            ),
            timeout_seconds=override.timeout_seconds or self.timeout_seconds,
            custom_params={**self.custom_params, **override.custom_params},
        )
