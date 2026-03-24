from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml
from dotenv import load_dotenv

from .errors import ConfigError
from .paths import ensure_dirs, get_package_data_file
from .security import sanitize_env_var, validate_seed

_ENV_PREFIX = "AIPO_"


def _deep_update(base: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    for k, v in new.items():
        if isinstance(v, dict) and isinstance(base.get(k), dict):
            _deep_update(base[k], v)
        else:
            base[k] = v
    return base


@dataclass
class RunConfig:
    output_dir: str = "out"
    reports_dir: str = "out/reports"
    transcripts_dir: str = "out/transcripts"
    log_level: str = "INFO"
    seed: int = 42


@dataclass
class StatisticsConfig:
    """Configuration for statistical analysis (confidence intervals, etc.)."""

    confidence_interval_method: str = "auto"  # auto, wilson, clopper-pearson
    confidence_level: float = 0.95  # 95% confidence intervals


@dataclass
class AdaptersConfig:
    garak: dict[str, Any] = field(default_factory=lambda: {"model": "openai:gpt-4o-mini"})
    art: dict[str, Any] = field(default_factory=lambda: {"enabled": True})


@dataclass
class HarnessConfig:
    run: RunConfig = field(default_factory=RunConfig)
    statistics: StatisticsConfig = field(default_factory=StatisticsConfig)
    adapters: AdaptersConfig = field(default_factory=AdaptersConfig)


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as e:
        raise ConfigError(f"Invalid YAML in {path}: {e!r}") from e


def _apply_env(cfg: dict[str, Any]) -> dict[str, Any]:
    # When AIPO_OUTPUT_DIR is set, derive reports/transcripts dirs from it
    # unless they are explicitly overridden by their own env vars.
    output_dir_env = os.getenv(f"{_ENV_PREFIX}OUTPUT_DIR")
    reports_dir_env = os.getenv(f"{_ENV_PREFIX}REPORTS_DIR")
    transcripts_dir_env = os.getenv(f"{_ENV_PREFIX}TRANSCRIPTS_DIR")

    if output_dir_env:
        if not reports_dir_env:
            reports_dir_env = str(Path(output_dir_env) / "reports")
        if not transcripts_dir_env:
            transcripts_dir_env = str(Path(output_dir_env) / "transcripts")

    # Simple env overrides for top-level run.* with security validation
    mapping = {
        "run.output_dir": output_dir_env,
        "run.reports_dir": reports_dir_env,
        "run.transcripts_dir": transcripts_dir_env,
        "run.log_level": os.getenv(f"{_ENV_PREFIX}LOG_LEVEL"),
        "run.seed": os.getenv(f"{_ENV_PREFIX}SEED"),
    }
    for dotted_key, val in mapping.items():
        if val is None:
            continue

        sect, key = dotted_key.split(".", 1)
        if sect not in cfg:
            cfg[sect] = {}

        # Validate and sanitize based on key type
        if dotted_key.endswith("seed"):
            # Validate seed value
            cfg[sect][key] = validate_seed(val)
        else:
            # Sanitize string values
            env_var_name = f"{_ENV_PREFIX}{key.upper()}"
            cfg[sect][key] = sanitize_env_var(val, env_var_name)

    return cfg


def load_config(yaml_path: str | None = None) -> HarnessConfig:
    """Load configuration from defaults, configs/harness.yaml, and environment."""
    load_dotenv(override=False)
    base: dict[str, Any] = {
        "run": {
            "output_dir": "out",
            "reports_dir": "out/reports",
            "transcripts_dir": "out/transcripts",
            "log_level": "INFO",
            "seed": 42,
        },
        "statistics": {
            "confidence_interval_method": "auto",
            "confidence_level": 0.95,
        },
        "adapters": {
            "garak": {"model": "openai:gpt-4o-mini"},
            "art": {"enabled": True},
        },
    }
    if yaml_path:
        config_path = Path(yaml_path)
    else:
        # Try CWD first, then package-bundled config
        cwd_config = Path("configs/harness.yaml")
        if cwd_config.exists():
            config_path = cwd_config
        else:
            try:
                config_path = get_package_data_file("configs/harness.yaml")
            except FileNotFoundError:
                config_path = cwd_config  # Will return {} from _load_yaml
    file_cfg = _load_yaml(config_path)
    merged = _deep_update(base, file_cfg)
    merged = _apply_env(merged)

    # Validate basics
    if "run" not in merged:
        raise ConfigError("Missing 'run' section in configuration")
    rc = RunConfig(**merged["run"])
    sc = StatisticsConfig(**merged.get("statistics", {}))
    ac = AdaptersConfig(**merged.get("adapters", {}))
    # Ensure dirs exist (self-healing)
    ensure_dirs([rc.output_dir, rc.reports_dir, rc.transcripts_dir])
    return HarnessConfig(run=rc, statistics=sc, adapters=ac)
