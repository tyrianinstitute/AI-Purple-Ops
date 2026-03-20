"""Centralized adapter path and module root resolution."""

from __future__ import annotations

import os
from pathlib import Path


def get_adapter_dir() -> Path:
    """Resolve the directory that stores adapter YAML specs."""
    configured = os.getenv("AIPO_ADAPTER_DIR")
    if configured:
        return Path(configured)
    return Path("adapters")


def adapter_spec_path(name: str) -> Path:
    """Build the YAML spec path for a named adapter."""
    return get_adapter_dir() / f"{name}.yaml"


def adapter_spec_globs() -> list[str]:
    """Return adapter YAML glob patterns."""
    return ["*.yaml", "*.yml"]


def get_adapter_templates_dir() -> Path:
    """Resolve the directory that stores adapter YAML templates."""
    return Path("templates/adapters")


def adapter_module_roots() -> list[str]:
    """Resolve Python module roots for custom adapter imports."""
    default_roots = ["adapters", "user_adapters", "custom_adapters"]
    configured = os.getenv("AIPO_ADAPTER_MODULE_PATHS")
    if not configured:
        return default_roots

    configured_roots = [entry.strip() for entry in configured.split(":") if entry.strip()]
    return configured_roots + default_roots
