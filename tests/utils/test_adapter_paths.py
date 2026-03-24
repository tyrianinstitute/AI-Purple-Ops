"""Tests for adapter path and module root resolution."""

from __future__ import annotations

from pathlib import Path

from aipop.utils.adapter_paths import (
    adapter_module_roots,
    adapter_spec_globs,
    adapter_spec_path,
    get_adapter_dir,
    get_adapter_templates_dir,
)


def test_adapter_path_defaults(monkeypatch) -> None:
    """Default adapter paths should resolve to adapters/."""
    monkeypatch.delenv("AIPO_ADAPTER_DIR", raising=False)
    monkeypatch.delenv("AIPO_ADAPTER_MODULE_PATHS", raising=False)

    assert get_adapter_dir() == Path("adapters")
    assert get_adapter_templates_dir() == Path("templates/adapters")
    assert adapter_spec_path("target") == Path("adapters/target.yaml")
    assert adapter_spec_globs() == ["*.yaml", "*.yml"]


def test_adapter_dir_env_override(monkeypatch) -> None:
    """AIPO_ADAPTER_DIR should override the YAML base directory."""
    monkeypatch.setenv("AIPO_ADAPTER_DIR", "custom/adapters")

    assert get_adapter_dir() == Path("custom/adapters")
    assert get_adapter_templates_dir() == Path("templates/adapters")
    assert adapter_spec_path("target") == Path("custom/adapters/target.yaml")


def test_adapter_module_roots_defaults(monkeypatch) -> None:
    """Default module roots should preserve current runtime behavior."""
    monkeypatch.delenv("AIPO_ADAPTER_MODULE_PATHS", raising=False)

    assert adapter_module_roots() == ["adapters", "user_adapters", "custom_adapters"]


def test_adapter_module_roots_env_prepend(monkeypatch) -> None:
    """AIPO_ADAPTER_MODULE_PATHS should prepend custom import roots."""
    monkeypatch.setenv("AIPO_ADAPTER_MODULE_PATHS", "tenant_adapters:partner.adapters")

    assert adapter_module_roots() == [
        "tenant_adapters",
        "partner.adapters",
        "adapters",
        "user_adapters",
        "custom_adapters",
    ]
