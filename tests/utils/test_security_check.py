"""Tests for security_check adapter gitignore protection behavior."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console

from aipop.utils import security_check
from aipop.utils.security_check import ensure_gitignore_protection


def test_ensure_gitignore_protection_uses_env_adapter_dir(monkeypatch, tmp_path: Path) -> None:
    """Protection should use AIPO_ADAPTER_DIR and include yaml/yml patterns."""
    monkeypatch.setenv("AIPO_ADAPTER_DIR", "tenant/adapters")

    applied, adapter_dir_display, patterns, error = ensure_gitignore_protection(repo_root=tmp_path)

    assert applied is True
    assert error is None
    assert adapter_dir_display == "tenant/adapters"
    assert patterns == [
        "tenant/adapters/*.yaml",
        "tenant/adapters/*.yml",
        "!tenant/adapters/templates/",
        "!tenant/adapters/templates/*.yaml",
        "!tenant/adapters/templates/*.yml",
    ]

    gitignore_text = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    for pattern in patterns:
        assert pattern in gitignore_text


def test_show_security_warning_is_truthful_when_protection_fails(
    monkeypatch, tmp_path: Path
) -> None:
    """Warning should provide manual remediation and avoid success claims."""
    recorder = Console(record=True, force_terminal=False)
    monkeypatch.setattr(security_check, "console", recorder)

    outside_dir = tmp_path.parent / "outside-adapters"
    config_path = outside_dir / "target.yaml"

    security_check.show_security_warning(
        config_path=config_path, warnings=["Bearer token detected in config"]
    )

    output = recorder.export_text()
    assert "Could not update .gitignore automatically" in output
    assert "Added protection in .gitignore" not in output
    assert "Add this to .gitignore manually:" in output
    assert "outside-adapters/*.yaml" in output
