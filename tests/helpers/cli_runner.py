"""Helpers for running CLI integration tests via the active test interpreter."""

from __future__ import annotations

import os
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _merged_env(env: Mapping[str, str] | None) -> dict[str, str]:
    merged = os.environ.copy()
    if env:
        merged.update(env)

    project_path = str(PROJECT_ROOT)
    current_pythonpath = merged.get("PYTHONPATH")
    merged["PYTHONPATH"] = (
        f"{project_path}{os.pathsep}{current_pythonpath}" if current_pythonpath else project_path
    )
    return merged


def run_cli(
    args: Sequence[str],
    *,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run `python -m aipop.cli.harness` using the same interpreter as pytest."""
    return subprocess.run(
        [sys.executable, "-m", "aipop.cli.harness", *args],
        cwd=cwd or PROJECT_ROOT,
        capture_output=True,
        text=True,
        env=_merged_env(env),
    )
