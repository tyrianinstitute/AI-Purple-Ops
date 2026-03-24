"""Test CLI version command."""

from __future__ import annotations

import subprocess
import sys

from aipop import __version__


def test_cli_version() -> None:
    """Verify CLI version outputs correct version."""
    proc = subprocess.run(
        [sys.executable, "-m", "aipop.cli.harness", "version"], capture_output=True, text=True
    )
    assert proc.returncode == 0
    assert __version__ in proc.stdout
