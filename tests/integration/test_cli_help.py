"""Test CLI help command."""

from __future__ import annotations

import subprocess
import sys


def test_cli_help_works() -> None:
    """Verify CLI help shows all commands."""
    proc = subprocess.run(
        [sys.executable, "-m", "aipop.cli.harness", "--help"], capture_output=True, text=True
    )
    assert proc.returncode == 0
    out = proc.stdout
    for kw in ("run", "gate", "version"):
        assert kw in out
