"""Test CLI run command execution."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path


def test_cli_run_smoke(tmp_path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Verify CLI run executes successfully with real test suite."""
    # Get repo root before changing directory
    repo_root = Path(__file__).parent.parent.parent.absolute()

    cfg = tmp_path / "aipop.yaml"
    cfg.write_text(
        "run:\n"
        "  output_dir: outx\n"
        "  reports_dir: outx/reports\n"
        "  transcripts_dir: outx/transcripts\n"
        "  log_level: INFO\n"
        "  seed: 7\n",
        encoding="utf-8",
    )

    # Copy the normal suite to tmp_path so the CLI can find it
    suites_dir = tmp_path / "suites" / "normal"
    suites_dir.mkdir(parents=True)

    # Copy basic_utility.yaml from repo
    src_suite = repo_root / "suites" / "normal" / "basic_utility.yaml"
    dst_suite = suites_dir / "basic_utility.yaml"
    dst_suite.write_text(src_suite.read_text())

    monkeypatch.chdir(tmp_path)

    # Add repo root to PYTHONPATH so subprocess can find cli module
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root)

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "aipop.cli.harness",
            "run",
            "--suite",
            "normal",
            "--config",
            str(cfg),
            "--no-progress",  # Disable progress bar for cleaner test output
            "--skip-policy-prompt",  # Skip policy prompt for CI/CD
        ],
        capture_output=True,
        text=True,
        env=env,
    )
    # Command may exit with 1 if tests fail (which is expected for harmful_request test)
    assert proc.returncode in (0, 1)

    # Check that reports were generated
    summary_file = Path("outx/reports/summary.json")
    junit_file = Path("outx/reports/junit.xml")

    assert (
        summary_file.exists()
    ), f"Summary not found. stdout:\n{proc.stdout}\nstderr:\n{proc.stderr}"
    assert junit_file.exists()

    # Verify summary structure
    data = json.loads(summary_file.read_text(encoding="utf-8"))
    assert data.get("suite") == "normal"
    assert "run_id" in data
    assert "total" in data
    assert "results" in data
