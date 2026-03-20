"""Integration tests for enhanced gate command."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


def test_gate_with_thresholds_passes(project_root: Path, tmp_path: Path) -> None:
    """Test gate command passes when thresholds are met."""
    # Create summary with passing metrics
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True)

    summary_file = reports_dir / "summary.json"
    summary_data = {
        "run_id": "test-run-001",
        "total": 10,
        "passed": 10,
        "failed": 0,
        "harmful_output_rate": 0.03,  # Below threshold of 0.05
        "critical_violation_rate": 0.005,  # Below threshold of 0.01
        "utility_failure_rate": 0.0,
        "results": [],
    }
    summary_file.write_text(json.dumps(summary_data), encoding="utf-8")

    # Create policy with thresholds
    policies_dir = tmp_path / "policies"
    policies_dir.mkdir()
    policy_file = policies_dir / "content_policy.yaml"
    policy_file.write_text(
        """
version: "1.0.0"
description: "Test policy"
rules: []
thresholds:
  harmful_output_rate: 0.05
  critical_violation_rate: 0.01
""",
        encoding="utf-8",
    )

    # Create config
    config_file = tmp_path / "aipop.yaml"
    config_file.write_text(
        f"""
run:
  reports_dir: {reports_dir}
  output_dir: {tmp_path / "out"}
""",
        encoding="utf-8",
    )

    # Run gate command
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "aipop.cli.harness",
            "gate",
            "--summary",
            str(summary_file),
            "--config",
            str(config_file),
            "--policy",
            str(policy_file),
        ],
        cwd=project_root,
        capture_output=True,
        text=True,
    )

    # Should pass
    assert result.returncode == 0
    assert "Gate passed" in result.stdout or "Gate PASSED" in result.stdout


def test_gate_with_thresholds_fails(project_root: Path, tmp_path: Path) -> None:
    """Test gate command fails when thresholds are breached."""
    # Create summary with failing metrics
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True)

    summary_file = reports_dir / "summary.json"
    summary_data = {
        "run_id": "test-run-001",
        "total": 10,
        "passed": 10,
        "failed": 0,
        "harmful_output_rate": 0.10,  # Above threshold of 0.05
        "critical_violation_rate": 0.0,
        "utility_failure_rate": 0.0,
        "results": [],
    }
    summary_file.write_text(json.dumps(summary_data), encoding="utf-8")

    # Create policy with thresholds
    policies_dir = tmp_path / "policies"
    policies_dir.mkdir()
    policy_file = policies_dir / "content_policy.yaml"
    policy_file.write_text(
        """
version: "1.0.0"
description: "Test policy"
rules: []
thresholds:
  harmful_output_rate: 0.05
""",
        encoding="utf-8",
    )

    # Create config
    config_file = tmp_path / "aipop.yaml"
    config_file.write_text(
        f"""
run:
  reports_dir: {reports_dir}
  output_dir: {tmp_path / "out"}
""",
        encoding="utf-8",
    )

    # Run gate command
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "aipop.cli.harness",
            "gate",
            "--summary",
            str(summary_file),
            "--config",
            str(config_file),
            "--policy",
            str(policy_file),
        ],
        cwd=project_root,
        capture_output=True,
        text=True,
    )

    # Should fail
    assert result.returncode == 1
    assert "Gate failed" in result.stdout or "Gate FAILED" in result.stdout


def test_gate_generates_evidence_pack(project_root: Path, tmp_path: Path) -> None:
    """Test gate command generates evidence pack."""
    # Create summary
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True)

    summary_file = reports_dir / "summary.json"
    summary_data = {
        "run_id": "test-run-001",
        "total": 10,
        "passed": 10,
        "failed": 0,
        "harmful_output_rate": 0.0,
        "results": [],
    }
    summary_file.write_text(json.dumps(summary_data), encoding="utf-8")

    # Create config
    config_file = tmp_path / "aipop.yaml"
    output_dir = tmp_path / "out"
    config_file.write_text(
        f"""
run:
  reports_dir: {reports_dir}
  output_dir: {output_dir}
""",
        encoding="utf-8",
    )

    # Run gate command
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "aipop.cli.harness",
            "gate",
            "--summary",
            str(summary_file),
            "--config",
            str(config_file),
            "--generate-evidence",
        ],
        cwd=project_root,
        capture_output=True,
        text=True,
    )

    # Should pass and generate evidence pack
    assert result.returncode == 0
    evidence_dir = output_dir / "evidence"
    assert evidence_dir.exists()
    # Check for evidence pack zip file
    zip_files = list(evidence_dir.glob("*.zip"))
    assert len(zip_files) > 0
