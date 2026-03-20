"""Integration tests for the gate command."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from tests.helpers.cli_runner import run_cli


@pytest.fixture
def project_root():
    """Get project root directory."""
    return Path(__file__).parent.parent.parent


def test_gate_fails_when_no_summary(project_root, tmp_path):
    """Test that gate command fails when summary.json doesn't exist."""
    # Create a custom config pointing to tmp directory
    config_file = tmp_path / "aipop.yaml"
    config_file.write_text(
        f"""
run:
  reports_dir: {tmp_path / "reports"}
  output_dir: {tmp_path / "out"}
"""
    )

    result = run_cli(["gate", "--config", str(config_file)], cwd=project_root)

    # Should fail with exit code 1
    assert result.returncode == 1

    # Should show helpful error message
    output = result.stdout + result.stderr
    assert "Gate failed" in output or "not found" in output


def test_gate_passes_with_valid_summary(project_root, tmp_path):
    """Test that gate passes when all tests passed."""
    # Create reports directory and summary
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True)

    summary = reports_dir / "summary.json"
    summary.write_text(
        json.dumps({"run_id": "test-run-001", "total": 5, "passed": 5, "failed": 0, "results": []})
    )

    # Create a custom config
    config_file = tmp_path / "aipop.yaml"
    config_file.write_text(
        f"""
run:
  reports_dir: {reports_dir}
  output_dir: {tmp_path / "out"}
"""
    )

    result = run_cli(["gate", "--config", str(config_file)], cwd=project_root)

    # Should pass with exit code 0
    assert result.returncode == 0, f"Gate should pass but failed: {result.stdout}\n{result.stderr}"

    # Should show success message
    output = result.stdout + result.stderr
    assert "passed" in output.lower()


def test_gate_fails_with_failed_tests(project_root, tmp_path):
    """Test that gate fails when tests failed."""
    # Create reports directory and summary with failures
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True)

    summary = reports_dir / "summary.json"
    summary.write_text(
        json.dumps({"run_id": "test-run-002", "total": 5, "passed": 3, "failed": 2, "results": []})
    )

    # Create a custom config
    config_file = tmp_path / "aipop.yaml"
    config_file.write_text(
        f"""
run:
  reports_dir: {reports_dir}
  output_dir: {tmp_path / "out"}
"""
    )

    result = run_cli(["gate", "--config", str(config_file)], cwd=project_root)

    # Should fail with exit code 1
    assert result.returncode == 1

    # Should show failure message
    output = result.stdout + result.stderr
    assert "failed" in output.lower()


def test_gate_generates_evidence_when_tests_failed(project_root, tmp_path):
    """Evidence packs are most valuable when the gate fails; generate them even on failures."""
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True)

    summary = reports_dir / "summary.json"
    summary.write_text(
        json.dumps(
            {
                "run_id": "test-run-evidence-on-fail",
                "total": 2,
                "passed": 1,
                "failed": 1,
                "results": [{"test_id": "t1", "passed": True}, {"test_id": "t2", "passed": False}],
            }
        )
    )

    config_file = tmp_path / "aipop.yaml"
    config_file.write_text(
        f"""
run:
  reports_dir: {reports_dir}
  output_dir: {tmp_path / "out"}
"""
    )

    evidence_dir = tmp_path / "evidence"
    result = run_cli(
        ["gate", "--config", str(config_file), "--evidence-dir", str(evidence_dir)],
        cwd=project_root,
    )

    assert result.returncode == 1
    zip_files = list(evidence_dir.glob("*.zip"))
    assert (
        zip_files
    ), f"Expected evidence zip in {evidence_dir}, got none. Output:\n{result.stdout}\n{result.stderr}"


def test_gate_with_explicit_summary_path(project_root, tmp_path):
    """Test gate with explicit --summary path."""
    # Create a summary in a custom location
    custom_summary = tmp_path / "my_summary.json"
    custom_summary.write_text(
        json.dumps({"run_id": "test-run-003", "total": 3, "passed": 3, "failed": 0, "results": []})
    )

    result = run_cli(["gate", "--summary", str(custom_summary)], cwd=project_root)

    # Should pass
    assert result.returncode == 0, f"Gate should pass but failed: {result.stdout}\n{result.stderr}"


def test_gate_fails_with_invalid_json(project_root, tmp_path):
    """Test that gate fails gracefully with invalid JSON."""
    # Create reports directory with invalid JSON
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True)

    summary = reports_dir / "summary.json"
    summary.write_text("{ invalid json }")

    # Create a custom config
    config_file = tmp_path / "aipop.yaml"
    config_file.write_text(
        f"""
run:
  reports_dir: {reports_dir}
  output_dir: {tmp_path / "out"}
"""
    )

    result = run_cli(["gate", "--config", str(config_file)], cwd=project_root)

    # Should fail
    assert result.returncode == 1

    # Should show helpful error
    output = result.stdout + result.stderr
    assert "Invalid JSON" in output or "failed" in output.lower()


def test_gate_fails_with_missing_run_id(project_root, tmp_path):
    """Test that gate validates required fields in summary."""
    # Create reports directory with summary missing run_id
    reports_dir = tmp_path / "reports"
    reports_dir.mkdir(parents=True)

    summary = reports_dir / "summary.json"
    summary.write_text(json.dumps({"total": 5, "passed": 5, "failed": 0, "results": []}))

    # Create a custom config
    config_file = tmp_path / "aipop.yaml"
    config_file.write_text(
        f"""
run:
  reports_dir: {reports_dir}
  output_dir: {tmp_path / "out"}
"""
    )

    result = run_cli(["gate", "--config", str(config_file)], cwd=project_root)

    # Should fail
    assert result.returncode == 1

    # Should show validation error
    output = result.stdout + result.stderr
    assert "run_id" in output.lower() or "missing" in output.lower()
