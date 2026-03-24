"""Integration tests for suites CLI commands."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_suites_list_command(project_root: Path) -> None:
    """Test suites list command."""
    result = subprocess.run(
        [sys.executable, "-m", "aipop.cli.harness", "suites", "list"],
        cwd=project_root,
        capture_output=True,
        text=True,
    )

    # Should list suites - check for suite names or categories
    assert result.returncode == 0
    # Should contain suite categories or names
    assert "adversarial" in result.stdout.lower() or "suite" in result.stdout.lower()


def test_suites_info_command(project_root: Path) -> None:
    """Test suites info command with valid suite."""
    # Use a known suite name
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "aipop.cli.harness",
            "suites",
            "info",
            "--suite",
            "tool_policy_validation",
        ],
        cwd=project_root,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    # Should show suite information
    assert "tool policy" in result.stdout.lower() or "tool_policy" in result.stdout.lower()


def test_suites_info_missing_suite(project_root: Path) -> None:
    """Test suites info command with non-existent suite."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "aipop.cli.harness",
            "suites",
            "info",
            "--suite",
            "nonexistent_suite_xyz",
        ],
        cwd=project_root,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    # Should show error message
    assert "not found" in result.stdout.lower() or "not found" in result.stderr.lower()


def test_suites_invalid_action(project_root: Path) -> None:
    """Test suites command with invalid action."""
    result = subprocess.run(
        [sys.executable, "-m", "aipop.cli.harness", "suites", "invalid_action"],
        cwd=project_root,
        capture_output=True,
        text=True,
    )

    assert result.returncode != 0
    # Should show error about unknown action
    assert "unknown action" in result.stdout.lower() or "unknown action" in result.stderr.lower()


def test_suites_info_with_category_path(project_root: Path) -> None:
    """Test suites info command with category/suite format."""
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "aipop.cli.harness",
            "suites",
            "info",
            "--suite",
            "tools/tool_policy_validation",
        ],
        cwd=project_root,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0
    # Should show suite information
    assert "tool policy" in result.stdout.lower() or "tool_policy" in result.stdout.lower()
