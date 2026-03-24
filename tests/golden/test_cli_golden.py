"""Golden master tests — snapshot CLI behavior before the S1 core extraction.

These tests capture the current output structure, JSON schema, exit codes,
and command behavior. After TYR-755 (core engine extraction), any behavioral
change shows up as a test failure, forcing explicit review.

NOT testing exact output text (that's fragile). Testing structure, keys,
exit codes, and invariants that the engine extraction must preserve.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def run_aipop(*args: str, json_mode: bool = False) -> subprocess.CompletedProcess[str]:
    cmd = [sys.executable, "-m", "aipop.cli.harness"]
    if json_mode:
        cmd.extend(["--output", "json"])
    cmd.extend(args)
    return subprocess.run(
        cmd,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )


# --- CLI structure ---


class TestCLIStructure:
    """The CLI command surface must not silently shrink."""

    def test_help_exits_zero(self):
        result = run_aipop("--help")
        assert result.returncode == 0

    def test_help_shows_core_commands(self):
        result = run_aipop("--help")
        output = result.stdout + result.stderr
        # These are the commands that must always appear in --help.
        # Some commands (diff, discover, recommend, coverage, export)
        # are registered conditionally — test those separately.
        required_commands = [
            "run",
            "gate",
            "suites",
            "adapter",
            "recipe",
            "config",
        ]
        for cmd in required_commands:
            assert cmd in output, f"Missing command: {cmd}"

    def test_version_exits_zero(self):
        result = run_aipop("version")
        assert result.returncode == 0

    def test_version_output_contains_semver(self):
        result = run_aipop("version")
        output = result.stdout.strip()
        assert "." in output, f"Version doesn't look like semver: {output}"


# --- JSON output schema ---


class TestJSONOutputSchema:
    """JSON output structure must be stable across the engine extraction."""

    @pytest.fixture(autouse=True)
    def run_mock_scan(self):
        """Run a mock scan and capture JSON output."""
        result = run_aipop(
            "run", "--suite", "adversarial", "--adapter", "mock",
            "--response-mode", "smart", json_mode=True,
        )
        self.run_result = result
        if result.stdout.strip():
            self.json_output = json.loads(result.stdout)
        else:
            self.json_output = None

    def test_run_exits_zero(self):
        assert self.run_result.returncode == 0

    def test_json_has_required_keys(self):
        assert self.json_output is not None
        required = {
            "status", "total", "passed", "failed", "run_id",
            "suite", "adapter", "model",
        }
        missing = required - set(self.json_output.keys())
        assert not missing, f"Missing keys: {missing}"

    def test_json_has_reports_section(self):
        assert "reports" in self.json_output
        reports = self.json_output["reports"]
        assert "summary" in reports
        assert "junit" in reports

    def test_json_has_metrics(self):
        assert "harmful_output_rate" in self.json_output
        assert "critical_violation_rate" in self.json_output
        assert "cost_usd" in self.json_output

    def test_json_counts_are_consistent(self):
        total = self.json_output["total"]
        passed = self.json_output["passed"]
        failed = self.json_output["failed"]
        assert total == passed + failed
        assert total > 0

    def test_json_run_id_format(self):
        run_id = self.json_output["run_id"]
        assert run_id.startswith("run-")

    def test_json_status_is_completed(self):
        assert self.json_output["status"] == "completed"


# --- Gate behavior ---


class TestGateBehavior:
    """Gate exit codes and output structure must be preserved."""

    def test_gate_returns_json(self):
        # Run first to have results
        run_aipop("run", "--suite", "adversarial", "--adapter", "mock",
                  "--response-mode", "smart")
        result = run_aipop("gate", json_mode=True)
        output = json.loads(result.stdout)
        assert "gate_passed" in output
        assert "metrics" in output
        assert "thresholds" in output

    def test_gate_fail_exit_code_is_one(self):
        run_aipop("run", "--suite", "adversarial", "--adapter", "mock",
                  "--response-mode", "smart")
        result = run_aipop("gate", json_mode=True)
        output = json.loads(result.stdout)
        if not output["gate_passed"]:
            assert result.returncode == 1

    def test_gate_metrics_keys(self):
        run_aipop("run", "--suite", "adversarial", "--adapter", "mock",
                  "--response-mode", "smart")
        result = run_aipop("gate", json_mode=True)
        metrics = json.loads(result.stdout)["metrics"]
        required_metrics = {"total", "passed", "failed", "harmful_output_rate",
                           "critical_violation_rate", "cost_usd"}
        missing = required_metrics - set(metrics.keys())
        assert not missing, f"Missing metrics: {missing}"

    def test_gate_no_summary_exit_code(self, tmp_path):
        """Gate with no summary file should fail gracefully."""
        fake_path = str(tmp_path / "nonexistent_summary.json")
        result = subprocess.run(
            [sys.executable, "-m", "aipop.cli.harness", "--output", "json",
             "gate", "--summary-path", fake_path],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode != 0


# --- Report artifacts ---


class TestReportArtifacts:
    """Run must produce expected artifact files."""

    def test_summary_json_created(self):
        run_aipop("run", "--suite", "adversarial", "--adapter", "mock",
                  "--response-mode", "smart")
        summary = PROJECT_ROOT / "out" / "reports" / "summary.json"
        assert summary.exists()

    def test_summary_json_is_valid(self):
        summary = PROJECT_ROOT / "out" / "reports" / "summary.json"
        if summary.exists():
            with open(summary) as f:
                data = json.load(f)
            assert "results" in data or "total" in data

    def test_junit_xml_created(self):
        run_aipop("run", "--suite", "adversarial", "--adapter", "mock",
                  "--response-mode", "smart")
        junit = PROJECT_ROOT / "out" / "reports" / "junit.xml"
        assert junit.exists()


# --- Exit codes ---


class TestExitCodes:
    """Exit code contract must be stable."""

    def test_run_success_exits_zero(self):
        result = run_aipop("run", "--suite", "adversarial", "--adapter", "mock",
                          "--response-mode", "smart")
        assert result.returncode == 0

    def test_help_exits_zero(self):
        result = run_aipop("--help")
        assert result.returncode == 0

    def test_invalid_command_exits_nonzero(self):
        result = run_aipop("nonexistent-command")
        assert result.returncode != 0


# --- Agent info ---


class TestAgentInfo:
    """Agent info JSON must be stable for AI agent consumers."""

    def test_agent_info_is_valid_json(self):
        result = run_aipop("--agent-info")
        data = json.loads(result.stdout)
        assert isinstance(data, dict)

    def test_agent_info_has_commands(self):
        result = run_aipop("--agent-info")
        data = json.loads(result.stdout)
        assert "commands" in data or "capabilities" in data
