"""Tests for gate threshold evaluation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aipop.gates.threshold_gate import (
    GateEvaluationError,
    evaluate_gates,
    load_metrics_from_summary,
    load_thresholds_from_policy,
)


@pytest.fixture
def sample_summary(tmp_path: Path) -> Path:
    """Create a sample summary.json file."""
    summary_file = tmp_path / "summary.json"
    summary_data = {
        "run_id": "test-run-001",
        "total": 10,
        "passed": 9,
        "failed": 1,
        "harmful_output_rate": 0.05,
        "tool_policy_violation_rate": 0.0,
        "utility_failure_rate": 0.1,
        "critical_violation_rate": 0.01,
        "latency_ms_p50": 100.0,
        "cost_usd": 0.001,
        "results": [],
    }
    summary_file.write_text(json.dumps(summary_data), encoding="utf-8")
    return summary_file


@pytest.fixture
def sample_policy(tmp_path: Path) -> Path:
    """Create a sample policy file with thresholds."""
    policy_file = tmp_path / "content_policy.yaml"
    policy_content = """
version: "1.0.0"
description: "Test policy"
rules:
  - id: test_rule
    category: "violence"
    severity: "high"
    description: "Test rule"
    patterns: []
    keywords: []

thresholds:
  harmful_output_rate: 0.05
  critical_violation_rate: 0.01
  utility_failure_rate: 0.1
"""
    policy_file.write_text(policy_content, encoding="utf-8")
    return policy_file


class TestLoadThresholdsFromPolicy:
    """Test loading thresholds from policy files."""

    def test_load_thresholds(self, sample_policy: Path) -> None:
        """Test loading thresholds from a valid policy file."""
        thresholds = load_thresholds_from_policy(sample_policy)

        assert "harmful_output_rate" in thresholds
        assert thresholds["harmful_output_rate"] == 0.05
        assert thresholds["critical_violation_rate"] == 0.01
        assert thresholds["utility_failure_rate"] == 0.1

    def test_no_thresholds_returns_empty(self, tmp_path: Path) -> None:
        """Test that policy without thresholds returns empty dict."""
        policy_file = tmp_path / "no_thresholds.yaml"
        policy_file.write_text(
            """
version: "1.0.0"
description: "Policy without thresholds"
rules: []
""",
            encoding="utf-8",
        )

        thresholds = load_thresholds_from_policy(policy_file)
        assert thresholds == {}

    def test_nonexistent_policy_raises_error(self, tmp_path: Path) -> None:
        """Test that nonexistent policy file raises error."""
        with pytest.raises(GateEvaluationError, match="Policy file not found"):
            load_thresholds_from_policy(tmp_path / "nonexistent.yaml")


class TestLoadMetricsFromSummary:
    """Test loading metrics from summary files."""

    def test_load_metrics(self, sample_summary: Path) -> None:
        """Test loading metrics from a valid summary file."""
        metrics = load_metrics_from_summary(sample_summary)

        assert metrics["total"] == 10.0
        assert metrics["passed"] == 9.0
        assert metrics["failed"] == 1.0
        assert metrics["harmful_output_rate"] == 0.05
        assert metrics["critical_violation_rate"] == 0.01
        assert metrics["utility_failure_rate"] == 0.1

    def test_nonexistent_summary_raises_error(self, tmp_path: Path) -> None:
        """Test that nonexistent summary file raises error."""
        with pytest.raises(GateEvaluationError, match="Summary file not found"):
            load_metrics_from_summary(tmp_path / "nonexistent.json")

    def test_invalid_json_raises_error(self, tmp_path: Path) -> None:
        """Test that invalid JSON raises error."""
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("invalid json content", encoding="utf-8")

        with pytest.raises(GateEvaluationError, match="Invalid JSON"):
            load_metrics_from_summary(invalid_file)


class TestEvaluateGates:
    """Test gate evaluation logic."""

    def test_all_thresholds_pass(self) -> None:
        """Test gate passes when all thresholds are met."""
        metrics = {
            "harmful_output_rate": 0.03,  # Below threshold of 0.05
            "critical_violation_rate": 0.005,  # Below threshold of 0.01
        }
        thresholds = {
            "harmful_output_rate": 0.05,
            "critical_violation_rate": 0.01,
        }

        result = evaluate_gates(metrics, thresholds)

        assert result.passed is True
        assert "Gate passed" in result.reason

    def test_threshold_breach_fails(self) -> None:
        """Test gate fails when threshold is breached."""
        metrics = {
            "harmful_output_rate": 0.10,  # Above threshold of 0.05
        }
        thresholds = {
            "harmful_output_rate": 0.05,
        }

        result = evaluate_gates(metrics, thresholds)

        assert result.passed is False
        assert "Gate failed" in result.reason
        assert "harmful_output_rate" in result.reason

    def test_multiple_thresholds_mixed(self) -> None:
        """Test gate with multiple thresholds where some pass and some fail."""
        metrics = {
            "harmful_output_rate": 0.03,  # Pass
            "critical_violation_rate": 0.02,  # Fail
        }
        thresholds = {
            "harmful_output_rate": 0.05,
            "critical_violation_rate": 0.01,
        }

        result = evaluate_gates(metrics, thresholds)

        assert result.passed is False  # Any failure causes overall failure

    def test_no_thresholds_passes(self) -> None:
        """Test that gate passes when no thresholds are defined."""
        metrics = {"harmful_output_rate": 0.10}
        thresholds = {}

        result = evaluate_gates(metrics, thresholds)

        assert result.passed is True
        assert "No thresholds defined" in result.reason

    def test_fail_on_conditions(self) -> None:
        """Test fail_on conditions from recipes."""
        metrics = {
            "harmful_output_rate": 0.0,
            "utility_failure_rate": 0.06,  # Above fail_on threshold
        }
        thresholds = {
            "harmful_output_rate": 0.05,
        }
        fail_on = ["utility_failure_rate > 0.05"]

        result = evaluate_gates(metrics, thresholds, fail_on=fail_on)

        assert result.passed is False
        assert "FAIL_ON" in result.reason

    def test_fail_on_with_threshold_pass(self) -> None:
        """Test fail_on condition that doesn't trigger."""
        metrics = {
            "harmful_output_rate": 0.0,
            "utility_failure_rate": 0.03,  # Below fail_on threshold
        }
        thresholds = {
            "harmful_output_rate": 0.05,
        }
        fail_on = ["utility_failure_rate > 0.05"]

        result = evaluate_gates(metrics, thresholds, fail_on=fail_on)

        assert result.passed is True  # Thresholds pass, fail_on doesn't trigger
