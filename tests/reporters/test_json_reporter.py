"""Tests for JSONReporter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aipop.core.models import RunResult
from aipop.reporters.json_reporter import JSONReporter


class TestJSONReporter:
    """Test JSONReporter functionality."""

    @pytest.fixture
    def sample_results(self) -> list[RunResult]:
        """Create sample test results."""
        return [
            RunResult(
                test_id="test_001",
                response="Response 1",
                passed=True,
                metadata={
                    "category": "utility",
                    "elapsed_ms": 45.2,
                    "model_meta": {
                        "tokens": 10,
                        "latency_ms": 40.0,
                        "cost_usd": 0.0001,
                    },
                },
            ),
            RunResult(
                test_id="test_002",
                response="Response 2",
                passed=True,
                metadata={
                    "category": "safety",
                    "elapsed_ms": 52.8,
                    "model_meta": {
                        "tokens": 15,
                        "latency_ms": 50.0,
                        "cost_usd": 0.00015,
                    },
                },
            ),
            RunResult(
                test_id="test_003",
                response="Response 3",
                passed=False,
                metadata={
                    "category": "safety",
                    "elapsed_ms": 38.1,
                    "model_meta": {
                        "tokens": 8,
                        "latency_ms": 35.0,
                        "cost_usd": 0.00008,
                    },
                },
            ),
        ]

    def test_write_summary(self, tmp_path: Path, sample_results: list[RunResult]) -> None:
        """Test writing summary to JSON file."""
        output_file = tmp_path / "summary.json"
        reporter = JSONReporter()

        reporter.write_summary(sample_results, str(output_file))

        assert output_file.exists()

        # Load and verify JSON
        with output_file.open("r") as f:
            data = json.load(f)

        assert data["total"] == 3
        assert data["passed"] == 2
        assert data["failed"] == 1

    def test_streaming_write(self, tmp_path: Path, sample_results: list[RunResult]) -> None:
        """Test streaming write with start/write_case/finalize."""
        output_file = tmp_path / "stream.json"
        reporter = JSONReporter()

        reporter.start(str(output_file))
        for result in sample_results:
            reporter.write_case(result)
        reporter.finalize()

        assert output_file.exists()

    def test_schema_compliance(self, tmp_path: Path, sample_results: list[RunResult]) -> None:
        """Test that output complies with run_summary.schema.json."""
        output_file = tmp_path / "schema_test.json"
        reporter = JSONReporter()

        reporter.write_summary(sample_results, str(output_file))

        with output_file.open("r") as f:
            data = json.load(f)

        # Check required fields from schema
        assert "total" in data
        assert "harmful_output_rate" in data
        assert "tool_policy_violation_rate" in data
        assert "utility_failure_rate" in data
        assert "results" in data

        # Check types
        assert isinstance(data["total"], int)
        assert isinstance(data["harmful_output_rate"], (int, float))
        assert isinstance(data["tool_policy_violation_rate"], (int, float))
        assert isinstance(data["utility_failure_rate"], (int, float))
        assert isinstance(data["results"], list)

    def test_metrics_calculation(self, tmp_path: Path, sample_results: list[RunResult]) -> None:
        """Test that metrics are calculated correctly."""
        output_file = tmp_path / "metrics.json"
        reporter = JSONReporter()

        reporter.write_summary(sample_results, str(output_file))

        with output_file.open("r") as f:
            data = json.load(f)

        assert data["total"] == 3
        assert data["passed"] == 2
        assert data["failed"] == 1
        assert data["utility_failure_rate"] == pytest.approx(0.3333, rel=0.01)

    def test_latency_percentile(self, tmp_path: Path, sample_results: list[RunResult]) -> None:
        """Test that latency percentile is calculated."""
        output_file = tmp_path / "latency.json"
        reporter = JSONReporter()

        reporter.write_summary(sample_results, str(output_file))

        with output_file.open("r") as f:
            data = json.load(f)

        assert "latency_ms_p50" in data
        assert isinstance(data["latency_ms_p50"], (int, float))
        assert data["latency_ms_p50"] > 0

    def test_cost_aggregation(self, tmp_path: Path, sample_results: list[RunResult]) -> None:
        """Test that costs are aggregated."""
        output_file = tmp_path / "cost.json"
        reporter = JSONReporter()

        reporter.write_summary(sample_results, str(output_file))

        with output_file.open("r") as f:
            data = json.load(f)

        assert "cost_usd" in data
        expected_cost = 0.0001 + 0.00015 + 0.00008
        assert data["cost_usd"] == pytest.approx(expected_cost, rel=0.0001)

    def test_empty_results(self, tmp_path: Path) -> None:
        """Test handling of empty results list."""
        output_file = tmp_path / "empty.json"
        reporter = JSONReporter()

        reporter.write_summary([], str(output_file))

        with output_file.open("r") as f:
            data = json.load(f)

        assert data["total"] == 0
        assert data["passed"] == 0
        assert data["failed"] == 0
        assert data["results"] == []

    def test_creates_parent_directories(
        self, tmp_path: Path, sample_results: list[RunResult]
    ) -> None:
        """Test that parent directories are created if missing."""
        output_file = tmp_path / "nested" / "dir" / "summary.json"
        reporter = JSONReporter()

        reporter.write_summary(sample_results, str(output_file))

        assert output_file.exists()
        assert output_file.parent.exists()

    def test_result_objects_included(self, tmp_path: Path, sample_results: list[RunResult]) -> None:
        """Test that individual result objects are included."""
        output_file = tmp_path / "results.json"
        reporter = JSONReporter()

        reporter.write_summary(sample_results, str(output_file))

        with output_file.open("r") as f:
            data = json.load(f)

        assert len(data["results"]) == 3

        result = data["results"][0]
        assert "test_id" in result
        assert "passed" in result
        assert "response" in result
        assert "metadata" in result

    def test_json_formatting(self, tmp_path: Path, sample_results: list[RunResult]) -> None:
        """Test that JSON is pretty-printed for readability."""
        output_file = tmp_path / "formatted.json"
        reporter = JSONReporter()

        reporter.write_summary(sample_results, str(output_file))

        content = output_file.read_text()

        # Check for indentation (pretty printing)
        assert "\n" in content
        assert "  " in content  # Indentation

    def test_rounding_precision(self, tmp_path: Path) -> None:
        """Test that numeric values are rounded appropriately."""
        results = [
            RunResult(
                test_id="test",
                response="response",
                passed=True,
                metadata={
                    "elapsed_ms": 45.123456789,
                    "model_meta": {
                        "latency_ms": 40.987654321,
                        "cost_usd": 0.000123456789,
                    },
                },
            )
        ]

        output_file = tmp_path / "precision.json"
        reporter = JSONReporter()

        reporter.write_summary(results, str(output_file))

        with output_file.open("r") as f:
            data = json.load(f)

        # Check rounding
        assert len(str(data["latency_ms_p50"]).split(".")[-1]) <= 2  # 2 decimal places
        assert len(str(data["cost_usd"]).split(".")[-1]) <= 6  # 6 decimal places
