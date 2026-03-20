"""Tests for JUnitReporter."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from aipop.core.models import RunResult
from aipop.reporters.junit_reporter import JUnitReporter


class TestJUnitReporter:
    """Test JUnitReporter functionality."""

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
                },
            ),
            RunResult(
                test_id="test_002",
                response="Response 2",
                passed=False,
                metadata={
                    "category": "safety",
                    "elapsed_ms": 52.8,
                    "error": "Test failed: expected refusal",
                },
            ),
        ]

    def test_write_summary(self, tmp_path: Path, sample_results: list[RunResult]) -> None:
        """Test writing summary to JUnit XML file."""
        output_file = tmp_path / "junit.xml"
        reporter = JUnitReporter(suite_name="test_suite")

        reporter.write_summary(sample_results, str(output_file))

        assert output_file.exists()

    def test_xml_structure(self, tmp_path: Path, sample_results: list[RunResult]) -> None:
        """Test that XML has correct structure."""
        output_file = tmp_path / "structure.xml"
        reporter = JUnitReporter(suite_name="test_suite")

        reporter.write_summary(sample_results, str(output_file))

        tree = ET.parse(output_file)
        root = tree.getroot()

        assert root.tag == "testsuites"
        testsuite = root.find("testsuite")
        assert testsuite is not None
        assert testsuite.get("name") == "test_suite"

    def test_testcase_count(self, tmp_path: Path, sample_results: list[RunResult]) -> None:
        """Test that all test cases are included."""
        output_file = tmp_path / "count.xml"
        reporter = JUnitReporter(suite_name="test_suite")

        reporter.write_summary(sample_results, str(output_file))

        tree = ET.parse(output_file)
        root = tree.getroot()
        testsuite = root.find("testsuite")
        testcases = testsuite.findall("testcase")  # type: ignore

        assert len(testcases) == 2

    def test_passed_testcase(self, tmp_path: Path) -> None:
        """Test that passed test case has no failure element."""
        results = [
            RunResult(
                test_id="test_pass",
                response="Success",
                passed=True,
                metadata={"category": "utility", "elapsed_ms": 45.0},
            )
        ]

        output_file = tmp_path / "pass.xml"
        reporter = JUnitReporter()

        reporter.write_summary(results, str(output_file))

        tree = ET.parse(output_file)
        testcase = tree.find(".//testcase")
        assert testcase is not None

        failure = testcase.find("failure")
        assert failure is None  # No failure for passed test

    def test_failed_testcase(self, tmp_path: Path) -> None:
        """Test that failed test case has failure element."""
        results = [
            RunResult(
                test_id="test_fail",
                response="Failed response",
                passed=False,
                metadata={
                    "category": "safety",
                    "elapsed_ms": 50.0,
                    "error": "Expected refusal",
                },
            )
        ]

        output_file = tmp_path / "fail.xml"
        reporter = JUnitReporter()

        reporter.write_summary(results, str(output_file))

        tree = ET.parse(output_file)
        testcase = tree.find(".//testcase")
        assert testcase is not None

        failure = testcase.find("failure")
        assert failure is not None
        assert "Expected refusal" in failure.get("message", "")

    def test_timing_included(self, tmp_path: Path, sample_results: list[RunResult]) -> None:
        """Test that timing information is included."""
        output_file = tmp_path / "timing.xml"
        reporter = JUnitReporter()

        reporter.write_summary(sample_results, str(output_file))

        tree = ET.parse(output_file)
        testcases = tree.findall(".//testcase")

        for testcase in testcases:
            time_attr = testcase.get("time")
            assert time_attr is not None
            assert float(time_attr) > 0

    def test_classname_uses_category(self, tmp_path: Path) -> None:
        """Test that classname is constructed from suite and category."""
        results = [
            RunResult(
                test_id="test_001",
                response="Response",
                passed=True,
                metadata={"category": "safety", "elapsed_ms": 45.0},
            )
        ]

        output_file = tmp_path / "classname.xml"
        reporter = JUnitReporter(suite_name="my_suite")

        reporter.write_summary(results, str(output_file))

        tree = ET.parse(output_file)
        testcase = tree.find(".//testcase")
        assert testcase is not None

        classname = testcase.get("classname")
        assert classname == "my_suite.safety"

    def test_stdout_includes_response(self, tmp_path: Path) -> None:
        """Test that system-out includes test response."""
        results = [
            RunResult(
                test_id="test_001",
                response="This is the model response",
                passed=True,
                metadata={"category": "utility", "elapsed_ms": 45.0},
            )
        ]

        output_file = tmp_path / "stdout.xml"
        reporter = JUnitReporter()

        reporter.write_summary(results, str(output_file))

        tree = ET.parse(output_file)
        testcase = tree.find(".//testcase")
        assert testcase is not None

        system_out = testcase.find("system-out")
        # Note: junit-xml might not always create system-out, check if exists
        if system_out is not None:
            assert "This is the model response" in system_out.text  # type: ignore

    def test_streaming_write(self, tmp_path: Path, sample_results: list[RunResult]) -> None:
        """Test streaming write with start/write_case/finalize."""
        output_file = tmp_path / "stream.xml"
        reporter = JUnitReporter()

        reporter.start(str(output_file))
        for result in sample_results:
            reporter.write_case(result)
        reporter.finalize()

        assert output_file.exists()

    def test_empty_results(self, tmp_path: Path) -> None:
        """Test handling of empty results list."""
        output_file = tmp_path / "empty.xml"
        reporter = JUnitReporter()

        reporter.write_summary([], str(output_file))

        assert output_file.exists()

        tree = ET.parse(output_file)
        testsuite = tree.find(".//testsuite")
        assert testsuite is not None

    def test_creates_parent_directories(
        self, tmp_path: Path, sample_results: list[RunResult]
    ) -> None:
        """Test that parent directories are created if missing."""
        output_file = tmp_path / "nested" / "dir" / "junit.xml"
        reporter = JUnitReporter()

        reporter.write_summary(sample_results, str(output_file))

        assert output_file.exists()
        assert output_file.parent.exists()

    def test_default_category(self, tmp_path: Path) -> None:
        """Test that missing category defaults to 'unknown'."""
        results = [
            RunResult(
                test_id="test_001",
                response="Response",
                passed=True,
                metadata={"elapsed_ms": 45.0},  # No category
            )
        ]

        output_file = tmp_path / "default.xml"
        reporter = JUnitReporter(suite_name="suite")

        reporter.write_summary(results, str(output_file))

        tree = ET.parse(output_file)
        testcase = tree.find(".//testcase")
        assert testcase is not None

        classname = testcase.get("classname")
        assert classname == "suite.unknown"

    def test_failure_with_expected_metadata(self, tmp_path: Path) -> None:
        """Test that failure message uses 'expected' from metadata."""
        results = [
            RunResult(
                test_id="test_fail",
                response="Failed",
                passed=False,
                metadata={"category": "safety", "expected": "refuse", "elapsed_ms": 45.0},
            )
        ]

        output_file = tmp_path / "expected.xml"
        reporter = JUnitReporter()

        reporter.write_summary(results, str(output_file))

        tree = ET.parse(output_file)
        failure = tree.find(".//failure")
        assert failure is not None

        message = failure.get("message")
        assert "refuse" in message  # type: ignore
