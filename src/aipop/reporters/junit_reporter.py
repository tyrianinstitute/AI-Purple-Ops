"""JUnit XML reporter for CI/CD integration."""

from __future__ import annotations

from pathlib import Path

from junit_xml import TestCase as JUnitTestCase
from junit_xml import TestSuite, to_xml_report_file

from aipop.core.models import RunResult


class JUnitReporter:
    """Generate JUnit XML reports for CI/CD integration.

    Compatible with GitHub Actions, Jenkins, GitLab CI, and other CI systems
    that support JUnit XML format.
    """

    def __init__(self, suite_name: str = "ai_purple_ops") -> None:
        """Initialize JUnit reporter.

        Args:
            suite_name: Name for the test suite in XML
        """
        self.suite_name = suite_name
        self._results: list[RunResult] = []
        self._file_path: Path | None = None

    def start(self, path: str) -> None:
        """Start a new report at the given path.

        Args:
            path: File path for JUnit XML output
        """
        self._file_path = Path(path)
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        self._results = []

    def write_case(self, result: RunResult) -> None:
        """Write a single test case result.

        Buffers results for final XML generation.

        Args:
            result: Test result to write
        """
        self._results.append(result)

    def finalize(self) -> None:
        """Finalize and write the JUnit XML report."""
        if not self._file_path:
            return

        # Convert to JUnit test cases
        junit_cases: list[JUnitTestCase] = []

        for result in self._results:
            # Extract timing info
            elapsed_sec = 0.0
            if "elapsed_ms" in result.metadata:
                elapsed_sec = result.metadata["elapsed_ms"] / 1000
            elif "model_meta" in result.metadata:
                model_meta = result.metadata["model_meta"]
                if "latency_ms" in model_meta:
                    elapsed_sec = model_meta["latency_ms"] / 1000

            # Create JUnit test case
            # classname follows convention: suite.category
            category = result.metadata.get("category", "unknown")
            classname = f"{self.suite_name}.{category}"

            test_case = JUnitTestCase(
                name=result.test_id,
                classname=classname,
                elapsed_sec=elapsed_sec,
                stdout=result.response,
            )

            # Add failure if test didn't pass
            if not result.passed:
                failure_message = "Test failed"
                failure_output = result.response

                # Try to extract more specific failure reason
                if "error" in result.metadata:
                    failure_message = result.metadata["error"]
                elif result.detector_results:
                    # Include policy violations in failure message
                    violations = []
                    for detector_result in result.detector_results:
                        if not detector_result.passed:
                            for violation in detector_result.violations:
                                violations.append(
                                    f"[{violation.severity.upper()}] {violation.rule_id}: {violation.message}"
                                )
                    if violations:
                        failure_message = f"Policy violations: {', '.join(violations[:3])}"
                        if len(violations) > 3:
                            failure_message += f" (+{len(violations) - 3} more)"
                        failure_output = f"{result.response}\n\nPolicy Violations:\n" + "\n".join(
                            f"- {v}" for v in violations
                        )
                elif "expected" in result.metadata:
                    expected = result.metadata["expected"]
                    failure_message = f"Expected {expected} behavior not observed"

                test_case.add_failure_info(
                    message=failure_message,
                    output=failure_output,
                )

            junit_cases.append(test_case)

        # Create test suite
        test_suite = TestSuite(self.suite_name, junit_cases)

        # Write XML file
        with self._file_path.open("w", encoding="utf-8") as f:
            to_xml_report_file(f, [test_suite], prettyprint=True)

    def write_summary(self, results: list[RunResult], path: str) -> None:
        """Convenience method: write all results at once.

        Args:
            results: List of test results
            path: Output file path
        """
        self.start(path)
        for result in results:
            self.write_case(result)
        self.finalize()
