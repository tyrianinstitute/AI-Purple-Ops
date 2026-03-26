"""JSON reporter for structured test results."""

from __future__ import annotations

import json
import statistics
from pathlib import Path
from typing import Any

from aipop.core.models import RunResult
from aipop.reporters.utils import sanitize_surrogates


class JSONReporter:
    """Generate structured JSON reports compliant with run_summary.schema.json.

    Supports both streaming (write_case) and batch (write_summary) modes.
    Aggregates metrics like pass rate, latency percentiles, and costs.
    """

    def __init__(self) -> None:
        """Initialize JSON reporter."""
        self._results: list[RunResult] = []
        self._file_path: Path | None = None
        self._file_handle: Any = None

    def start(self, path: str) -> None:
        """Start a new report at the given path.

        Args:
            path: File path for JSON output
        """
        self._file_path = Path(path)
        self._file_path.parent.mkdir(parents=True, exist_ok=True)
        self._results = []
        # Don't open file yet - we'll write all at once in finalize

    def write_case(self, result: RunResult) -> None:
        """Write a single test case result.

        Buffers results in memory for aggregation. In streaming mode,
        this enables incremental collection while allowing us to compute
        summary statistics at finalization.

        Args:
            result: Test result to write
        """
        self._results.append(result)

    def finalize(self) -> None:
        """Finalize and write the complete report.

        Computes aggregate metrics and writes schema-compliant JSON.
        """
        if not self._file_path:
            return

        summary = self._build_summary(self._results)

        # Write pretty-printed JSON for human readability.
        # Sanitize surrogates that may come from unicode smuggling payloads —
        # they are valid in Python str but cannot be encoded to UTF-8.
        json_text = json.dumps(summary, indent=2, ensure_ascii=False)
        json_text = sanitize_surrogates(json_text)
        with self._file_path.open("w", encoding="utf-8") as f:
            f.write(json_text)

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

    def _build_summary(self, results: list[RunResult]) -> dict[str, Any]:
        """Build summary dictionary from results.

        Computes metrics required by run_summary.schema.json:
        - total, passed, failed counts
        - harmful_output_rate
        - tool_policy_violation_rate
        - utility_failure_rate
        - latency_ms_p50
        - cost_usd

        Args:
            results: List of test results

        Returns:
            Summary dictionary
        """
        if not results:
            return {
                "total": 0,
                "passed": 0,
                "failed": 0,
                "harmful_output_rate": 0.0,
                "tool_policy_violation_rate": 0.0,
                "utility_failure_rate": 0.0,
                "critical_violation_rate": 0.0,
                "latency_ms_p50": 0.0,
                "cost_usd": 0.0,
                "results": [],
            }

        total = len(results)
        passed = sum(1 for r in results if r.passed)
        failed = total - passed

        # Extract metrics from metadata
        latencies: list[float] = []
        costs: list[float] = []

        for result in results:
            # Extract latency
            if "elapsed_ms" in result.metadata:
                latencies.append(result.metadata["elapsed_ms"])
            elif "model_meta" in result.metadata:
                model_meta = result.metadata["model_meta"]
                if "latency_ms" in model_meta:
                    latencies.append(model_meta["latency_ms"])

            # Extract cost
            if "model_meta" in result.metadata:
                model_meta = result.metadata["model_meta"]
                if "cost_usd" in model_meta:
                    costs.append(model_meta["cost_usd"])

        # Compute percentiles
        latency_p50 = statistics.median(latencies) if latencies else 0.0
        total_cost = sum(costs) if costs else 0.0

        # Compute rates using detector results (b05)
        utility_failure_rate = failed / total if total > 0 else 0.0

        # Count harmful outputs and tool violations from detectors
        harmful_count = 0
        tool_violation_count = 0
        critical_violation_count = 0
        for result in results:
            has_critical = False

            # Check detector results for violations
            if result.detector_results:
                for detector_result in result.detector_results:
                    if (
                        detector_result.detector_name == "harmful_content"
                        and not detector_result.passed
                    ):
                        harmful_count += 1
                        # Check for critical severity violations from detector
                        if not has_critical:
                            for violation in detector_result.violations:
                                if violation.severity == "critical":
                                    critical_violation_count += 1
                                    has_critical = True
                                    break
                    elif (
                        detector_result.detector_name == "tool_policy"
                        and not detector_result.passed
                    ):
                        tool_violation_count += 1

            # Also count failed tests with critical risk in metadata
            # This aligns gate metrics with the CLI vulnerability report
            if not result.passed and not has_critical:
                risk = result.metadata.get("risk", "").lower()
                if risk == "critical":
                    critical_violation_count += 1

        harmful_output_rate = harmful_count / total if total > 0 else 0.0
        tool_policy_violation_rate = tool_violation_count / total if total > 0 else 0.0
        critical_violation_rate = critical_violation_count / total if total > 0 else 0.0

        # Build result objects with detector results
        result_objects = []
        for r in results:
            # Enrich with taxonomy data (human title, description, remediation)
            taxonomy_info = {}
            try:
                from aipop.data import get_finding_info
                info = get_finding_info(r.test_id)
                if info.get("title") != r.test_id:
                    taxonomy_info = {
                        "title": info.get("title", r.test_id),
                        "description": info.get("description", ""),
                        "remediation": info.get("remediation", ""),
                        "owasp_llm": info.get("owasp_llm", ""),
                        "owasp_agentic": info.get("owasp_agentic", ""),
                        "atlas": info.get("atlas", ""),
                        "cvss_estimate": info.get("cvss_estimate", 0.0),
                    }
            except ImportError:
                pass

            result_obj = {
                "test_id": r.test_id,
                **taxonomy_info,
                "prompt": r.prompt,
                "passed": r.passed,
                "response": r.response,
                "metadata": r.metadata,
            }
            # Include detector results if available
            if r.detector_results:
                result_obj["detector_results"] = [
                    {
                        "detector_name": dr.detector_name,
                        "passed": dr.passed,
                        "violations": [
                            {
                                "rule_id": v.rule_id,
                                "severity": v.severity,
                                "message": v.message,
                                "matched_text": v.matched_text,
                            }
                            for v in dr.violations
                        ],
                        "metadata": dr.metadata,
                    }
                    for dr in r.detector_results
                ]
            result_objects.append(result_obj)

        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "harmful_output_rate": round(harmful_output_rate, 4),
            "tool_policy_violation_rate": round(tool_policy_violation_rate, 4),
            "utility_failure_rate": round(utility_failure_rate, 4),
            "critical_violation_rate": round(critical_violation_rate, 4),
            "latency_ms_p50": round(latency_p50, 2),
            "cost_usd": round(total_cost, 6),
            "results": result_objects,
        }
