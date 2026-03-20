"""Recipe executor for orchestrating recipe workflows."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC
from pathlib import Path
from typing import Any

from aipop.adapters.registry import AdapterRegistry
from aipop.core.detectors import Detector
from aipop.detectors.harmful_content import HarmfulContentDetector
from aipop.detectors.tool_policy import ToolPolicyDetector
from aipop.integrations.orchestrator import orchestrate_tools
from aipop.loaders.policy_loader import load_policy
from aipop.loaders.recipe_loader import RecipeConfig
from aipop.loaders.yaml_suite import load_yaml_suite
from aipop.reporters.evidence_pack import EvidencePackGenerator
from aipop.reporters.json_reporter import JSONReporter
from aipop.reporters.junit_reporter import JUnitReporter
from aipop.runners.mock import MockRunner
from aipop.utils.errors import HarnessError
from aipop.utils.log_utils import log


class RecipeExecutionError(HarnessError):
    """Error during recipe execution."""


@dataclass
class RecipeExecutionResult:
    """Result of recipe execution."""

    success: bool
    run_id: str
    summary_path: Path | None = None
    junit_path: Path | None = None
    evidence_pack_path: Path | None = None
    metrics: dict[str, Any] | None = None
    error: str | None = None


def execute_recipe(
    recipe: RecipeConfig,
    output_dir: Path | str = "out",
    run_id: str | None = None,
) -> RecipeExecutionResult:
    """Execute a recipe workflow end-to-end.

    Orchestrates the complete workflow:
    1. Load test suites
    2. Configure detectors
    3. Execute tests
    4. Generate reports
    5. Generate evidence pack
    6. Run gates

    Args:
        recipe: Loaded recipe configuration
        output_dir: Base output directory
        run_id: Optional run identifier (generated if not provided)

    Returns:
        RecipeExecutionResult with execution status and artifacts

    Raises:
        RecipeExecutionError: If execution fails
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Generate run ID if not provided
    if not run_id:
        import os
        import uuid
        from datetime import datetime

        now = datetime.now(UTC)
        run_id = f"run-{now.strftime('%Y%m%dT%H%M%S')}-{os.getpid()}-{uuid.uuid4().hex[:6]}"

    try:
        # Load test suites
        all_test_cases = []
        for suite_name in recipe.execution.get("suites", []):
            suite_path = Path(f"suites/{suite_name}")
            # Handle nested paths (e.g., policies/content_safety ->
            # suites/policies/content_safety.yaml)
            if not suite_path.exists():
                # Try as a file path (add .yaml extension)
                suite_file = suite_path.with_suffix(".yaml")
                if suite_file.exists():
                    suite_path = suite_file
                else:
                    # Try parent directory if it exists (for nested paths)
                    parent_dir = suite_path.parent
                    if parent_dir.exists() and parent_dir.is_dir():
                        # Use parent directory - loader will find YAML files
                        suite_path = parent_dir
                    else:
                        raise RecipeExecutionError(f"Suite not found: {suite_name}")
            test_cases = load_yaml_suite(suite_path)
            all_test_cases.extend(test_cases)

        if not all_test_cases:
            raise RecipeExecutionError("No test cases found in specified suites")

        # Configure detectors from recipe
        detectors: list[Detector] = []
        detector_configs = recipe.execution.get("detectors", [])
        for detector_config in detector_configs:
            if isinstance(detector_config, dict):
                if "harmful_content" in detector_config:
                    # Load content policy
                    policy_config = load_policy("policies/content_policy.yaml")
                    if policy_config.content_policy:
                        detectors.append(HarmfulContentDetector(policy_config.content_policy))
                elif "tool_policy" in detector_config:
                    # Load tool policy
                    policy_config = load_policy("policies/tool_allowlist.yaml")
                    if policy_config.tool_policy:
                        detectors.append(ToolPolicyDetector(policy_config.tool_policy))

        # Get seed from config (default: 42)
        seed = recipe.config.get("seed", 42)
        if isinstance(seed, str):
            try:
                seed = int(seed)
            except ValueError:
                seed = 42

        # Load adapter from recipe config
        adapter_name = recipe.config.get("adapter", "mock")
        adapter_config = recipe.config.get("adapter_config", {})

        # Add seed to config if adapter supports it (for mock adapter)
        if adapter_name == "mock":
            if "seed" not in adapter_config:
                adapter_config["seed"] = seed
            if "response_mode" not in adapter_config:
                adapter_config["response_mode"] = "smart"

        try:
            adapter = AdapterRegistry.get(adapter_name, config=adapter_config)
        except Exception as e:
            available = AdapterRegistry.list_adapters()
            raise RecipeExecutionError(
                f"Failed to load adapter '{adapter_name}': {e}\n"
                f"Available adapters: {', '.join(available) if available else 'none'}\n"
                f"Run aipop adapter --help for setup."
            ) from e

        # Test adapter connection before executing tests
        try:
            test_response = adapter.invoke("test", max_tokens=10)
            if not test_response or not test_response.text:
                raise RuntimeError("Adapter returned empty response")
        except Exception as e:
            raise RecipeExecutionError(
                f"Adapter connection test failed: {e}\n"
                f"Check adapter configuration and availability.\n"
                f"Adapter: {adapter_name}"
            ) from e

        # Initialize runner
        runner = MockRunner(adapter=adapter, seed=seed, detectors=detectors if detectors else None)

        # Execute tests
        results = list(runner.execute_many(all_test_cases))

        # Execute external tools if specified in recipe
        tool_results: list[Any] = []
        tool_statuses: list[Any] = []
        tools_config = recipe.execution.get("tools", [])
        skip_missing_tools = recipe.execution.get("skip_missing_tools", False)
        if tools_config:
            log.info(f"Executing {len(tools_config)} external tool(s)...")
            try:
                tool_results, tool_statuses = orchestrate_tools(
                    tools_config, adapter=adapter, skip_missing=skip_missing_tools
                )
                executed_count = sum(1 for s in tool_statuses if s.executed)
                log.ok(
                    f"Tool execution completed: {executed_count}/{len(tools_config)} tool(s) executed"
                )
            except Exception as e:
                log.warn(f"Tool execution encountered errors: {e}")
                # Continue execution even if tools fail

        # Setup output directories
        reports_dir = output_dir / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        # Generate reports based on recipe outputs
        summary_path = None
        junit_path = None

        outputs = recipe.outputs or {}
        report_configs = outputs.get("reports", [])

        # Default to both JSON and JUnit if not specified
        if not report_configs:
            report_configs = [
                {"type": "json", "path": str(reports_dir / "summary.json")},
                {"type": "junit", "path": str(reports_dir / "junit.xml")},
            ]

        for report_config in report_configs:
            report_type = report_config.get("type", "json")
            report_path_str = report_config.get(
                "path", str(reports_dir / f"{report_type}.{report_type}")
            )
            # Resolve relative paths relative to output_dir
            report_path = Path(report_path_str)
            if not report_path.is_absolute():
                report_path = output_dir / report_path

            if report_type == "json":
                json_reporter = JSONReporter()
                json_reporter.write_summary(results, str(report_path))
                summary_path = report_path

                # Add run metadata and tool results
                import json

                with report_path.open("r", encoding="utf-8") as f:
                    summary_data = json.load(f)
                summary_data["run_id"] = run_id
                summary_data["recipe"] = recipe.metadata.get("name", "unknown")

                # Add tool results and statuses if any tools were configured
                if tool_statuses:
                    summary_data["tool_status"] = [
                        {
                            "tool_name": ts.tool_name,
                            "available": ts.available,
                            "executed": ts.executed,
                            "success": ts.success,
                            "findings_count": ts.findings_count,
                            "error": ts.error,
                        }
                        for ts in tool_statuses
                    ]

                if tool_results:
                    summary_data["tool_results"] = [
                        {
                            "tool_name": tr.tool_name,
                            "success": tr.success,
                            "findings_count": len(tr.findings),
                            "execution_time": tr.execution_time,
                            "findings": tr.findings,
                            "error": tr.error,
                        }
                        for tr in tool_results
                    ]
                    # Aggregate tool findings
                    all_tool_findings = []
                    for tr in tool_results:
                        all_tool_findings.extend(tr.findings)
                    summary_data["tool_findings"] = all_tool_findings
                    summary_data["total_tool_findings"] = len(all_tool_findings)

                with report_path.open("w", encoding="utf-8") as f:
                    json.dump(summary_data, f, indent=2, ensure_ascii=False)

            elif report_type == "junit":
                suite_name = recipe.metadata.get("name", "recipe")
                junit_reporter = JUnitReporter(suite_name=suite_name)
                junit_reporter.write_summary(results, str(report_path))
                junit_path = report_path

        # Generate evidence pack if configured
        evidence_pack_path = None
        evidence_config = outputs.get("evidence_pack")
        if evidence_config:
            # Get path and resolve any variables
            evidence_path_str = evidence_config.get(
                "path", str(output_dir / "evidence" / f"{run_id}_evidence.zip")
            )
            # Replace special variables like TIMESTAMP
            if isinstance(evidence_path_str, str):
                timestamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S")
                evidence_path_str = evidence_path_str.replace("${TIMESTAMP}", timestamp)
                # Resolve other environment variables if any remain
                if "${" in evidence_path_str:
                    from aipop.loaders.recipe_loader import resolve_variables

                    evidence_path_str = resolve_variables(evidence_path_str)

            # Use output_dir/evidence as base (not evidence_path.parent
            # which might already be evidence)
            evidence_base_dir = output_dir / "evidence"
            evidence_base_dir.mkdir(parents=True, exist_ok=True)

            generator = EvidencePackGenerator(evidence_base_dir)

            # Prepare tool results for evidence pack
            tool_results_data = None
            if tool_statuses:
                tool_results_data = {
                    "tools": [
                        {
                            "tool_name": ts.tool_name,
                            "available": ts.available,
                            "executed": ts.executed,
                            "success": ts.success,
                            "findings_count": ts.findings_count,
                            "error": ts.error,
                        }
                        for ts in tool_statuses
                    ],
                    "total_findings": (
                        sum(len(tr.findings) for tr in tool_results) if tool_results else 0
                    ),
                    "executed_count": sum(1 for ts in tool_statuses if ts.executed),
                    "missing_count": sum(1 for ts in tool_statuses if not ts.available),
                }

            evidence_pack_path = generator.generate(
                run_id=run_id,
                summary_path=summary_path or (reports_dir / "summary.json"),
                junit_path=junit_path,
                transcripts_dir=None,  # Transcripts not implemented yet
                gate_result=None,  # Gate evaluation happens separately
                metrics=None,  # Metrics from summary
                tool_results=tool_results_data,
            )

        # Extract metrics from summary if available
        metrics = None
        if summary_path and summary_path.exists():
            import json

            with summary_path.open("r", encoding="utf-8") as f:
                summary_data = json.load(f)
                metrics = {
                    "total": summary_data.get("total", 0),
                    "passed": summary_data.get("passed", 0),
                    "failed": summary_data.get("failed", 0),
                    "harmful_output_rate": summary_data.get("harmful_output_rate", 0.0),
                    "tool_policy_violation_rate": summary_data.get(
                        "tool_policy_violation_rate", 0.0
                    ),
                    "utility_failure_rate": summary_data.get("utility_failure_rate", 0.0),
                    "critical_violation_rate": summary_data.get("critical_violation_rate", 0.0),
                }

        # Determine success (all tests passed)
        success = all(r.passed for r in results)

        return RecipeExecutionResult(
            success=success,
            run_id=run_id,
            summary_path=summary_path,
            junit_path=junit_path,
            evidence_pack_path=evidence_pack_path,
            metrics=metrics,
        )

    except Exception as e:
        # Preserve full error information for debugging
        import traceback

        error_msg = str(e)
        error_traceback = traceback.format_exc()
        log.error(f"Recipe execution failed: {error_msg}\n{error_traceback}")

        return RecipeExecutionResult(
            success=False,
            run_id=run_id or "unknown",
            error=f"{error_msg}\n\nTraceback:\n{error_traceback}",
        )
