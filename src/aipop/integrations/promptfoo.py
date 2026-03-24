"""Promptfoo integration wrapper."""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from aipop.core.adapters import Adapter
from aipop.integrations.base import (
    ToolResult,
    normalize_category,
    normalize_remediation,
    normalize_severity,
)
from aipop.integrations.exceptions import (
    ToolExecutionError,
    ToolNotAvailableError,
    ToolOutputParseError,
)


class PromptfooWrapper:
    """Wrapper for Promptfoo redteam tool."""

    def __init__(self) -> None:
        """Initialize Promptfoo wrapper."""
        self.tool_name = "promptfoo"

    def is_available(self) -> bool:
        """Check if promptfoo is installed (direct CLI or via npx).

        Returns:
            True if promptfoo CLI is available
        """
        # Try direct CLI first
        for cmd in [["promptfoo", "--version"], ["npx", "--yes", "promptfoo", "--version"]]:
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=15, check=False,
                )
                if result.returncode == 0:
                    self._cmd_prefix = cmd[:-1]  # Store the working command prefix
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                continue
        return False

    def execute(self, config: dict[str, Any], adapter: Adapter | None = None) -> ToolResult:
        """Execute promptfoo with configuration.

        Args:
            config: Tool configuration from recipe
            adapter: Optional model adapter (not used by promptfoo directly)

        Returns:
            ToolResult with findings

        Raises:
            ToolNotAvailableError: If promptfoo is not installed
            ToolExecutionError: If execution fails
        """
        if not self.is_available():
            raise ToolNotAvailableError(
                "Promptfoo is not installed. Install with: npm install -g promptfoo"
            )

        start_time = time.time()

        # Generate promptfoo configuration and execute
        with tempfile.TemporaryDirectory() as tmpdir:
            config_path = Path(tmpdir) / "promptfoo.yaml"
            output_path = Path(tmpdir) / "results.json"

            # Generate promptfoo config from recipe config
            promptfoo_config = self._generate_config(config, adapter)
            config_path.write_text(promptfoo_config, encoding="utf-8")

            # Run promptfoo
            try:
                cmd = [
                    "promptfoo",
                    "eval",
                    "-c",
                    str(config_path),
                    "-o",
                    str(output_path),
                    "--no-progress-bar",
                ]

                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,  # 5 minute timeout
                    cwd=tmpdir,
                    check=False,
                )

                execution_time = time.time() - start_time

                if result.returncode != 0:
                    raise ToolExecutionError(
                        f"Promptfoo execution failed: {result.stderr}\n{result.stdout}"
                    )

                # Parse output - promptfoo writes JSON to the output path
                if output_path.exists():
                    try:
                        raw_output = json.loads(output_path.read_text(encoding="utf-8"))
                        findings = self.parse_output(raw_output)
                    except json.JSONDecodeError as e:
                        # Try reading as JSONL (line-delimited JSON)
                        findings = []
                        raw_output = {"error": "Failed to parse JSON", "details": str(e)}
                        for line in output_path.read_text(encoding="utf-8").splitlines():
                            if line.strip():
                                try:
                                    line_data = json.loads(line)
                                    findings.extend(self.parse_output(line_data))
                                except json.JSONDecodeError:
                                    continue
                else:
                    # Fallback: try parsing stdout as JSON
                    raw_output = {"stdout": result.stdout, "stderr": result.stderr}
                    findings = []
                    if result.stdout.strip():
                        try:
                            stdout_json = json.loads(result.stdout)
                            findings = self.parse_output(stdout_json)
                            raw_output = stdout_json
                        except json.JSONDecodeError:
                            # Not JSON, leave findings empty
                            pass

                return ToolResult(
                    tool_name=self.tool_name,
                    success=True,
                    findings=findings,
                    raw_output=raw_output,
                    execution_time=execution_time,
                )

            except subprocess.TimeoutExpired as e:
                raise ToolExecutionError(f"Promptfoo execution timed out: {e}") from e
            except json.JSONDecodeError as e:
                raise ToolOutputParseError(f"Failed to parse promptfoo output: {e}") from e
            except Exception as e:
                raise ToolExecutionError(f"Promptfoo execution error: {e}") from e

    def _generate_config(self, config: dict[str, Any], adapter: Adapter | None) -> str:
        """Generate promptfoo YAML config from recipe config.

        Args:
            config: Tool configuration from recipe
            adapter: Optional model adapter

        Returns:
            Promptfoo YAML config string
        """
        # Extract model info from adapter or config
        model_name = config.get("model", "gpt-4")
        provider = config.get("provider", "openai")

        # Build promptfoo config
        promptfoo_yaml = f"""providers:
  - {provider}:
      model: {model_name}

tests:
  - vars:
      prompt: "{{{{prompt}}}}"
"""

        # Add plugins if specified
        plugins = config.get("plugins", ["prompt-injection", "harmful"])
        if plugins:
            promptfoo_yaml += "\nplugins:\n"
            for plugin in plugins:
                promptfoo_yaml += f"  - {plugin}\n"

        return promptfoo_yaml

    def parse_output(self, raw: Any) -> list[dict[str, Any]]:
        """Parse promptfoo output into normalized findings.

        Args:
            raw: Raw promptfoo JSON output

        Returns:
            List of normalized findings
        """
        findings: list[dict[str, Any]] = []

        if not isinstance(raw, dict):
            return findings

        # Promptfoo output structure: { results: [...], stats: {...} }
        results = raw.get("results", [])

        for result in results:
            # Extract test case info
            test_name = result.get("name", "unknown")
            success = result.get("success", False)
            output = result.get("output", {})

            # Extract assertions/checks
            checks = result.get("checks", [])
            for check in checks:
                check_name = check.get("name", "")
                check_passed = check.get("passed", True)

                # If check failed, it's a finding (vulnerability detected)
                if not check_passed:
                    finding = {
                        "id": f"promptfoo_{test_name}_{check_name}",
                        "source": self.tool_name,
                        "category": normalize_category(check_name),
                        "severity": normalize_severity(check_name),
                        "attack_vector": check_name,
                        "payload": result.get("vars", {}).get("prompt", test_name),
                        "response": output.get("text", output.get("content", "")),
                        "success": True,  # Finding = vulnerability found
                        "evidence": {
                            "test_name": test_name,
                            "check_name": check_name,
                            "check_result": check,
                            "output": output,
                        },
                        "remediation": normalize_remediation(check_name),
                    }
                    findings.append(finding)

        return findings
