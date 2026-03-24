"""Garak integration wrapper."""

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


class GarakWrapper:
    """Wrapper for Garak LLM vulnerability scanner."""

    def __init__(self) -> None:
        """Initialize Garak wrapper."""
        self.tool_name = "garak"

    def is_available(self) -> bool:
        """Check if garak is installed.

        Returns:
            True if garak CLI is available
        """
        try:
            result = subprocess.run(
                ["garak", "--version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            # Try Python module import as fallback
            try:
                import garak  # noqa: F401

                return True
            except ImportError:
                return False

    def execute(self, config: dict[str, Any], adapter: Adapter | None = None) -> ToolResult:
        """Execute garak with configuration.

        Args:
            config: Tool configuration from recipe
            adapter: Optional model adapter

        Returns:
            ToolResult with findings

        Raises:
            ToolNotAvailableError: If garak is not installed
            ToolExecutionError: If execution fails
        """
        if not self.is_available():
            raise ToolNotAvailableError("Garak is not installed. Install with: pip install garak")

        start_time = time.time()

        # Extract config
        probes = config.get("probes", ["encoding", "jailbreak"])
        model_name = config.get("model", "gpt-4")

        # Build garak command with JSON output
        # Try --output_format json first, fallback to stdout parsing
        import sys as _sys
        cmd = [_sys.executable, "-m", "garak", "--model_name", model_name]

        # Add probes
        if probes:
            cmd.extend(["--probes", ",".join(probes)])

        # Try to use JSON output format if available
        json_output_path = None
        with tempfile.TemporaryDirectory() as tmpdir:
            json_output_path = Path(tmpdir) / "garak_results.json"
            # Try --output_format json (if supported)
            cmd_json = cmd + ["--output_format", "json", "--output", str(json_output_path)]

            try:
                # First try with JSON output
                result = subprocess.run(
                    cmd_json,
                    capture_output=True,
                    text=True,
                    timeout=600,  # 10 minute timeout
                    cwd=tmpdir,
                    check=False,
                )

                execution_time = time.time() - start_time

                # Try parsing JSON output file
                if json_output_path.exists():
                    try:
                        raw_output = json.loads(json_output_path.read_text(encoding="utf-8"))
                        findings = self.parse_output(raw_output)
                    except json.JSONDecodeError:
                        # Fallback to stdout parsing
                        raw_output = {"stdout": result.stdout, "stderr": result.stderr}
                        findings = self._parse_stdout(result.stdout)
                else:
                    # No JSON file, try parsing stdout as JSON or JSONL
                    raw_output = {"stdout": result.stdout, "stderr": result.stderr}
                    findings = self._parse_stdout(result.stdout)

                    # Try parsing stdout as JSON/JSONL
                    if result.stdout.strip():
                        try:
                            # Try as single JSON object
                            stdout_json = json.loads(result.stdout)
                            findings = self.parse_output(stdout_json)
                            raw_output = stdout_json
                        except json.JSONDecodeError:
                            # Try as JSONL (line-delimited JSON)
                            jsonl_findings = []
                            for line in result.stdout.splitlines():
                                if line.strip():
                                    try:
                                        line_data = json.loads(line)
                                        jsonl_findings.extend(self.parse_output(line_data))
                                    except json.JSONDecodeError:
                                        continue
                            if jsonl_findings:
                                findings = jsonl_findings
                                raw_output = {"format": "jsonl", "lines": len(jsonl_findings)}

                return ToolResult(
                    tool_name=self.tool_name,
                    success=True,
                    findings=findings,
                    raw_output=raw_output,
                    execution_time=execution_time,
                )

            except subprocess.TimeoutExpired as e:
                raise ToolExecutionError(f"Garak execution timed out: {e}") from e
            except json.JSONDecodeError as e:
                raise ToolOutputParseError(f"Failed to parse garak output: {e}") from e
            except Exception as e:
                raise ToolExecutionError(f"Garak execution error: {e}") from e

    def parse_output(self, raw: Any) -> list[dict[str, Any]]:
        """Parse garak output into normalized findings.

        Args:
            raw: Raw garak JSON output

        Returns:
            List of normalized findings
        """
        findings: list[dict[str, Any]] = []

        if not isinstance(raw, dict):
            return findings

        # Garak output structure varies, try common formats
        results = raw.get("results", [])
        if not results and isinstance(raw, list):
            results = raw

        for result in results:
            probe_name = result.get("probe", result.get("name", "unknown"))
            success = result.get("success", False)
            response = result.get("response", result.get("output", ""))

            # If probe succeeded (found vulnerability), create finding
            if success:
                finding = {
                    "id": f"garak_{probe_name}",
                    "source": self.tool_name,
                    "category": normalize_category(probe_name),
                    "severity": normalize_severity(probe_name),
                    "attack_vector": probe_name,
                    "payload": result.get("prompt", result.get("input", "")),
                    "response": response,
                    "success": True,
                    "evidence": {
                        "probe": probe_name,
                        "result": result,
                    },
                    "remediation": normalize_remediation(probe_name),
                }
                findings.append(finding)

        return findings

    def _parse_stdout(self, stdout: str) -> list[dict[str, Any]]:
        """Parse garak stdout for findings (fallback).

        Args:
            stdout: Standard output from garak

        Returns:
            List of findings
        """
        findings: list[dict[str, Any]] = []
        # Basic parsing of stdout for probe results
        # This is a fallback if JSON output isn't available
        lines = stdout.split("\n")
        for line in lines:
            if "FAIL" in line or "VULN" in line:
                # Extract probe name and create basic finding
                parts = line.split()
                if len(parts) > 1:
                    probe_name = parts[0]
                    finding = {
                        "id": f"garak_{probe_name}",
                        "source": self.tool_name,
                        "category": normalize_category(probe_name),
                        "severity": normalize_severity(probe_name),
                        "attack_vector": probe_name,
                        "payload": "",
                        "response": "",
                        "success": True,
                        "evidence": {"stdout_line": line},
                        "remediation": normalize_remediation(probe_name),
                    }
                    findings.append(finding)

        return findings
