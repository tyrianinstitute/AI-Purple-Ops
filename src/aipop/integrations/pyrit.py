"""PyRIT integration wrapper."""

from __future__ import annotations

import importlib.util
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
    ToolNotAvailableError,
)


class PyRITWrapper:
    """Wrapper for PyRIT (Python Risk Identification Toolkit)."""

    def __init__(self) -> None:
        """Initialize PyRIT wrapper."""
        self.tool_name = "pyrit"

    def is_available(self) -> bool:
        """Check if pyrit is installed.

        Returns:
            True if pyrit is available
        """
        try:
            # Try Python import first
            spec = importlib.util.find_spec("pyrit")
            if spec is not None:
                return True
            # Module not found via import
            return False
        except ImportError:
            # Try CLI as fallback
            try:
                result = subprocess.run(
                    ["pyrit", "--version"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                return result.returncode == 0
            except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
                return False

    def execute(self, config: dict[str, Any], adapter: Adapter | None = None) -> ToolResult:
        """Execute PyRIT with configuration.

        Args:
            config: Tool configuration from recipe
            adapter: Optional model adapter

        Returns:
            ToolResult with findings

        Raises:
            ToolNotAvailableError: If pyrit is not installed
            ToolExecutionError: If execution fails
        """
        if not self.is_available():
            raise ToolNotAvailableError(
                "PyRIT is not installed. Install from: https://github.com/Azure/PyRIT"
            )

        start_time = time.time()
        strategies = config.get("strategies", ["red-team-orchestrator"])
        model_name = config.get("model", "gpt-4")

        # Try Python API first
        try:
            spec = importlib.util.find_spec("pyrit")
            if spec is None:
                raise ImportError("pyrit package not found")

            # Import PyRIT modules
            pyrit_module = importlib.import_module("pyrit")

            # PyRIT uses orchestrator pattern - try to use RedTeamOrchestrator
            # This is a simplified integration - full implementation would require
            # proper PyRIT setup with Azure OpenAI endpoint configuration
            try:
                from pyrit.models import ChatMessage
                from pyrit.orchestrator import RedTeamOrchestrator

                # Create orchestrator (requires Azure OpenAI endpoint)
                # For now, we'll use a mock/test approach if endpoint not configured
                raw_output = {
                    "strategies": strategies,
                    "model": model_name,
                    "integration_status": "PyRIT Python API available but requires Azure OpenAI endpoint configuration",
                    "note": "Configure Azure OpenAI endpoint to use PyRIT orchestrator",
                }
                findings: list[dict[str, Any]] = []

            except ImportError:
                # PyRIT API structure may differ - try alternative import
                raw_output = {
                    "strategies": strategies,
                    "model": model_name,
                    "integration_status": "PyRIT package found but API structure unknown",
                }
                findings = []

            execution_time = time.time() - start_time

            # Only report success if the attack actually produced findings.
            # Importability alone is not execution.
            actually_ran = len(findings) > 0
            return ToolResult(
                tool_name=self.tool_name,
                success=actually_ran,
                findings=findings,
                raw_output=raw_output,
                execution_time=execution_time,
            )

        except ImportError:
            # PyRIT not available - try CLI fallback
            with tempfile.TemporaryDirectory() as tmpdir:
                output_path = Path(tmpdir) / "pyrit_results.json"

                # Try PyRIT CLI if available
                cmd = ["pyrit", "run", "--strategy", ",".join(strategies), "--model", model_name]
                if adapter:
                    # Try to extract endpoint info from adapter
                    if hasattr(adapter, "endpoint"):
                        cmd.extend(["--endpoint", str(adapter.endpoint)])

                try:
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=600,
                        cwd=tmpdir,
                        check=False,
                    )

                    execution_time = time.time() - start_time

                    # Parse output
                    if output_path.exists():
                        try:
                            raw_output = json.loads(output_path.read_text(encoding="utf-8"))
                            findings = self.parse_output(raw_output)
                        except json.JSONDecodeError:
                            raw_output = {"stdout": result.stdout, "stderr": result.stderr}
                            findings = self._parse_stdout(result.stdout)
                    else:
                        raw_output = {"stdout": result.stdout, "stderr": result.stderr}
                        findings = self._parse_stdout(result.stdout)

                    return ToolResult(
                        tool_name=self.tool_name,
                        success=result.returncode == 0,
                        findings=findings,
                        raw_output=raw_output,
                        execution_time=execution_time,
                    )
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    # CLI not available - return informative result
                    raw_output = {
                        "strategies": strategies,
                        "model": model_name,
                        "integration_status": "PyRIT requires installation and Azure OpenAI endpoint configuration",
                        "installation": "pip install pyrit",
                        "docs": "https://github.com/Azure/PyRIT",
                    }
                    findings = []
                    execution_time = time.time() - start_time

                    return ToolResult(
                        tool_name=self.tool_name,
                        success=False,
                        findings=findings,
                        raw_output=raw_output,
                        execution_time=execution_time,
                        error="PyRIT not properly configured. Install pyrit package and configure Azure OpenAI endpoint.",
                    )

    def parse_output(self, raw: Any) -> list[dict[str, Any]]:
        """Parse PyRIT output into normalized findings.

        Args:
            raw: Raw PyRIT output

        Returns:
            List of normalized findings
        """
        findings: list[dict[str, Any]] = []

        if isinstance(raw, dict):
            # JSON output
            results = raw.get("results", [])
            for result in results:
                finding = self._create_finding(result)
                if finding:
                    findings.append(finding)
        elif isinstance(raw, str):
            # Text output
            findings = self._parse_stdout(raw)

        return findings

    def _parse_stdout(self, stdout: str) -> list[dict[str, Any]]:
        """Parse PyRIT stdout for findings.

        Args:
            stdout: Standard output

        Returns:
            List of findings
        """
        findings: list[dict[str, Any]] = []
        lines = stdout.split("\n")

        for line in lines:
            if "VULNERABILITY" in line or "RISK" in line or "ATTACK" in line:
                # Extract attack info
                parts = line.split(":")
                if len(parts) >= 2:
                    attack_type = parts[0].strip()
                    details = ":".join(parts[1:]).strip()

                    finding = {
                        "id": f"pyrit_{attack_type}",
                        "source": self.tool_name,
                        "category": normalize_category(attack_type),
                        "severity": normalize_severity(attack_type),
                        "attack_vector": attack_type,
                        "payload": details,
                        "response": "",
                        "success": True,
                        "evidence": {"stdout_line": line},
                        "remediation": normalize_remediation(attack_type),
                    }
                    findings.append(finding)

        return findings

    def _create_finding(self, result: dict[str, Any]) -> dict[str, Any] | None:
        """Create finding from result dict.

        Args:
            result: Result dictionary

        Returns:
            Finding dict or None
        """
        if not result.get("success", False):
            return None

        attack_type = result.get("attack_type", result.get("strategy", "unknown"))
        severity = result.get("severity", "high")
        return {
            "id": f"pyrit_{result.get('id', 'unknown')}",
            "source": self.tool_name,
            "category": normalize_category(attack_type),
            "severity": (
                severity
                if severity in ["critical", "high", "medium", "low"]
                else normalize_severity(attack_type)
            ),
            "attack_vector": attack_type,
            "payload": result.get("prompt", result.get("input", "")),
            "response": result.get("response", result.get("output", "")),
            "success": True,
            "evidence": result,
            "remediation": normalize_remediation(attack_type),
        }
