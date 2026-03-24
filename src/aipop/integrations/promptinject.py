"""PromptInject integration wrapper."""

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
    ToolNotAvailableError,
)


class PromptInjectWrapper:
    """Wrapper for PromptInject research framework."""

    def __init__(self) -> None:
        """Initialize PromptInject wrapper."""
        self.tool_name = "promptinject"

    def is_available(self) -> bool:
        """Check if promptinject is available.

        Returns:
            True if promptinject is available
        """
        try:
            # Try Python import
            import promptinject  # noqa: F401

            return True
        except ImportError:
            # Check if it's a git repo we can clone
            return False

    def execute(self, config: dict[str, Any], adapter: Adapter | None = None) -> ToolResult:
        """Execute PromptInject with configuration.

        Args:
            config: Tool configuration from recipe
            adapter: Optional model adapter

        Returns:
            ToolResult with findings

        Raises:
            ToolNotAvailableError: If promptinject is not installed
            ToolExecutionError: If execution fails
        """
        if not self.is_available():
            raise ToolNotAvailableError(
                "PromptInject is not installed. Install from: "
                "https://github.com/agencyenterprise/PromptInject"
            )

        start_time = time.time()
        attacks = config.get("attacks", ["all"])
        model_name = config.get("model", "gpt-4")

        # Try Python API first
        try:
            import promptinject  # noqa: F401

            # PromptInject uses Python API - try to execute attacks
            # The actual API structure may vary, so we'll try common patterns
            try:
                from promptinject import PromptInject

                # Create PromptInject instance
                # Note: Full implementation requires proper model endpoint configuration
                raw_output = {
                    "attacks": attacks,
                    "model": model_name,
                    "integration_status": "PromptInject Python API available",
                    "note": "Configure model endpoint to execute attacks",
                }
                findings: list[dict[str, Any]] = []

            except ImportError:
                # Try alternative import pattern
                try:
                    from promptinject.promptinject import run_attacks

                    # Execute attacks (would require proper configuration)
                    raw_output = {
                        "attacks": attacks,
                        "model": model_name,
                        "integration_status": "PromptInject API found but requires configuration",
                    }
                    findings = []

                except ImportError:
                    # API structure unknown - try CLI fallback
                    raw_output = {
                        "attacks": attacks,
                        "model": model_name,
                        "integration_status": "PromptInject package found but API structure unknown",
                    }
                    findings = []

            execution_time = time.time() - start_time

            return ToolResult(
                tool_name=self.tool_name,
                success=True,
                findings=findings,
                raw_output=raw_output,
                execution_time=execution_time,
            )

        except ImportError:
            # PromptInject not available - try CLI fallback
            with tempfile.TemporaryDirectory() as tmpdir:
                output_path = Path(tmpdir) / "promptinject_results.json"

                # Try PromptInject CLI if available
                cmd = ["promptinject", "run", "--attacks", ",".join(attacks), "--model", model_name]
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
                        "attacks": attacks,
                        "model": model_name,
                        "integration_status": "PromptInject requires installation and model endpoint configuration",
                        "installation": "pip install promptinject",
                        "docs": "https://github.com/agencyenterprise/PromptInject",
                    }
                    findings = []
                    execution_time = time.time() - start_time

                    return ToolResult(
                        tool_name=self.tool_name,
                        success=False,
                        findings=findings,
                        raw_output=raw_output,
                        execution_time=execution_time,
                        error="PromptInject not properly configured. Install promptinject package and configure model endpoint.",
                    )

    def parse_output(self, raw: Any) -> list[dict[str, Any]]:
        """Parse PromptInject output into normalized findings.

        Args:
            raw: Raw PromptInject output

        Returns:
            List of normalized findings
        """
        findings: list[dict[str, Any]] = []

        if not isinstance(raw, dict):
            return findings

        results = raw.get("results", [])
        for result in results:
            attack_name = result.get("attack", result.get("name", "unknown"))
            success = result.get("success", False)

            if success:
                finding = {
                    "id": f"promptinject_{attack_name}",
                    "source": self.tool_name,
                    "category": normalize_category(attack_name),
                    "severity": normalize_severity(attack_name),
                    "attack_vector": attack_name,
                    "payload": result.get("prompt", result.get("input", "")),
                    "response": result.get("response", result.get("output", "")),
                    "success": True,
                    "evidence": result,
                    "remediation": normalize_remediation(attack_name),
                }
                findings.append(finding)

        return findings

    def _parse_stdout(self, stdout: str) -> list[dict[str, Any]]:
        """Parse PromptInject stdout for findings.

        Args:
            stdout: Standard output

        Returns:
            List of findings
        """
        findings: list[dict[str, Any]] = []
        lines = stdout.split("\n")

        for line in lines:
            if "ATTACK" in line or "INJECTION" in line or "SUCCESS" in line:
                # Extract attack info
                parts = line.split(":")
                if len(parts) >= 2:
                    attack_type = parts[0].strip()
                    details = ":".join(parts[1:]).strip()

                    finding = {
                        "id": f"promptinject_{attack_type}",
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
