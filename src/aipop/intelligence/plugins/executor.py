"""Subprocess execution engine for attack plugins.

Executes attack plugins in isolated Python subprocesses with dedicated
virtual environments to prevent dependency conflicts.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from aipop.intelligence.plugins.base import AttackResult

logger = logging.getLogger(__name__)


class SubprocessAttackExecutor:
    """Executes attacks in isolated Python subprocess with dedicated venv.

    This executor handles:
    - Dependency isolation (each plugin has its own venv)
    - Progress streaming via stderr
    - Error handling and timeouts
    - Cost tracking across subprocess boundary
    """

    def __init__(
        self,
        plugin_name: str,
        venv_path: Path,
        timeout: int | None = None,
    ) -> None:
        """Initialize subprocess executor.

        Args:
            plugin_name: Name of the plugin (gcg, pair, autodan)
            venv_path: Path to plugin's virtual environment
            timeout: Maximum execution time in seconds (None = no timeout)
        """
        self.plugin_name = plugin_name
        self.venv_path = Path(venv_path)
        self.timeout = timeout

        # Determine Python executable path based on OS
        if sys.platform == "win32":
            self.python_exe = self.venv_path / "Scripts" / "python.exe"
        else:
            self.python_exe = self.venv_path / "bin" / "python"

    def execute(
        self,
        config: dict[str, Any],
        progress_callback: callable | None = None,
    ) -> AttackResult:
        """Run attack in subprocess and return results.

        Args:
            config: Attack configuration dictionary
            progress_callback: Optional callback for progress updates (called with str)

        Returns:
            AttackResult from the plugin execution

        Raises:
            subprocess.TimeoutExpired: If execution exceeds timeout
            subprocess.CalledProcessError: If plugin execution fails
            ValueError: If result cannot be parsed
        """
        # Check that Python executable exists
        if not self.python_exe.exists():
            raise FileNotFoundError(
                f"Python executable not found at {self.python_exe}. "
                f"Plugin {self.plugin_name} may not be installed correctly."
            )

        # Write config to temporary file
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as config_file:
            json.dump(config, config_file)
            config_path = Path(config_file.name)

        try:
            # Build command to run plugin runner
            cmd = [
                str(self.python_exe),
                "-m",
                f"aipop.intelligence.plugins.runners.{self.plugin_name}",
                "--config",
                str(config_path),
            ]

            logger.info(f"Executing {self.plugin_name} plugin: {' '.join(cmd)}")

            # Execute subprocess
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # Line buffered
            )

            # Stream stderr for progress updates
            stderr_lines = []
            if process.stderr:
                for line in process.stderr:
                    stderr_lines.append(line.rstrip())
                    if progress_callback:
                        progress_callback(line.rstrip())
                    else:
                        logger.debug(f"[{self.plugin_name}] {line.rstrip()}")

            # Wait for completion
            stdout, _ = process.communicate(timeout=self.timeout)

            # Check return code
            if process.returncode != 0:
                error_msg = "\n".join(stderr_lines)
                raise subprocess.CalledProcessError(
                    process.returncode,
                    cmd,
                    output=stdout,
                    stderr=error_msg,
                )

            # Parse JSON result from stdout
            try:
                result_data = json.loads(stdout)
                return self._parse_result(result_data)
            except json.JSONDecodeError as e:
                raise ValueError(
                    f"Failed to parse plugin output as JSON: {e}\n" f"Output: {stdout[:500]}"
                ) from e

        finally:
            # Clean up temp config file
            try:
                config_path.unlink()
            except Exception as e:
                logger.warning(f"Failed to delete temp config: {e}")

    def _parse_result(self, data: dict[str, Any]) -> AttackResult:
        """Parse result dictionary into AttackResult object.

        Args:
            data: Dictionary from plugin's JSON output

        Returns:
            AttackResult instance
        """
        return AttackResult(
            success=data.get("success", False),
            adversarial_prompts=data.get("adversarial_prompts", []),
            scores=data.get("scores", []),
            metadata=data.get("metadata", {}),
            cost=data.get("cost", 0.0),
            num_queries=data.get("num_queries", 0),
            execution_time=data.get("execution_time", 0.0),
            error=data.get("error"),
        )

    def check_available(self) -> tuple[bool, str]:
        """Check if subprocess executor is properly configured.

        Returns:
            Tuple of (is_available, error_message)
        """
        if not self.venv_path.exists():
            return False, f"Virtual environment not found: {self.venv_path}"

        if not self.python_exe.exists():
            return False, f"Python executable not found: {self.python_exe}"

        return True, ""


class DirectImportExecutor:
    """Executes attacks by directly importing plugin class.

    Faster than subprocess execution but shares dependencies with main process.
    Use only when dependency isolation is not required.
    """

    def __init__(self, plugin_instance: Any) -> None:
        """Initialize direct import executor.

        Args:
            plugin_instance: Instance of AttackPlugin subclass
        """
        self.plugin = plugin_instance

    def execute(
        self,
        config: dict[str, Any],
        progress_callback: callable | None = None,
    ) -> AttackResult:
        """Run attack by calling plugin.run() directly.

        Args:
            config: Attack configuration dictionary
            progress_callback: Optional callback (ignored for direct execution)

        Returns:
            AttackResult from the plugin execution
        """
        # Direct execution - no subprocess
        return self.plugin.run(config)

    def check_available(self) -> tuple[bool, str]:
        """Check if plugin is available for direct import.

        Returns:
            Tuple of (is_available, error_message)
        """
        return self.plugin.check_available()
