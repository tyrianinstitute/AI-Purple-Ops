"""External tool invocation — detect, invoke, and capture output from
PyRIT, Promptfoo, Garak, and other security tools.

Subprocess-level integration. Not the full engine router (S3a) —
just "run the tool and show me what happened."
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


@dataclass
class ToolInfo:
    """Information about an installed external tool."""

    name: str
    installed: bool
    path: str | None = None
    version: str | None = None
    install_hint: str = ""


@dataclass
class ToolRunResult:
    """Result of invoking an external tool."""

    tool: str
    command: list[str]
    exit_code: int
    stdout: str
    stderr: str
    elapsed_secs: float
    output_path: str | None = None


# Tool registry — how to detect and invoke each tool
TOOL_REGISTRY = {
    "pyrit": {
        "detect": ["python", "-c", "import pyrit; print(pyrit.__version__)"],
        "install_hint": "pip install pyrit",
        "description": "Microsoft multi-turn agentic red teaming",
    },
    "promptfoo": {
        "detect": ["npx", "promptfoo", "--version"],
        "detect_alt": ["promptfoo", "--version"],
        "install_hint": "npm install -g promptfoo",
        "description": "LLM eval and red teaming framework (133+ plugins)",
    },
    "garak": {
        "detect": ["python", "-c", "import garak; print(garak.__version__)"],
        "detect_alt": ["garak", "--version"],
        "install_hint": "pip install garak",
        "description": "LLM vulnerability scanner with 100+ probes",
    },
}


def detect_tools() -> list[ToolInfo]:
    """Detect which external security tools are installed."""
    results = []

    for name, config in TOOL_REGISTRY.items():
        info = ToolInfo(
            name=name,
            installed=False,
            install_hint=config["install_hint"],
        )

        # Try primary detection
        for detect_cmd in [config["detect"]] + ([config["detect_alt"]] if "detect_alt" in config else []):
            try:
                result = subprocess.run(
                    detect_cmd,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    info.installed = True
                    info.version = result.stdout.strip().split("\n")[0][:50]
                    info.path = shutil.which(detect_cmd[0]) or detect_cmd[0]
                    break
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue

        results.append(info)

    return results


def invoke_tool(
    tool_name: str,
    args: list[str],
    capture_dir: Path | None = None,
) -> ToolRunResult:
    """Invoke an external tool via subprocess and capture output.

    Args:
        tool_name: Tool name (pyrit, promptfoo, garak)
        args: Additional arguments to pass
        capture_dir: Directory to save output (default: out/tool_runs/)

    Returns:
        ToolRunResult with stdout, stderr, exit code, timing
    """
    if tool_name not in TOOL_REGISTRY:
        available = ", ".join(TOOL_REGISTRY.keys())
        raise ValueError(
            f"Unknown tool: {tool_name}. Available: {available}"
        )

    # Build the command
    if tool_name == "promptfoo":
        cmd = ["npx", "promptfoo"] + args
    elif tool_name == "garak":
        cmd = ["python", "-m", "garak"] + args
    elif tool_name == "pyrit":
        cmd = ["python", "-m", "pyrit"] + args
    else:
        cmd = [tool_name] + args

    # Execute
    start = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )
        elapsed = time.time() - start

        run_result = ToolRunResult(
            tool=tool_name,
            command=cmd,
            exit_code=result.returncode,
            stdout=result.stdout,
            stderr=result.stderr,
            elapsed_secs=elapsed,
        )

    except FileNotFoundError:
        config = TOOL_REGISTRY[tool_name]
        raise RuntimeError(
            f"{tool_name} not found. Install with: {config['install_hint']}"
        ) from None
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        run_result = ToolRunResult(
            tool=tool_name,
            command=cmd,
            exit_code=-1,
            stdout="",
            stderr="Timeout after 300 seconds",
            elapsed_secs=elapsed,
        )

    # Save output
    if capture_dir is None:
        capture_dir = Path("out/tool_runs")
    capture_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
    output_path = capture_dir / f"{tool_name}_{ts}.json"
    output_path.write_text(
        json.dumps(
            {
                "tool": run_result.tool,
                "command": run_result.command,
                "exit_code": run_result.exit_code,
                "stdout": run_result.stdout[:50000],  # cap at 50KB
                "stderr": run_result.stderr[:10000],
                "elapsed_secs": run_result.elapsed_secs,
                "timestamp": ts,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    run_result.output_path = str(output_path)

    return run_result
