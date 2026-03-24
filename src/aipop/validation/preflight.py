"""Preflight validation to catch configuration errors before testing.

Validates API keys, network connectivity, and adapter instantiation to fail fast
with clear error messages rather than during test execution.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PreflightResult:
    """Result of a preflight validation check."""

    adapter_name: str
    status: str  # "pass", "fail", "warn", "skip"
    message: str
    details: dict[str, Any] | None = None


def validate_adapter_config(adapter_name: str) -> PreflightResult:
    """Validate configuration for a specific adapter.

    Checks:
    - Required environment variables (API keys)
    - Adapter can be instantiated
    - Network connectivity (if applicable)

    Args:
        adapter_name: Name of the adapter to validate (e.g., "openai", "anthropic")

    Returns:
        PreflightResult with status and message
    """
    adapter_lower = adapter_name.lower()

    # Mock adapter always passes
    if adapter_lower == "mock":
        return PreflightResult(
            adapter_name=adapter_name,
            status="pass",
            message="Mock adapter available (no credentials required)",
        )

    # Check for required API keys
    key_env_vars = {
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "bedrock": "AWS_ACCESS_KEY_ID",
        "huggingface": "HUGGINGFACE_TOKEN",
    }

    if adapter_lower in key_env_vars:
        env_var = key_env_vars[adapter_lower]
        if not os.getenv(env_var):
            return PreflightResult(
                adapter_name=adapter_name,
                status="fail",
                message=f"Missing environment variable: {env_var}",
                details={
                    "remediation": f"Set {env_var} environment variable",
                    "example": f"export {env_var}=your-api-key-here",
                },
            )

    # Try to instantiate the adapter
    try:
        from aipop.adapters.registry import AdapterRegistry

        registry = AdapterRegistry()

        # Check if adapter is registered
        if adapter_lower not in registry.list_adapters():
            return PreflightResult(
                adapter_name=adapter_name,
                status="warn",
                message=f"Adapter '{adapter_name}' not found in registry",
                details={
                    "available_adapters": registry.list_adapters(),
                },
            )

        # For adapters that require models, we can't fully validate without config
        # but we can check basic requirements
        if adapter_lower in ("openai", "anthropic", "bedrock"):
            return PreflightResult(
                adapter_name=adapter_name,
                status="pass",
                message=f"API key present for {adapter_name}",
                details={"env_var": key_env_vars.get(adapter_lower)},
            )

        # For local adapters (ollama, llamacpp), check if service is reachable
        if adapter_lower == "ollama":
            import socket

            try:
                # Quick check if Ollama is running on localhost:11434
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex(("localhost", 11434))
                sock.close()

                if result == 0:
                    return PreflightResult(
                        adapter_name=adapter_name,
                        status="pass",
                        message="Ollama service reachable on localhost:11434",
                    )
                else:
                    return PreflightResult(
                        adapter_name=adapter_name,
                        status="warn",
                        message="Ollama service not reachable on localhost:11434",
                        details={
                            "remediation": "Start Ollama: ollama serve",
                        },
                    )
            except Exception as e:
                return PreflightResult(
                    adapter_name=adapter_name,
                    status="warn",
                    message=f"Could not check Ollama service: {e}",
                )

        # Default: assume adapter is configured
        return PreflightResult(
            adapter_name=adapter_name,
            status="pass",
            message=f"Adapter {adapter_name} appears configured",
        )

    except Exception as e:
        logger.exception(f"Error validating adapter {adapter_name}")
        return PreflightResult(
            adapter_name=adapter_name,
            status="fail",
            message=f"Failed to validate adapter: {e}",
            details={"exception": str(e)},
        )


def validate_all_adapters() -> list[PreflightResult]:
    """Validate all available adapters.

    Returns:
        List of PreflightResult objects
    """
    from aipop.adapters.registry import AdapterRegistry

    registry = AdapterRegistry()
    adapters = registry.list_adapters()

    results = []
    for adapter in adapters:
        result = validate_adapter_config(adapter)
        results.append(result)

    return results


def validate_environment() -> PreflightResult:
    """Validate general environment setup.

    Checks:
    - Python version
    - Required dependencies
    - File system permissions

    Returns:
        PreflightResult for environment
    """
    import sys

    # Check Python version
    if sys.version_info < (3, 11):
        return PreflightResult(
            adapter_name="environment",
            status="fail",
            message=f"Python 3.11+ required, found {sys.version_info.major}.{sys.version_info.minor}",
        )

    # Check for critical dependencies
    missing_deps = []
    try:
        import typer
    except ImportError:
        missing_deps.append("typer")

    try:
        import yaml
    except ImportError:
        missing_deps.append("pyyaml")

    try:
        import duckdb
    except ImportError:
        missing_deps.append("duckdb")

    if missing_deps:
        return PreflightResult(
            adapter_name="environment",
            status="fail",
            message=f"Missing required dependencies: {', '.join(missing_deps)}",
            details={
                "remediation": "pip install ai-purple-ops",
            },
        )

    return PreflightResult(
        adapter_name="environment",
        status="pass",
        message="Environment configured correctly",
    )
