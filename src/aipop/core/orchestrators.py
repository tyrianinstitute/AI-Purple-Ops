"""Orchestrator protocol for conversation state management."""

from __future__ import annotations

from typing import Any, Protocol

from aipop.core.adapters import Adapter
from aipop.core.models import ModelResponse, TestCase


class Orchestrator(Protocol):
    """Protocol for orchestrating test execution with conversation state management.

    Orchestrators control how prompts are sent to models, managing multi-turn
    conversations, context injection, and attack strategy coordination.

    Configuration Hierarchy:
    1. Test case metadata (highest priority)
    2. Orchestrator instance config
    3. Default config file
    """

    def execute_prompt(
        self,
        prompt: str,
        test_case: TestCase,
        adapter: Adapter,
        config_override: dict[str, Any] | None = None,
    ) -> ModelResponse:
        """Execute a single prompt through the adapter with orchestration logic.

        Args:
            prompt: The prompt text to send
            test_case: Original test case (for metadata/context)
            adapter: Model adapter to invoke
            config_override: Per-call config override (from test metadata)

        Returns:
            ModelResponse from the adapter with orchestration metadata
        """
        ...

    def reset_state(self) -> None:
        """Reset conversation state between test cases."""
        ...

    def get_debug_info(self) -> dict[str, Any]:
        """Return current orchestrator state for debugging.

        Returns:
            Dictionary with state, config, and execution history
        """
        ...
