"""Adapter protocol for model I/O abstraction."""

from __future__ import annotations

from typing import Any, Protocol

from .models import ModelResponse


class Adapter(Protocol):
    """Model I/O abstraction (device driver analogy)."""

    def invoke(self, prompt: str, **kwargs: Any) -> ModelResponse:  # noqa: ANN401
        """Invoke the model with a prompt and return response with metadata.

        Returns ModelResponse containing text and meta dict for tokens, cost,
        latency, finish_reason, etc. This prevents signature changes when
        detectors/evaluators need additional metadata.
        """
        ...

    def batch_query(self, prompts: list[str], **kwargs: Any) -> list[ModelResponse]:  # noqa: ANN401
        """Execute batch of prompts in parallel (default: sequential fallback).

        Args:
            prompts: List of prompts to execute
            **kwargs: Additional arguments passed to invoke()

        Returns:
            List of ModelResponse objects in same order as prompts

        Note:
            Default implementation executes sequentially. Adapters should override
            for parallel execution when supported by the API.
        """
        return [self.invoke(p, **kwargs) for p in prompts]

    # TODO(b05): Add streaming support
    # TODO(b07): Add tool call support for agent testing
