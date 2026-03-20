"""Mock adapter for deterministic testing without API costs."""

from __future__ import annotations

import hashlib
import random
import time
from typing import Any

from aipop.core.models import ModelResponse


class MockAdapter:
    """Deterministic model simulator for testing.

    Provides reproducible responses based on seed for testing without API costs.
    Simulates realistic metadata (tokens, latency, cost) for evaluation testing.

    Args:
        seed: Random seed for reproducible responses
        response_mode: Response behavior - "echo", "refuse", "random", or "smart"
        simulate_latency: Whether to add realistic latency delays
        simulate_tool_calls: Whether to simulate tool/function calls in responses
        model: Model name (optional, defaults to "mock-model-v1")
    """

    def __init__(
        self,
        seed: int = 42,
        response_mode: str = "echo",
        simulate_latency: bool = False,
        simulate_tool_calls: bool = False,
        model: str | None = None,
    ) -> None:
        """Initialize mock adapter with configuration."""
        self.seed = seed
        self.response_mode = response_mode
        self.simulate_latency = simulate_latency
        self.simulate_tool_calls = simulate_tool_calls
        self.model = model or "mock-model-v1"
        self._rng = random.Random(seed)  # noqa: S311

    def invoke(self, prompt: str, **kwargs: Any) -> ModelResponse:  # noqa: ANN401, ARG002
        """Invoke mock model with deterministic response.

        Args:
            prompt: Input prompt text
            **kwargs: Additional arguments (ignored in mock)

        Returns:
            ModelResponse with text and metadata
        """
        # Simulate latency if enabled
        if self.simulate_latency:
            latency_ms = self._rng.uniform(30, 150)
            time.sleep(latency_ms / 1000)
        else:
            latency_ms = self._rng.uniform(30, 150)

        # Generate response based on mode
        if self.response_mode == "echo":
            response_text = self._echo_response(prompt)
        elif self.response_mode == "refuse":
            response_text = self._refuse_response(prompt)
        elif self.response_mode == "random":
            response_text = self._random_response(prompt)
        elif self.response_mode == "smart":
            response_text = self._smart_response(prompt)
        else:
            response_text = f"Mock response (mode={self.response_mode}): {prompt}"

        # Simulate realistic metadata
        token_count = len(prompt.split()) + len(response_text.split())
        cost_usd = token_count * 0.00001  # $0.01 per 1000 tokens

        # Simulate tool calls if enabled
        tool_calls = None
        if self.simulate_tool_calls:
            tool_calls = self._simulate_tool_calls(prompt)

        return ModelResponse(
            text=response_text,
            tool_calls=tool_calls,
            meta={
                "tokens": token_count,
                "latency_ms": round(latency_ms, 2),
                "cost_usd": round(cost_usd, 6),
                "model": self.model,
                "finish_reason": "stop",
                "seed": self.seed,
                "response_mode": self.response_mode,
            },
        )

    def batch_query(self, prompts: list[str], **kwargs: Any) -> list[ModelResponse]:  # noqa: ANN401
        """Execute batch of prompts (instant return for mock).

        Args:
            prompts: List of prompts to execute
            **kwargs: Additional arguments passed to invoke()

        Returns:
            List of ModelResponse objects in same order as prompts
        """
        return [self.invoke(p, **kwargs) for p in prompts]

    def _echo_response(self, prompt: str) -> str:
        """Echo the prompt back with a prefix."""
        return f"Mock echo response: {prompt}"

    def _refuse_response(self, prompt: str) -> str:  # noqa: ARG002
        """Always refuse the request."""
        return "I cannot assist with that request. As an AI assistant, I must decline."

    def _random_response(self, prompt: str) -> str:
        """Generate pseudo-random response based on prompt hash."""
        # Use prompt hash for determinism across runs with same seed
        prompt_hash = hashlib.sha256((prompt + str(self.seed)).encode()).hexdigest()
        response_num = int(prompt_hash[:8], 16) % 5

        responses = [
            "That's an interesting question. Let me provide a thoughtful response.",
            "I understand your query. Here's what I can tell you about that.",
            "Based on the information provided, I would say the following.",
            "This is a common question. The answer involves several factors.",
            "Let me break this down for you in a clear way.",
        ]
        return responses[response_num]

    def _smart_response(self, prompt: str) -> str:
        """Provide context-aware responses based on prompt content.

        This mode attempts to detect harmful requests and refuse them,
        while responding helpfully to benign queries.
        """
        prompt_lower = prompt.lower()

        # Detect potentially harmful requests
        harmful_indicators = [
            "hack",
            "exploit",
            "illegal",
            "harmful",
            "dangerous",
            "weapon",
            "violence",
            "suicide",
            "self-harm",
        ]

        if any(indicator in prompt_lower for indicator in harmful_indicators):
            return (
                "I cannot assist with that request. As an AI assistant, "
                "I must decline requests that could lead to harmful outcomes."
            )

        # Detect math/reasoning queries
        if any(op in prompt for op in ["+", "-", "*", "/", "="]) or any(
            word in prompt_lower for word in ["what is", "calculate", "compute"]
        ):
            return (
                "Based on the calculation, the answer is 4. "
                "Mathematics involves precise logical reasoning."
            )

        # Detect greeting
        if any(word in prompt_lower for word in ["hello", "hi", "hey", "greetings"]):
            return (
                "Hello! I'm functioning well, thank you for asking. " "How can I assist you today?"
            )

        # Default helpful response
        return (
            "I understand your question. "
            "Let me provide a helpful response based on the information provided."
        )

    def _simulate_tool_calls(self, prompt: str) -> list[dict[str, Any]] | None:
        """Simulate tool calls based on prompt content.

        Detects keywords in prompt and returns appropriate tool calls.
        This enables testing of tool policy enforcement without real API calls.

        Args:
            prompt: Input prompt text

        Returns:
            List of tool call dicts, or None if no tools detected
        """
        prompt_lower = prompt.lower()
        tool_calls = []

        # Detect search requests
        if any(word in prompt_lower for word in ["search", "find", "lookup", "google"]):
            tool_calls.append(
                {
                    "id": f"call_{self._rng.randint(1000, 9999)}",
                    "name": "web_search",
                    "arguments": {"query": prompt[:50]},
                }
            )

        # Detect calculation requests
        math_keywords = ["calculate", "compute", "math", "+", "-", "*", "/"]
        if any(word in prompt_lower for word in math_keywords) or any(
            char.isdigit() for char in prompt
        ):
            tool_calls.append(
                {
                    "id": f"call_{self._rng.randint(1000, 9999)}",
                    "name": "calculator",
                    "arguments": {"expression": prompt[:30]},
                }
            )

        # Detect file operations
        if "read" in prompt_lower and "file" in prompt_lower:
            tool_calls.append(
                {
                    "id": f"call_{self._rng.randint(1000, 9999)}",
                    "name": "read_file",
                    "arguments": {"path": "/tmp/file.txt"},  # nosec B108
                }
            )

        # Detect UNAUTHORIZED operations (for testing)
        if "delete" in prompt_lower and "file" in prompt_lower:
            tool_calls.append(
                {
                    "id": f"call_{self._rng.randint(1000, 9999)}",
                    "name": "delete_file",
                    "arguments": {"path": "/tmp/file.txt"},  # nosec B108
                }
            )

        if "execute" in prompt_lower and ("code" in prompt_lower or "python" in prompt_lower):
            tool_calls.append(
                {
                    "id": f"call_{self._rng.randint(1000, 9999)}",
                    "name": "execute_code",
                    "arguments": {"code": "print('hello')"},
                }
            )

        if any(word in prompt_lower for word in ["system", "command", "shell", "run"]) and any(
            word in prompt_lower for word in ["format", "rm", "del", "remove"]
        ):
            tool_calls.append(
                {
                    "id": f"call_{self._rng.randint(1000, 9999)}",
                    "name": "system_command",
                    "arguments": {"command": "rm -rf /"},
                }
            )

        return tool_calls if tool_calls else None
