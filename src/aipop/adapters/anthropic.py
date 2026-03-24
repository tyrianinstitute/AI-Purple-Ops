"""Anthropic Claude adapter with robust error handling."""

from __future__ import annotations

import os
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from aipop.core.models import ModelResponse
from aipop.utils.rate_limiter import RateLimiter


class AnthropicAdapter:
    """Anthropic Claude API adapter."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-3-opus-20240229",
        timeout: int = 30,
        max_retries: int = 3,
        rpm_limit: int = 50,
        proxy: str | None = None,
    ) -> None:
        """Initialize Anthropic adapter.

        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
            model: Model name (claude-3-opus, claude-3-sonnet, etc.)
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
            rpm_limit: Requests per minute limit (default: 50)
            proxy: HTTP/SOCKS5 proxy URL (e.g., http://127.0.0.1:8080)
        """
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise ValueError(
                "Anthropic API key not found. Set ANTHROPIC_API_KEY environment variable.\n"
                "Example: export ANTHROPIC_API_KEY=sk-ant-...\n"
                "Or use --adapter mock for testing without API keys."
            )

        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        self.proxy = proxy or os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY")
        self.rate_limiter = RateLimiter(rpm=rpm_limit)

        try:
            from anthropic import Anthropic

            # Route through proxy if configured
            http_client = None
            if self.proxy:
                try:
                    import httpx
                    http_client = httpx.Client(proxy=self.proxy, verify=False)
                except ImportError:
                    pass

            self.client = Anthropic(
                api_key=self.api_key,
                timeout=self.timeout,
                http_client=http_client,
            )
        except ImportError as e:
            msg = "Anthropic SDK not installed. Install with: pip install anthropic"
            raise ImportError(msg) from e

    @retry(
        retry=retry_if_exception_type((Exception,)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=4),
    )
    def invoke(self, prompt: str, **kwargs: Any) -> ModelResponse:  # noqa: ANN401
        """Invoke Claude model with prompt.

        Args:
            prompt: Input prompt
            **kwargs: Additional parameters (temperature, max_tokens, etc.)

        Returns:
            ModelResponse with text and metadata
        """
        # Rate limit before API call
        self.rate_limiter.acquire()

        start_time = time.time()

        try:
            response = self.client.messages.create(
                model=self.model,
                max_tokens=kwargs.get("max_tokens", 1024),
                messages=[{"role": "user", "content": prompt}],
            )

            latency_ms = (time.time() - start_time) * 1000

            # Extract text content
            text = ""
            tool_calls = None

            if response.content:
                # Extract text from text blocks
                text_blocks = [
                    block.text
                    for block in response.content
                    if hasattr(block, "type") and block.type == "text"
                ]
                text = "".join(text_blocks)

                # Extract tool_use blocks
                tool_blocks = [
                    block
                    for block in response.content
                    if hasattr(block, "type") and block.type == "tool_use"
                ]
                if tool_blocks:
                    tool_calls = [
                        {
                            "id": block.id,
                            "name": block.name,
                            "arguments": block.input if hasattr(block, "input") else {},
                        }
                        for block in tool_blocks
                    ]

            # Calculate cost (approximate)
            cost = self._calculate_cost(
                response.usage.input_tokens,
                response.usage.output_tokens,
            )

            return ModelResponse(
                text=text,
                tool_calls=tool_calls,
                meta={
                    "model": self.model,
                    "latency_ms": latency_ms,
                    "tokens_prompt": response.usage.input_tokens,
                    "tokens_completion": response.usage.output_tokens,
                    "cost_usd": cost,
                    "finish_reason": response.stop_reason,
                },
            )

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            raise RuntimeError(f"Anthropic API error: {e}") from e

    def batch_query(self, prompts: list[str], **kwargs: Any) -> list[ModelResponse]:  # noqa: ANN401
        """Execute batch of prompts in parallel using ThreadPoolExecutor.

        Args:
            prompts: List of prompts to execute
            **kwargs: Additional parameters passed to invoke()

        Returns:
            List of ModelResponse objects in same order as prompts
        """
        # Use ThreadPoolExecutor for parallel execution
        # Limit to 10 concurrent requests to avoid overwhelming the API
        max_workers = min(10, len(prompts))

        results = [None] * len(prompts)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all tasks
            future_to_index = {
                executor.submit(self.invoke, prompt, **kwargs): i
                for i, prompt in enumerate(prompts)
            }

            # Collect results as they complete
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                try:
                    results[index] = future.result()
                except Exception as e:
                    # Create error response for failed requests
                    results[index] = ModelResponse(
                        text="",
                        meta={
                            "error": str(e),
                            "model": self.model,
                            "latency_ms": 0,
                            "cost_usd": 0,
                        },
                    )

        return results

    def _calculate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Calculate approximate cost in USD.

        Args:
            input_tokens: Input tokens
            output_tokens: Output tokens

        Returns:
            Cost in USD
        """
        # Pricing as of 2025-11-13 (approximate)
        pricing = {
            "claude-3-opus": {"input": 0.015 / 1000, "output": 0.075 / 1000},
            "claude-3-sonnet": {"input": 0.003 / 1000, "output": 0.015 / 1000},
            "claude-3-haiku": {"input": 0.00025 / 1000, "output": 0.00125 / 1000},
        }

        model_parts = self.model.split("-")[0:3]  # Extract parts: ["claude", "3", "opus"]
        model_key = "-".join(model_parts)  # Join to "claude-3-opus"
        if model_key not in pricing:
            model_key = "claude-3-sonnet"  # Default

        cost = (
            input_tokens * pricing[model_key]["input"]
            + output_tokens * pricing[model_key]["output"]
        )

        return cost
