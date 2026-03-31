"""OpenAI adapter with retry, backoff, timeouts, and cost tracking."""

from __future__ import annotations

import json
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


class OpenAIAdapter:
    """OpenAI API adapter with robust error handling."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gpt-4",
        timeout: int = 30,
        max_retries: int = 3,
        rpm_limit: int = 60,
        proxy: str | None = None,
        insecure: bool = False,
    ) -> None:
        """Initialize OpenAI adapter.

        Args:
            api_key: OpenAI API key (defaults to OPENAI_API_KEY env var)
            model: Model name (gpt-4, gpt-3.5-turbo, etc.)
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
            rpm_limit: Requests per minute limit (default: 60)
            proxy: HTTP/SOCKS5 proxy URL (e.g., http://127.0.0.1:8080)
            insecure: Disable TLS verification (only use for local MITM proxies)
        """
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise ValueError(
                "OpenAI API key not found. Set OPENAI_API_KEY environment variable.\n"
                "Example: export OPENAI_API_KEY=sk-...\n"
                "Or use --adapter mock for testing without API keys."
            )

        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries
        self.proxy = proxy or os.getenv("HTTPS_PROXY") or os.getenv("HTTP_PROXY")
        self.insecure = insecure
        self.rate_limiter = RateLimiter(rpm=rpm_limit)

        # Try to import openai
        try:
            import openai

            # Route through proxy if configured (for Burp Suite, mitmproxy, etc.)
            http_client = None
            if self.proxy:
                try:
                    import httpx
                    verify_tls = not self.insecure
                    http_client = httpx.Client(proxy=self.proxy, verify=verify_tls)
                except ImportError:
                    pass  # httpx not available, proxy won't work

            self.client = openai.OpenAI(
                api_key=self.api_key,
                timeout=self.timeout,
                http_client=http_client,
            )
        except ImportError as e:
            msg = "OpenAI SDK not installed. Install with: pip install openai"
            raise ImportError(msg) from e

    @retry(
        retry=retry_if_exception_type((Exception,)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=4),
    )
    def invoke(self, prompt: str, **kwargs: Any) -> ModelResponse:  # noqa: ANN401
        """Invoke OpenAI model with prompt.

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
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                **kwargs,
            )

            latency_ms = (time.time() - start_time) * 1000

            # Extract response
            text = response.choices[0].message.content or ""

            # Extract tool_calls if present
            tool_calls = None
            message = response.choices[0].message
            if hasattr(message, "tool_calls") and message.tool_calls:
                tool_calls = [
                    {
                        "id": tc.id,
                        "name": tc.function.name,
                        "arguments": (
                            json.loads(tc.function.arguments) if tc.function.arguments else {}
                        ),
                    }
                    for tc in message.tool_calls
                ]

            # Calculate cost (approximate)
            cost = self._calculate_cost(
                response.usage.prompt_tokens if response.usage else 0,
                response.usage.completion_tokens if response.usage else 0,
            )

            return ModelResponse(
                text=text,
                tool_calls=tool_calls,
                meta={
                    "model": self.model,
                    "latency_ms": latency_ms,
                    "tokens_prompt": response.usage.prompt_tokens if response.usage else 0,
                    "tokens_completion": response.usage.completion_tokens if response.usage else 0,
                    "cost_usd": cost,
                    "finish_reason": response.choices[0].finish_reason,
                },
            )

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            raise RuntimeError(f"OpenAI API error: {e}") from e

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

    def _calculate_cost(self, prompt_tokens: int, completion_tokens: int) -> float:
        """Calculate approximate cost in USD.

        Args:
            prompt_tokens: Prompt tokens
            completion_tokens: Completion tokens

        Returns:
            Cost in USD
        """
        # Pricing as of 2025-11-13 (approximate)
        pricing = {
            "gpt-4": {"prompt": 0.03 / 1000, "completion": 0.06 / 1000},
            "gpt-4-turbo": {"prompt": 0.01 / 1000, "completion": 0.03 / 1000},
            "gpt-3.5-turbo": {"prompt": 0.0015 / 1000, "completion": 0.002 / 1000},
        }

        model_key = self.model
        if model_key not in pricing:
            model_key = "gpt-3.5-turbo"  # Default

        cost = (
            prompt_tokens * pricing[model_key]["prompt"]
            + completion_tokens * pricing[model_key]["completion"]
        )

        return cost
