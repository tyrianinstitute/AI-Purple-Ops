"""AWS Bedrock adapter with STS auth and retry logic."""

from __future__ import annotations

import os
import time
from typing import Any

from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from aipop.core.models import ModelResponse


class BedrockAdapter:
    """AWS Bedrock adapter with STS credentials."""

    def __init__(
        self,
        region: str | None = None,
        model: str = "anthropic.claude-v2",
        timeout: int = 30,
        max_retries: int = 3,
    ) -> None:
        """Initialize Bedrock adapter.

        Args:
            region: AWS region (defaults to AWS_REGION env var or us-east-1)
            model: Model ID (anthropic.claude-v2, etc.)
            timeout: Request timeout in seconds
            max_retries: Maximum retry attempts
        """
        self.region = region or os.getenv("AWS_REGION", "us-east-1")
        self.model = model
        self.timeout = timeout
        self.max_retries = max_retries

        try:
            import boto3

            self.client = boto3.client("bedrock-runtime", region_name=self.region)
        except ImportError:
            raise ImportError("boto3 not installed. Install with: pip install boto3")
        except Exception as e:
            # Check for common credential issues
            error_msg = str(e).lower()
            if "credentials" in error_msg or "access" in error_msg:
                raise RuntimeError(
                    f"AWS credentials not found or invalid.\n"
                    f"Set AWS_REGION, AWS_ACCESS_KEY_ID, and AWS_SECRET_ACCESS_KEY environment variables.\n"
                    f"Or use AWS CLI: aws configure\n"
                    f"Or use --adapter mock for testing without API keys.\n"
                    f"Original error: {e}"
                ) from e
            raise RuntimeError(
                f"Failed to initialize Bedrock client: {e}\n"
                f"Check AWS credentials and region settings.\n"
                f"Or use --adapter mock for testing without API keys."
            ) from e

    @retry(
        retry=retry_if_exception_type((Exception,)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=4),
    )
    def invoke(self, prompt: str, **kwargs: Any) -> ModelResponse:
        """Invoke Bedrock model with prompt.

        Args:
            prompt: Input prompt
            **kwargs: Additional parameters

        Returns:
            ModelResponse with text and metadata
        """
        start_time = time.time()

        try:
            # Format request based on model
            if "anthropic.claude" in self.model:
                body = {
                    "prompt": f"\n\nHuman: {prompt}\n\nAssistant:",
                    "max_tokens_to_sample": kwargs.get("max_tokens", 1024),
                    "temperature": kwargs.get("temperature", 0.7),
                }

                response = self.client.invoke_model(
                    modelId=self.model,
                    body=bytes(str(body).replace("'", '"'), "utf-8"),
                )

                import json

                response_body = json.loads(response["body"].read())
                text = response_body.get("completion", "")

            else:
                # Generic format for other models
                body = {"inputText": prompt, **kwargs}

                response = self.client.invoke_model(
                    modelId=self.model,
                    body=bytes(str(body).replace("'", '"'), "utf-8"),
                )

                import json

                response_body = json.loads(response["body"].read())
                text = response_body.get("results", [{}])[0].get("outputText", "")

            latency_ms = (time.time() - start_time) * 1000

            # Estimate cost (Bedrock pricing varies)
            cost = self._estimate_cost(len(prompt), len(text))

            return ModelResponse(
                text=text,
                meta={
                    "model": self.model,
                    "latency_ms": latency_ms,
                    "tokens_prompt": len(prompt) // 4,  # Rough estimate
                    "tokens_completion": len(text) // 4,
                    "cost_usd": cost,
                    "finish_reason": "stop",
                },
            )

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            raise RuntimeError(f"Bedrock API error: {e}") from e

    def _estimate_cost(self, prompt_chars: int, completion_chars: int) -> float:
        """Estimate cost in USD (rough approximation).

        Args:
            prompt_chars: Prompt character count
            completion_chars: Completion character count

        Returns:
            Estimated cost in USD
        """
        # Rough estimate: ~4 chars per token, pricing varies by model
        prompt_tokens = prompt_chars // 4
        completion_tokens = completion_chars // 4

        # Claude v2 pricing (approximate)
        cost = (prompt_tokens * 0.008 / 1000) + (completion_tokens * 0.024 / 1000)

        return cost
