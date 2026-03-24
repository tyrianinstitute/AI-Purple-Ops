"""Ollama adapter for local LLM testing."""

from __future__ import annotations

import os
import time
from typing import Any

import requests

from aipop.core.models import ModelResponse


def _check_ollama_connection(base_url: str) -> tuple[bool, list[str]]:
    """Check if Ollama is reachable and list available models."""
    try:
        resp = requests.get(f"{base_url}/api/tags", timeout=5)
        resp.raise_for_status()
        data = resp.json()
        models = [m.get("name", m.get("model", "")) for m in data.get("models", [])]
        return True, models
    except Exception:
        return False, []


class OllamaAdapter:
    """Adapter for local Ollama models.

    Runs models locally via Ollama API - no cloud, no API keys, no costs.
    Perfect for testing without exploding your PC.

    Respects OLLAMA_HOST env var for base URL (same as Ollama CLI).
    Point this at any Ollama-compatible API — including lab targets
    that expose /api/generate and /api/tags endpoints.

    Args:
        model: Model name (e.g., "tinyllama", "phi3:mini", "gemma:2b")
        base_url: Ollama API base URL (default: OLLAMA_HOST or http://localhost:11434)
        timeout: Request timeout in seconds
    """

    def __init__(
        self,
        model: str = "tinyllama",
        base_url: str | None = None,
        timeout: int = 120,
        **kwargs: Any,
    ) -> None:
        """Initialize Ollama adapter."""
        self.model = model
        self.base_url = (
            base_url
            or os.environ.get("OLLAMA_HOST")
            or "http://localhost:11434"
        ).rstrip("/")
        self.timeout = timeout

        # Test connection and check if model exists
        connected, available_models = _check_ollama_connection(self.base_url)
        if not connected:
            raise RuntimeError(
                f"Ollama not running at {self.base_url}\n"
                f"Start it with: ollama serve\n"
                f"Or install from: https://ollama.com\n"
                f"Or set OLLAMA_HOST to point at your target"
            )

        if model not in available_models:
            raise RuntimeError(
                f"Model '{model}' not found in Ollama.\n"
                f"Available models: {', '.join(available_models) if available_models else 'none'}\n"
                f"Pull it with: ollama pull {model}"
            )

    def invoke(self, prompt: str, **kwargs: Any) -> ModelResponse:
        """Invoke Ollama model and return response.

        Args:
            prompt: Input prompt text
            **kwargs: Additional arguments (temperature, max_tokens, etc.)

        Returns:
            ModelResponse with text and metadata

        Raises:
            RuntimeError: If Ollama is not running or model not found
        """
        start_time = time.time()

        url = f"{self.base_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,  # Get full response at once
            "options": {
                "temperature": kwargs.get("temperature", 0.7),
                "num_predict": kwargs.get("max_tokens", 512),
            },
        }

        try:
            response = requests.post(url, json=payload, timeout=self.timeout)
            response.raise_for_status()
            data = response.json()

            # Calculate latency
            latency_ms = (time.time() - start_time) * 1000

            # Extract response
            response_text = data.get("response", "")

            # Estimate tokens (rough approximation)
            prompt_tokens = len(prompt.split())
            completion_tokens = len(response_text.split())
            total_tokens = prompt_tokens + completion_tokens

            return ModelResponse(
                text=response_text,
                meta={
                    "model": self.model,
                    "tokens": total_tokens,
                    "tokens_prompt": prompt_tokens,
                    "tokens_completion": completion_tokens,
                    "latency_ms": round(latency_ms, 2),
                    "cost_usd": 0.0,  # Free!
                    "finish_reason": data.get("done_reason", "stop"),
                    "context": data.get("context", []),
                },
            )
        except requests.exceptions.ConnectionError as e:
            raise RuntimeError(
                "Ollama connection failed. Is it running?\nStart with: ollama serve"
            ) from e
        except requests.exceptions.HTTPError as e:
            if response.status_code == 404:
                raise RuntimeError(
                    f"Model '{self.model}' not found.\nPull it with: ollama pull {self.model}"
                ) from e
            raise RuntimeError(f"Ollama API error: {e}") from e
        except Exception as e:
            raise RuntimeError(f"Ollama adapter error: {e}") from e
