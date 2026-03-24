"""llama.cpp adapter for ultra-efficient CPU inference."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from aipop.adapters.connection_helpers import validate_model_file
from aipop.core.models import ModelResponse


class LlamaCppAdapter:
    """Adapter for llama.cpp models (GGUF format).

    Most efficient CPU inference. Supports GGUF quantized models.

    Args:
        model_path: Path to .gguf model file
        n_ctx: Context window size (default: 2048)
        n_threads: CPU threads (default: auto)
        n_gpu_layers: GPU layers (0 = CPU only)
    """

    def __init__(
        self,
        model_path: str | Path,
        n_ctx: int = 2048,
        n_threads: int | None = None,
        n_gpu_layers: int = 0,  # 0 = CPU only
        **kwargs: Any,
    ) -> None:
        """Initialize llama.cpp adapter."""
        model_path = Path(model_path)

        # Validate model file
        valid, error_msg = validate_model_file(model_path)
        if not valid:
            raise RuntimeError(
                f"Invalid model file: {error_msg}\n"
                f"Download quantized models from: https://huggingface.co/TheBloke\n"
                f"Or use a different adapter (e.g., ollama)."
            )

        print(f"Loading model {model_path.name}... (this may take 30 seconds)")

        try:
            from llama_cpp import Llama

            self.llm = Llama(
                model_path=str(model_path),
                n_ctx=n_ctx,
                n_threads=n_threads,  # Auto-detect if None
                n_gpu_layers=n_gpu_layers,
                verbose=False,
            )

            print("Model loaded successfully!")

        except ImportError:
            raise ImportError(
                "llama-cpp-python not installed.\n"
                "Install with: pip install llama-cpp-python\n"
                "Or use a different adapter (e.g., ollama)."
            )
        except Exception as e:
            raise RuntimeError(
                f"Failed to load llama.cpp model '{model_path}': {e}\n"
                f"Ensure the file is a valid GGUF format model."
            ) from e

    def invoke(self, prompt: str, **kwargs: Any) -> ModelResponse:
        """Invoke llama.cpp model and return response."""
        start_time = time.time()

        max_tokens = kwargs.get("max_tokens", 512)
        temperature = kwargs.get("temperature", 0.7)

        try:
            output = self.llm(
                prompt,
                max_tokens=max_tokens,
                temperature=temperature,
                stop=["</s>", "\n\n\n"],  # Common stop sequences
            )

            # Extract response
            response_text = output["choices"][0]["text"]

            # Calculate latency
            latency_ms = (time.time() - start_time) * 1000

            # Estimate tokens (llama.cpp doesn't always return exact counts)
            prompt_tokens = len(prompt.split())  # Rough estimate
            completion_tokens = len(response_text.split())
            total_tokens = prompt_tokens + completion_tokens

            return ModelResponse(
                text=response_text,
                meta={
                    "model": str(self.llm.model_path),
                    "tokens": total_tokens,
                    "tokens_prompt": prompt_tokens,
                    "tokens_completion": completion_tokens,
                    "latency_ms": round(latency_ms, 2),
                    "cost_usd": 0.0,
                    "finish_reason": output["choices"][0].get("finish_reason", "stop"),
                },
            )
        except Exception as e:
            raise RuntimeError(f"llama.cpp model error: {e}") from e
