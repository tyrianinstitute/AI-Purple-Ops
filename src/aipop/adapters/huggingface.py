"""HuggingFace Transformers adapter for local quantized models."""

from __future__ import annotations

import os
import time
from typing import Any

from aipop.adapters.connection_helpers import check_huggingface_model
from aipop.core.models import ModelResponse


class HuggingFaceAdapter:
    """Adapter for local HuggingFace models with CPU quantization.

    Runs quantized models directly - no API, no network, fully local.
    Uses 4-bit quantization to keep memory usage low.

    Args:
        model_name: HuggingFace model ID (e.g., "TinyLlama/TinyLlama-1.1B-Chat-v1.0")
        device_map: "cpu" or "auto" (auto uses GPU if available)
        load_in_4bit: Use 4-bit quantization (default: True for CPU)
        cache_dir: Model cache directory (defaults to HF_HOME env var)
    """

    def __init__(
        self,
        model_name: str = "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
        device_map: str = "cpu",
        load_in_4bit: bool = True,
        cache_dir: str | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize HuggingFace adapter."""
        self.model_name = model_name
        self.device_map = device_map

        # Check if model is accessible
        accessible, error_msg = check_huggingface_model(model_name)
        if not accessible:
            raise RuntimeError(
                f"Cannot access HuggingFace model '{model_name}': {error_msg}\n"
                f"Install transformers: pip install transformers\n"
                f"Or use a different adapter (e.g., ollama)."
            )

        print(f"Loading model {model_name}... (this may take a minute)")

        try:
            from transformers import AutoModelForCausalLM, AutoTokenizer, pipeline

            # Load tokenizer with revision pinning for security
            self.tokenizer = AutoTokenizer.from_pretrained(
                model_name, cache_dir=cache_dir or os.getenv("HF_HOME"), revision="main"
            )

            # Load model with quantization
            if load_in_4bit and device_map == "cpu":
                # For CPU, try 8-bit if 4-bit not available
                try:
                    from transformers import BitsAndBytesConfig

                    quantization_config = BitsAndBytesConfig(
                        load_in_4bit=True,
                        bnb_4bit_compute_dtype="float16",
                    )
                    self.model = AutoModelForCausalLM.from_pretrained(
                        model_name,
                        quantization_config=quantization_config,
                        device_map=device_map,
                        low_cpu_mem_usage=True,
                        cache_dir=cache_dir or os.getenv("HF_HOME"),
                        revision="main",
                    )
                except Exception:
                    # Fallback to 8-bit or no quantization
                    try:
                        self.model = AutoModelForCausalLM.from_pretrained(
                            model_name,
                            load_in_8bit=True,
                            device_map=device_map,
                            low_cpu_mem_usage=True,
                            cache_dir=cache_dir or os.getenv("HF_HOME"),
                            revision="main",
                        )
                    except Exception:
                        # No quantization - use full precision
                        self.model = AutoModelForCausalLM.from_pretrained(
                            model_name,
                            device_map=device_map,
                            low_cpu_mem_usage=True,
                            cache_dir=cache_dir or os.getenv("HF_HOME"),
                            revision="main",
                        )
            else:
                self.model = AutoModelForCausalLM.from_pretrained(
                    model_name,
                    device_map=device_map,
                    low_cpu_mem_usage=True,
                    cache_dir=cache_dir or os.getenv("HF_HOME"),
                    revision="main",
                )

            # Create pipeline
            self.pipeline = pipeline(
                "text-generation",
                model=self.model,
                tokenizer=self.tokenizer,
                device_map=device_map,
            )

            print("Model loaded successfully!")

        except ImportError as e:
            raise ImportError(
                f"Required libraries not installed: {e}\n"
                f"Install with: pip install transformers torch accelerate\n"
                f"For quantization: pip install bitsandbytes"
            ) from e
        except Exception as e:
            raise RuntimeError(
                f"Failed to load HuggingFace model '{model_name}': {e}\n"
                f"Check model name and ensure you have sufficient disk space."
            ) from e

    def invoke(self, prompt: str, **kwargs: Any) -> ModelResponse:
        """Invoke HuggingFace model and return response."""
        start_time = time.time()

        max_length = kwargs.get("max_tokens", 512) or 512
        temperature = kwargs.get("temperature", 0.7)

        try:
            outputs = self.pipeline(
                prompt,
                max_length=max_length,
                temperature=temperature,
                do_sample=True,
                num_return_sequences=1,
                pad_token_id=self.tokenizer.eos_token_id,
            )

            # Extract response
            response_text = outputs[0]["generated_text"]
            # Remove prompt from response if it's included
            if response_text.startswith(prompt):
                response_text = response_text[len(prompt) :].strip()

            # Calculate latency
            latency_ms = (time.time() - start_time) * 1000

            # Tokenize to get accurate token counts
            prompt_tokens = len(self.tokenizer.encode(prompt))
            completion_tokens = len(self.tokenizer.encode(response_text))
            total_tokens = prompt_tokens + completion_tokens

            return ModelResponse(
                text=response_text,
                meta={
                    "model": self.model_name,
                    "tokens": total_tokens,
                    "tokens_prompt": prompt_tokens,
                    "tokens_completion": completion_tokens,
                    "latency_ms": round(latency_ms, 2),
                    "cost_usd": 0.0,
                    "finish_reason": "stop",
                    "device": self.device_map,
                },
            )
        except Exception as e:
            raise RuntimeError(f"HuggingFace model error: {e}") from e
