"""Official GCG plugin wrapper.

Wraps llm-attacks/llm-attacks implementation for white-box gradient-based
adversarial suffix generation.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from aipop.intelligence.plugins.base import AttackPlugin, AttackResult, CostEstimate

logger = logging.getLogger(__name__)


class GCGOfficialPlugin(AttackPlugin):
    """Wraps llm-attacks/llm-attacks for white-box GCG.

    **Known Limitations:**
    - Requires local HuggingFace models (Vicuna, LLaMA)
    - 80GB GPU recommended for Vicuna-13B
    - Only LLaMA-style tokenizers supported
    - Cannot use API models (OpenAI, Anthropic)

    **Fallback:** Use `--implementation legacy` for black-box GCG
    """

    def name(self) -> str:
        """Return plugin name."""
        return "gcg"

    def check_available(self) -> tuple[bool, str]:
        """Check if GCG is available (llm-attacks + GPU required).

        Returns:
            Tuple of (is_available, error_message)
        """
        # Check GPU first (GCG needs gradients)
        try:
            import torch

            if not torch.cuda.is_available():
                return False, (
                    "GCG requires GPU (CUDA not available).\n\n"
                    "Alternatives:\n"
                    "  1. Use PAIR (works without GPU): --method pair\n"
                    "  2. Use legacy GCG (black-box): --implementation legacy\n"
                    "  3. Get GPU access: Cloud GPU (AWS, GCP, Lambda Labs)\n\n"
                    "Why: GCG needs gradients from local model, cannot use API-only"
                )
        except ImportError:
            pass  # PyTorch not installed, will fail on llm-attacks import anyway

        # Check llm-attacks package
        try:
            import llm_attacks  # noqa: F401

            return True, ""
        except ImportError:
            return False, (
                "llm-attacks not installed.\n\n" "Install with: aipop plugins install gcg"
            )

    def estimate_cost(self, config: dict[str, Any]) -> CostEstimate:
        """Estimate cost for GCG attack.

        GCG is white-box (local model) so API cost is $0, but GPU time is high.

        Args:
            config: Attack configuration

        Returns:
            CostEstimate with $0 API cost
        """
        n_steps = config.get("max_iterations", 500)
        batch_size = config.get("batch_size", 512)

        total_queries = n_steps * batch_size

        return CostEstimate(
            total_usd=0.0,  # No API costs (local model)
            breakdown={"gpu_inference": 0.0},
            num_queries=total_queries,
            confidence="high",
            notes=[
                "GCG runs on local GPU (no API costs)",
                f"Estimated {total_queries:,} forward passes",
                "Requires ~30-60 minutes on A100 for 500 steps",
            ],
        )

    def run(self, config: dict[str, Any]) -> AttackResult:
        """Execute GCG attack using official implementation.

        Args:
            config: Attack configuration containing:
                - prompt: Target prompt
                - target: Desired output prefix
                - model: HuggingFace model ID
                - max_iterations: Number of optimization steps
                - batch_size: Batch size for candidates
                - gcg_top_k: Top-k candidates per position
                - device: CUDA device

        Returns:
            AttackResult with generated suffixes
        """
        start_time = time.time()

        try:
            # Import llm_attacks internals
            import torch
            from llm_attacks import GCGConfig
            from llm_attacks.gcg import GCGAttack
            from transformers import AutoModelForCausalLM, AutoTokenizer

            # Extract config
            prompt = config.get("prompt", "")
            target = config.get("target", "Sure, I can help")
            model_id = config.get("model")
            if not model_id:
                raise ValueError("model (HuggingFace model ID) is required")

            device = config.get("device", "cuda" if torch.cuda.is_available() else "cpu")
            n_steps = config.get("max_iterations", 500)
            batch_size = config.get("batch_size", 512)
            topk = config.get("gcg_top_k", 256)

            logger.info(f"Loading model: {model_id}")

            # Load model and tokenizer
            model = AutoModelForCausalLM.from_pretrained(
                model_id,
                torch_dtype=torch.float16 if device == "cuda" else torch.float32,
                device_map="auto" if device == "cuda" else None,
            )
            tokenizer = AutoTokenizer.from_pretrained(model_id)

            if not tokenizer.pad_token:
                tokenizer.pad_token = tokenizer.eos_token

            # Create GCG config
            gcg_config = GCGConfig(
                num_steps=n_steps,
                batch_size=batch_size,
                topk=topk,
                target=target,
                control_init="! " * 20,  # Initial suffix
            )

            logger.info(f"Running GCG attack: {n_steps} steps, batch size {batch_size}")

            # Initialize attack
            attack = GCGAttack(
                model=model,
                tokenizer=tokenizer,
                config=gcg_config,
            )

            # Run attack
            result = attack.run(
                user_prompt=prompt,
                target=target,
            )

            execution_time = time.time() - start_time

            # Extract best suffixes
            if hasattr(result, "control_strs"):
                adversarial_prompts = result.control_strs[:10]  # Top 10
                scores = (
                    result.losses[:10]
                    if hasattr(result, "losses")
                    else [0.0] * len(adversarial_prompts)
                )
            else:
                # Fallback parsing
                adversarial_prompts = [result.control_str] if hasattr(result, "control_str") else []
                scores = [result.best_loss] if hasattr(result, "best_loss") else [0.0]

            success = len(adversarial_prompts) > 0

            return AttackResult(
                success=success,
                adversarial_prompts=adversarial_prompts,
                scores=scores,
                metadata={
                    "method": "gcg_official",
                    "model": model_id,
                    "n_steps": n_steps,
                    "batch_size": batch_size,
                    "device": device,
                },
                cost=0.0,  # No API cost
                num_queries=n_steps * batch_size,
                execution_time=execution_time,
            )

        except ImportError as e:
            return AttackResult(
                success=False,
                adversarial_prompts=[],
                scores=[],
                error=f"llm-attacks not properly installed: {e}",
            )
        except Exception as e:
            logger.error(f"GCG attack failed: {e}", exc_info=True)
            return AttackResult(
                success=False,
                adversarial_prompts=[],
                scores=[],
                execution_time=time.time() - start_time,
                error=str(e),
            )
