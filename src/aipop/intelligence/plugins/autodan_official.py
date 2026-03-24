"""Official AutoDAN plugin wrapper.

Wraps SheltonLiu-N/AutoDAN hierarchical genetic algorithm implementation
with log-likelihood fitness function.
"""

from __future__ import annotations

import logging
import time
from typing import Any

from aipop.intelligence.plugins.base import AttackPlugin, AttackResult, CostEstimate

logger = logging.getLogger(__name__)


class AutoDANOfficialPlugin(AttackPlugin):
    """Wraps SheltonLiu-N/AutoDAN hierarchical GA implementation.

    **Known Limitations:**
    - White-box only (needs logits for fitness function)
    - High GPU memory (256 candidates in VRAM)
    - ~25,600 forward passes per attack
    - Only HuggingFace models supported

    **Fallback:** Use `--implementation legacy` (uses keyword fitness)
    """

    def name(self) -> str:
        """Return plugin name."""
        return "autodan"

    def check_available(self) -> tuple[bool, str]:
        """Check if AutoDAN is available (repo + GPU required).

        Returns:
            Tuple of (is_available, error_message)
        """
        # Check GPU first (AutoDAN needs logits for fitness)
        try:
            import torch

            if not torch.cuda.is_available():
                return False, (
                    "AutoDAN requires GPU (CUDA not available).\n\n"
                    "Alternatives:\n"
                    "  1. Use PAIR (works without GPU): --method pair\n"
                    "  2. Use legacy AutoDAN (keyword fitness): --implementation legacy\n"
                    "  3. Get GPU access: Cloud GPU (AWS, GCP, Lambda Labs)\n\n"
                    "Why: AutoDAN needs log-likelihood fitness from local model"
                )
        except ImportError:
            pass  # PyTorch not installed, will fail later anyway

        try:
            # Check if AutoDAN modules are available

            # These would be in the AutoDAN repo
            try:
                # AutoDAN doesn't have a package, we import from repo
                import autodan_hga_eval  # noqa: F401

                return True, ""
            except ImportError:
                # Check if dependencies are available
                try:
                    import fschat  # noqa: F401
                    import torch
                    import transformers  # noqa: F401

                    # Dependencies present, but repo not installed
                    return False, (
                        "AutoDAN not installed.\n\n" "Install with: aipop plugins install autodan"
                    )
                except ImportError:
                    return False, (
                        "AutoDAN dependencies not installed.\n\n"
                        "Install with: aipop plugins install autodan"
                    )
        except Exception as e:
            return False, f"Error checking AutoDAN availability: {e}"

    def estimate_cost(self, config: dict[str, Any]) -> CostEstimate:
        """Estimate cost for AutoDAN attack.

        AutoDAN is white-box (local model) so API cost is $0 for fitness computation,
        but optional GPT-based mutation incurs costs.

        Args:
            config: Attack configuration

        Returns:
            CostEstimate
        """
        population_size = config.get("population_size", 256)
        num_generations = config.get("num_generations", 100)
        use_gpt_mutation = config.get("mutator_model") is not None

        # Forward passes for fitness evaluation
        total_forward_passes = population_size * num_generations

        # GPT mutation cost (if enabled)
        gpt_cost = 0.0
        if use_gpt_mutation:
            # Estimate: ~10% of population gets GPT mutation per generation
            num_mutations = int(population_size * 0.1 * num_generations)
            # Each mutation: ~200 tokens input, ~200 tokens output
            gpt_cost = num_mutations * ((200 / 1000) * 0.03 + (200 / 1000) * 0.06)  # GPT-4 pricing

        return CostEstimate(
            total_usd=gpt_cost,
            breakdown={
                "gpt_mutation": gpt_cost,
                "gpu_inference": 0.0,
            },
            num_queries=total_forward_passes + (num_mutations if use_gpt_mutation else 0),
            confidence="high",
            notes=[
                f"AutoDAN: {population_size} pop × {num_generations} gen",
                f"~{total_forward_passes:,} forward passes on local GPU",
                f"GPT mutation: {'enabled' if use_gpt_mutation else 'disabled'}",
                "Requires high GPU memory (256 prompts in VRAM)",
            ],
        )

    def run(self, config: dict[str, Any]) -> AttackResult:
        """Execute AutoDAN attack using official implementation.

        Args:
            config: Attack configuration containing:
                - prompt: Target goal
                - target: Desired output prefix
                - model: HuggingFace model ID
                - population_size: Population size (default 256)
                - num_generations: Number of generations (default 100)
                - mutator_model: Optional GPT model for mutation
                - device: CUDA device

        Returns:
            AttackResult with generated adversarial prompts
        """
        start_time = time.time()

        try:
            # Import AutoDAN internals
            import os

            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer

            # Extract config
            goal = config.get("prompt", "")
            target_str = config.get("target", "Sure, here is")
            model_id = config.get("model")
            if not model_id:
                raise ValueError("model (HuggingFace model ID) is required")

            device = config.get("device", "cuda" if torch.cuda.is_available() else "cpu")
            population_size = config.get("population_size", 256)
            num_generations = config.get("num_generations", 100)
            mutator_model = config.get("mutator_model")

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

            # Import AutoDAN's genetic algorithm
            # Note: This assumes we're running in the AutoDAN venv where their modules are available
            from autodan_hga_eval import hierarchical_genetic_algorithm

            logger.info(f"Running AutoDAN: pop={population_size}, gen={num_generations}")

            # Set optional GPT API key for mutation
            if mutator_model:
                os.environ["API_KEY"] = os.getenv("OPENAI_API_KEY", "")

            # Run hierarchical genetic algorithm
            best_prompts, best_losses = hierarchical_genetic_algorithm(
                model=model,
                tokenizer=tokenizer,
                goal=goal,
                target=target_str,
                batch_size=population_size,
                num_steps=num_generations,
                use_gpt_mutation=(mutator_model is not None),
            )

            execution_time = time.time() - start_time

            # Extract results
            adversarial_prompts = best_prompts[:10]  # Top 10
            scores = [-loss for loss in best_losses[:10]]  # Convert loss to score

            success = len(adversarial_prompts) > 0

            # Calculate actual cost (mostly GPU time, minimal API)
            cost_estimate = self.estimate_cost(config)
            actual_cost = cost_estimate.total_usd

            return AttackResult(
                success=success,
                adversarial_prompts=adversarial_prompts,
                scores=scores,
                metadata={
                    "method": "autodan_official",
                    "model": model_id,
                    "population_size": population_size,
                    "num_generations": num_generations,
                    "used_gpt_mutation": mutator_model is not None,
                    "best_loss": min(best_losses) if best_losses else None,
                },
                cost=actual_cost,
                num_queries=population_size * num_generations,
                execution_time=execution_time,
            )

        except ImportError as e:
            return AttackResult(
                success=False,
                adversarial_prompts=[],
                scores=[],
                error=f"AutoDAN not properly installed: {e}",
            )
        except Exception as e:
            logger.error(f"AutoDAN attack failed: {e}", exc_info=True)
            return AttackResult(
                success=False,
                adversarial_prompts=[],
                scores=[],
                execution_time=time.time() - start_time,
                error=str(e),
            )
