"""GCG-based mutation strategies for adversarial suffix generation."""

from __future__ import annotations

from typing import Any

from aipop.core.mutators import MutationResult
from aipop.intelligence.adversarial_suffix import AdversarialSuffixGenerator


class GCGMutator:
    """Mutator that uses GCG to generate adversarial suffixes."""

    def __init__(
        self,
        mode: str = "black-box",
        use_library: bool = True,
        generate_on_demand: bool = False,
        max_iterations: int = 100,
    ) -> None:
        """Initialize GCG mutator.

        Args:
            mode: "white-box" (gradient-based) or "black-box" (gradient-free)
            use_library: Use pre-computed universal suffixes first (fast)
            generate_on_demand: Generate new suffixes if needed (slow, powerful)
            max_iterations: Max iterations for on-demand generation
        """
        self.mode = mode
        self.use_library = use_library
        self.generate_on_demand = generate_on_demand
        self.max_iterations = max_iterations
        self.generator = AdversarialSuffixGenerator(method="gcg", mode=mode)
        self.stats = {"total": 0, "library_used": 0, "generated": 0, "success": 0}

    def mutate(
        self,
        prompt: str,
        context: dict[str, Any] | None = None,
    ) -> list[MutationResult]:
        """Generate GCG-based mutations.

        Args:
            prompt: Original prompt text
            context: Optional context (test case, adapter, etc.)

        Returns:
            List of MutationResult objects with GCG mutations
        """
        mutations = []

        # Strategy 1: Use pre-computed universal suffixes (fast)
        if self.use_library:
            # Try to get model from context for filtering
            model_id = None
            if context and "adapter" in context:
                adapter = context["adapter"]
                model_id = f"{adapter.__class__.__name__}:{getattr(adapter, 'model', 'unknown')}"

            universal_suffixes = self.generator.load_universal_suffixes(
                filter_by_model=model_id,
                min_asr=0.6,
            )

            for suffix in universal_suffixes[:10]:  # Top 10
                mutations.append(
                    MutationResult(
                        original=prompt,
                        mutated=f"{prompt} {suffix.suffix}",
                        mutation_type="gcg_universal",
                        metadata={
                            "suffix": suffix.suffix,
                            "suffix_id": suffix.id,
                            "asr": (
                                suffix.asr.get(model_id or "default", 0.0) if suffix.asr else 0.0
                            ),
                            "source": suffix.source,
                            "category": suffix.category,
                        },
                    )
                )
                self.stats["library_used"] += 1

        # Strategy 2: Generate new suffixes on-demand (slow, powerful)
        if self.generate_on_demand and context and context.get("adapter"):
            try:
                adapter = context["adapter"]
                model = context.get("model")
                tokenizer = context.get("tokenizer")

                generated = self.generator.generate_suffix(
                    prompt=prompt,
                    adapter=adapter if self.mode == "black-box" else None,
                    model=model if self.mode == "white-box" else None,
                    tokenizer=tokenizer if self.mode == "white-box" else None,
                    max_iterations=self.max_iterations,
                    return_top_k=5,
                )

                for suffix_result in generated:
                    mutations.append(
                        MutationResult(
                            original=prompt,
                            mutated=f"{prompt} {suffix_result.suffix}",
                            mutation_type="gcg_generated",
                            metadata={
                                "suffix": suffix_result.suffix,
                                "asr": suffix_result.asr,
                                "loss": suffix_result.loss,
                                "method": "gcg",
                                "mode": self.mode,
                                **suffix_result.metadata,
                            },
                        )
                    )
                    self.stats["generated"] += 1
            except Exception:
                # Graceful degradation: if generation fails, continue with library only
                pass

        self.stats["total"] += len(mutations)
        return mutations

    def get_stats(self) -> dict[str, Any]:
        """Return mutation statistics.

        Returns:
            Dictionary with mutation stats and suffix database analytics
        """
        db_stats = self.generator.db.get_suffix_stats()
        return {
            **self.stats,
            "suffix_database": db_stats,
        }
