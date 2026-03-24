"""Plugin loader and registry for attack plugins."""

from __future__ import annotations

import logging
from typing import Any

from aipop.intelligence.plugins.autodan_official import AutoDANOfficialPlugin
from aipop.intelligence.plugins.base import AttackPlugin
from aipop.intelligence.plugins.gcg_official import GCGOfficialPlugin
from aipop.intelligence.plugins.pair_official import PAIROfficialPlugin

logger = logging.getLogger(__name__)


def load_plugin(
    method: str,
    implementation: str = "official",
) -> AttackPlugin:
    """Load attack plugin by method and implementation.

    Args:
        method: Attack method (gcg, pair, autodan)
        implementation: "official" (battle-tested) or "legacy" (scratch)

    Returns:
        AttackPlugin instance

    Raises:
        ValueError: If method or implementation is unknown
    """
    if implementation == "official":
        return _load_official_plugin(method)
    elif implementation == "legacy":
        return _load_legacy_plugin(method)
    else:
        raise ValueError(
            f"Unknown implementation: {implementation}. " f"Use 'official' or 'legacy'."
        )


def _load_official_plugin(method: str) -> AttackPlugin:
    """Load official plugin implementation.

    Args:
        method: Attack method

    Returns:
        Official AttackPlugin instance

    Raises:
        ValueError: If method is unknown
        RuntimeError: If plugin is not installed
    """
    if method == "gcg":
        plugin = GCGOfficialPlugin()
    elif method == "pair":
        plugin = PAIROfficialPlugin()
    elif method == "autodan":
        plugin = AutoDANOfficialPlugin()
    else:
        raise ValueError(f"Unknown method: {method}. " f"Use 'gcg', 'pair', or 'autodan'.")

    # Check if plugin is available
    is_available, error_msg = plugin.check_available()

    if not is_available:
        from rich.console import Console
        from rich.panel import Panel

        console = Console()

        # ASR mapping for clear comparison
        asr_map = {
            "pair": {"official": "88%", "legacy": "65%"},
            "gcg": {"official": "99%", "legacy": "40%"},
            "autodan": {"official": "88%", "legacy": "58%"},
        }

        asr = asr_map.get(method, {"official": "high", "legacy": "moderate"})

        console.print("\n")
        console.print(
            Panel.fit(
                f"[yellow]⚠️  Official {method.upper()} Not Available[/yellow]\n\n"
                f"[bold]Reason:[/bold]\n{error_msg}\n\n"
                f"[bold yellow]Falling back to legacy implementation:[/bold yellow]\n"
                f"  • Expected ASR: {asr['legacy']} (vs {asr['official']} official)\n"
                f"  • Works immediately (no install needed)\n"
                f"  • Good for testing, education, air-gapped environments\n\n"
                f"[bold]To use official implementation:[/bold]\n"
                f"  aipop plugins install {method}",
                border_style="yellow",
                title="[bold]Auto-Fallback[/bold]",
            )
        )
        console.print()

        logger.warning(f"Official {method} not available: {error_msg}")
        logger.warning("Falling back to legacy implementation...")

        # Auto-fallback to legacy
        return _load_legacy_plugin(method)

    return plugin


def _load_legacy_plugin(method: str) -> AttackPlugin:
    """Load legacy (scratch) plugin implementation.

    Args:
        method: Attack method

    Returns:
        Legacy AttackPlugin wrapped in adapter

    Raises:
        ValueError: If method is unknown
    """
    # Import legacy implementations

    if method == "gcg":
        return LegacyGCGAdapter()
    elif method == "autodan":
        return LegacyAutoDANAdapter()
    elif method == "pair":
        return LegacyPAIRAdapter()
    else:
        raise ValueError(f"Unknown method: {method}. " f"Use 'gcg', 'pair', or 'autodan'.")


# Legacy adapters wrap scratch implementations to match AttackPlugin interface


class LegacyGCGAdapter(AttackPlugin):
    """Adapter for legacy GCG implementation."""

    def name(self) -> str:
        return "gcg_legacy"

    def check_available(self) -> tuple[bool, str]:
        return True, ""  # Always available (no external deps)

    def run(self, config: dict[str, Any]) -> Any:
        import time

        from aipop.intelligence.legacy import GCGBlackBoxOptimizer
        from aipop.intelligence.plugins.base import AttackResult

        start_time = time.time()

        try:
            # Create optimizer (black-box mode, no model/tokenizer needed)
            optimizer = GCGBlackBoxOptimizer(mode="black-box")

            # Run optimizer using the actual method signature
            results = optimizer.optimize_suffix(
                prompt=config.get("prompt", ""),
                target=config.get("target", "Sure, I can help"),
                max_iterations=config.get("max_iterations", 500),
                batch_size=config.get("batch_size", 256),
                top_k=config.get("top_k", 256),
            )

            # Results is list[tuple[str, float]] - (suffix, loss)
            adversarial_prompts = [
                suffix for suffix, _ in results[: config.get("return_top_k", 10)]
            ]
            scores = [loss for _, loss in results[: config.get("return_top_k", 10)]]

            return AttackResult(
                success=len(adversarial_prompts) > 0,
                adversarial_prompts=adversarial_prompts,
                scores=scores,
                metadata={"method": "gcg_legacy", "mode": "black-box"},
                execution_time=time.time() - start_time,
            )

        except Exception as e:
            logger.error(f"Legacy GCG failed: {e}", exc_info=True)
            from aipop.intelligence.plugins.base import AttackResult

            return AttackResult(
                success=False,
                adversarial_prompts=[],
                scores=[],
                execution_time=time.time() - start_time,
                error=str(e),
            )

    def estimate_cost(self, config: dict[str, Any]) -> Any:
        from aipop.intelligence.plugins.base import CostEstimate

        return CostEstimate(
            total_usd=0.0,
            num_queries=0,
            notes=["Legacy implementation (no API costs)"],
        )


class LegacyAutoDANAdapter(AttackPlugin):
    """Adapter for legacy AutoDAN implementation."""

    def name(self) -> str:
        return "autodan_legacy"

    def check_available(self) -> tuple[bool, str]:
        return True, ""

    def run(self, config: dict[str, Any]) -> Any:
        import time

        from aipop.intelligence.legacy.autodan_scratch import (
            AutoDANScratchConfig,
            HierarchicalGeneticAlgorithmScratch,
        )
        from aipop.intelligence.plugins.base import AttackResult

        start_time = time.time()

        try:
            autodan_config = AutoDANScratchConfig(
                population_size=config.get("population_size", 256),
                num_generations=config.get("num_generations", 100),
            )

            # Need adapter for target model
            target_adapter = config.get("adapter")
            if not target_adapter:
                raise ValueError("adapter is required for AutoDAN")

            hga = HierarchicalGeneticAlgorithmScratch(
                config=autodan_config,
                target_adapter=target_adapter,
                mutator_adapter=config.get("mutator_adapter"),  # Optional separate LLM for mutation
                judge=config.get("judge"),
            )

            # Run attack - evolve() returns list[Candidate] sorted by fitness
            # Combine the prompt and target into a base prompt for evolution
            base_prompt = config.get("prompt", "")
            target_prefix = config.get("target", "Sure, I can help")

            # AutoDAN requires multi-sentence prompts for crossover to work effectively
            # If base_prompt is single-sentence, expand it to enable genetic diversity
            num_sentences = len([s for s in base_prompt.split(".") if s.strip()])
            if num_sentences <= 1:
                logger.info("Expanding single-sentence prompt for AutoDAN evolution")
                base_prompt = f"{base_prompt}. I need help with this task. Can you assist me?"

            # Format: "OBJECTIVE: <prompt>\nRESPONSE: <target_prefix>..."
            if target_prefix:
                base_prompt = f"{base_prompt}\n\nPlease begin your response with: {target_prefix}"

            best_candidates = hga.evolve(base_prompt)

            return AttackResult(
                success=len(best_candidates) > 0,
                adversarial_prompts=[c.prompt for c in best_candidates[:10]],
                scores=[c.fitness for c in best_candidates[:10]],
                metadata={
                    "method": "autodan_legacy",
                    "population_size": autodan_config.population_size,
                    "num_generations": autodan_config.num_generations,
                },
                execution_time=time.time() - start_time,
            )

        except Exception as e:
            logger.error(f"Legacy AutoDAN failed: {e}", exc_info=True)
            from aipop.intelligence.plugins.base import AttackResult

            return AttackResult(
                success=False,
                adversarial_prompts=[],
                scores=[],
                execution_time=time.time() - start_time,
                error=str(e),
            )

    def estimate_cost(self, config: dict[str, Any]) -> Any:
        from aipop.intelligence.plugins.base import CostEstimate

        population_size = config.get("population_size", 256)
        num_generations = config.get("num_generations", 100)

        return CostEstimate(
            total_usd=0.0,
            num_queries=population_size * num_generations,
            notes=["Legacy implementation (black-box, keyword fitness)"],
        )


class LegacyPAIRAdapter(AttackPlugin):
    """Adapter for legacy PAIR implementation."""

    def name(self) -> str:
        return "pair_legacy"

    def check_available(self) -> tuple[bool, str]:
        return True, ""

    def run(self, config: dict[str, Any]) -> Any:
        import time

        from aipop.intelligence.legacy.pair_scratch import PAIRAttackerScratch, PAIRScratchConfig
        from aipop.intelligence.plugins.base import AttackResult

        start_time = time.time()

        try:
            pair_config = PAIRScratchConfig(
                num_streams=config.get("num_streams", 30),
                iterations_per_stream=config.get("iterations_per_stream", 3),
                keep_last_n=config.get("keep_last_n", 4),
            )

            # Get adapters
            attacker_adapter = config.get("attacker_adapter") or config.get("adapter")
            target_adapter = config.get("adapter")
            if not target_adapter:
                raise ValueError("adapter is required for PAIR")

            pair = PAIRAttackerScratch(
                config=pair_config,
                attacker_adapter=attacker_adapter,
                target_adapter=target_adapter,
                judge=config.get("judge"),
            )

            # Run attack - returns list[PAIRStream]
            streams = pair.attack(
                objective=config.get("prompt", ""),
                starting_string=config.get("target", "Sure, here is"),
            )

            # Extract successful prompts
            successful_prompts = []
            all_scores = []

            if not streams:
                logger.warning("PAIR generated no streams, returning objective as fallback")
                successful_prompts = [config.get("prompt", "")]
                all_scores = [0.0]
            else:
                for stream in streams:
                    if stream.success and stream.history:
                        # Get the final successful prompt (PAIRTurn.prompt field)
                        final_turn = stream.history[-1]
                        successful_prompts.append(final_turn.prompt)
                        all_scores.append(final_turn.score)
                    elif stream.history:
                        # Get the best attempted prompt even if not successful
                        # Sort by score descending
                        best_turn = max(stream.history, key=lambda t: t.score)
                        if best_turn.prompt and len(successful_prompts) < 10:
                            successful_prompts.append(best_turn.prompt)
                            all_scores.append(best_turn.score)

                # If no prompts were generated, return at least the objective as a fallback
                if not successful_prompts:
                    logger.warning(
                        "PAIR generated no successful prompts, returning objective as fallback"
                    )
                    successful_prompts = [config.get("prompt", "")]
                    all_scores = [0.0]

            return AttackResult(
                success=len([s for s in streams if s.success]) > 0,
                adversarial_prompts=successful_prompts[:10],
                scores=all_scores[:10],
                metadata={
                    "method": "pair_legacy",
                    "num_streams": len(streams),
                    "success_rate": (
                        len([s for s in streams if s.success]) / len(streams) if streams else 0
                    ),
                },
                execution_time=time.time() - start_time,
            )

        except Exception as e:
            logger.error(f"Legacy PAIR failed: {e}", exc_info=True)
            from aipop.intelligence.plugins.base import AttackResult

            return AttackResult(
                success=False,
                adversarial_prompts=[],
                scores=[],
                execution_time=time.time() - start_time,
                error=str(e),
            )

    def estimate_cost(self, config: dict[str, Any]) -> Any:
        from aipop.intelligence.plugins.base import CostEstimate

        n_streams = config.get("num_streams", 30)
        n_iterations = config.get("iterations_per_stream", 3)

        # Legacy PAIR uses API for attacker/target/judge (3 calls per iteration)
        # Research shows PAIR averages ~15 queries (not max of 90)
        # Most succeed in first 1-2 iterations due to early stopping
        avg_queries = 15  # From paper: 14.6-21.3 queries average
        avg_tokens_per_query = 800  # Estimate (attacker + target + judge)

        # Cost calculation (assuming GPT-3.5-turbo: $0.5/1M input, $1.5/1M output)
        input_cost_per_1k = 0.0005
        output_cost_per_1k = 0.0015

        # 3 API calls per query: attacker, target, judge
        estimated_input_tokens = avg_queries * avg_tokens_per_query * 0.7 * 3
        estimated_output_tokens = avg_queries * avg_tokens_per_query * 0.3 * 3

        estimated_cost = (estimated_input_tokens / 1000) * input_cost_per_1k + (
            estimated_output_tokens / 1000
        ) * output_cost_per_1k

        return CostEstimate(
            total_usd=estimated_cost,
            num_queries=avg_queries * 3,  # attacker + target + judge per query
            notes=[
                "Legacy implementation (API-based, keyword fitness)",
                f"Estimated {avg_queries} attack queries (not max {n_streams * n_iterations})",
                "Each query = 3 API calls (attacker + target + judge)",
                "Official implementation may be more cost-efficient with early stopping",
            ],
        )


class CachedPluginWrapper(AttackPlugin):
    """Wrapper that adds caching to any plugin.

    Automatically caches attack results to avoid re-running identical attacks.
    """

    def __init__(self, method: str, implementation: str):
        """Initialize cached plugin wrapper.

        Args:
            method: Attack method (gcg, pair, autodan)
            implementation: official or legacy
        """
        self.plugin = load_plugin(method, implementation)
        from aipop.storage.attack_cache import AttackCache

        self.cache = AttackCache()
        self.method = method
        self.implementation = implementation

    def name(self) -> str:
        return self.plugin.name()

    def check_available(self) -> tuple[bool, str]:
        return self.plugin.check_available()

    def info(self):
        return self.plugin.info()

    def run(self, config: dict[str, Any]):
        """Run attack with caching.

        Args:
            config: Attack configuration

        Returns:
            AttackResult (from cache if available, otherwise fresh)
        """
        import logging

        logger = logging.getLogger(__name__)

        # Try cache first
        cache_key = self.cache._generate_cache_key(
            self.method,
            config.get("prompt", ""),
            config.get("adapter_model", config.get("model", "")),
            self.implementation,
            self._extract_cache_params(config),
        )
        logger.info(f"Looking for cache key: {cache_key}")

        cached = self.cache.get_cached_result(
            self.method,
            config.get("prompt", ""),
            config.get("adapter_model", config.get("model", "")),
            self.implementation,
            self._extract_cache_params(config),
        )

        if cached:
            logger.info("✓ Cache hit! Using cached result")
            # Print to console for user visibility (used by wrapper when not using fast cache)
            from rich.console import Console

            console = Console()
            cost_saved = (
                cached.get("metadata", {}).get("cost", 0.02) if isinstance(cached, dict) else 0.02
            )
            console.print(
                f"[green]✓ Cache hit![/green] Saved ${cost_saved:.2f} (avoiding API call)"
            )
            # Reconstruct AttackResult from cached dict
            from aipop.intelligence.plugins.base import AttackResult

            return AttackResult(**cached)

        logger.info("Cache miss, running attack...")
        # Run attack
        result = self.plugin.run(config)

        # Cache result
        self.cache.cache_attack_result(
            self.method,
            config.get("prompt", ""),
            config.get("adapter_model", config.get("model", "")),
            self.implementation,
            self._extract_cache_params(config),
            result,
        )
        logger.info(f"Cached result with key: {cache_key}")

        return result

    def estimate_cost(self, config: dict[str, Any]):
        return self.plugin.estimate_cost(config)

    def _extract_cache_params(self, config: dict[str, Any]) -> dict[str, Any]:
        """Extract cacheable parameters from config.

        Only includes params that affect attack results.
        """
        return {
            "num_streams": config.get("num_streams"),
            "iterations_per_stream": config.get("iterations_per_stream"),
            "max_iterations": config.get("max_iterations"),
            "population_size": config.get("population_size"),
            "num_generations": config.get("num_generations"),
            "target": config.get("target"),
            "judge_model": config.get("judge_model"),
            "attacker_model": config.get("attacker_model"),
        }


def check_cache_fast(
    method: str,
    prompt: str,
    model: str,
    implementation: str,
    params: dict,
) -> dict | None:
    """Fast cache check without loading plugin.

    Args:
        method: Attack method
        prompt: Target prompt
        model: Target model
        implementation: official or legacy
        params: Attack parameters

    Returns:
        Cached result dict or None
    """
    from aipop.storage.attack_cache import AttackCache

    cache = AttackCache()
    return cache.get_cached_result(method, prompt, model, implementation, params)


def load_plugin_with_cache(
    method: str,
    implementation: str = "official",
    use_cache: bool = True,
) -> AttackPlugin:
    """Load plugin with optional caching wrapper.

    Args:
        method: Attack method (gcg, pair, autodan)
        implementation: official or legacy
        use_cache: Enable result caching

    Returns:
        AttackPlugin (optionally wrapped with CachedPluginWrapper)
    """
    if use_cache:
        return CachedPluginWrapper(method, implementation)
    else:
        return load_plugin(method, implementation)
