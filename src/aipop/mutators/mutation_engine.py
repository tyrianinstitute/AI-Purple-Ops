"""Central mutation engine coordinating all mutators."""

from __future__ import annotations

import random
from typing import Any

from aipop.core.mutation_config import MutationConfig
from aipop.mutators.encoding import EncodingMutator
from aipop.mutators.genetic import GeneticMutator
from aipop.mutators.html import HTMLMutator
from aipop.mutators.paraphrasing import ParaphrasingMutator
from aipop.mutators.unicode_mutator import UnicodeMutator
from aipop.storage.mutation_db import MutationDatabase


class MutationEngine:
    """Central mutation engine coordinating all mutators."""

    def __init__(self, config: MutationConfig) -> None:
        """Initialize mutation engine.

        Args:
            config: Mutation configuration
        """
        self.config = config
        self.mutators: list[Any] = []
        self.db = MutationDatabase(config.db_path)
        self.guardrail_type: str | None = None
        self.priority_mutators: list[str] = []  # High-priority mutators based on guardrail
        self._initialize_mutators()

    def _initialize_mutators(self) -> None:
        """Initialize enabled mutators based on config."""
        if self.config.enable_encoding:
            self.mutators.append(EncodingMutator())

        if self.config.enable_unicode:
            self.mutators.append(UnicodeMutator())

        if self.config.enable_html:
            self.mutators.append(HTMLMutator())

        if self.config.enable_paraphrasing:
            try:
                self.mutators.append(
                    ParaphrasingMutator(
                        provider=self.config.paraphrase_provider,
                        model=self.config.paraphrase_model,
                        api_key=self.config.paraphrase_api_key,
                    )
                )
            except ValueError as e:
                print(f"Warning: Paraphrasing mutator disabled - {e}")

        if self.config.enable_genetic:
            self.mutators.append(GeneticMutator(self.config))

        if self.config.enable_gcg:
            try:
                from aipop.mutators.gcg_mutator import GCGMutator

                self.mutators.append(
                    GCGMutator(
                        mode=self.config.gcg_mode,
                        use_library=self.config.gcg_use_library,
                        generate_on_demand=self.config.gcg_generate_on_demand,
                        max_iterations=self.config.gcg_max_iterations,
                    )
                )
            except ImportError as e:
                print(f"Warning: GCG mutator disabled - {e}")
            except Exception as e:
                print(f"Warning: GCG mutator disabled - {e}")

    def mutate(self, prompt: str, context: dict[str, Any] | None = None) -> list[Any]:
        """Generate all mutations for a prompt.

        Args:
            prompt: Original prompt text
            context: Optional context (test case, previous results, etc.)

        Returns:
            List of MutationResult objects
        """
        all_mutations = []

        for mutator in self.mutators:
            mutations = mutator.mutate(prompt, context)
            all_mutations.extend(mutations)

        return all_mutations

    def save_stats_to_session(self, session_id: str) -> None:
        """Persist mutation success rates to session store for cross-run adaptation."""
        try:
            from aipop.core.session_store import SessionStore
            store = SessionStore()
            stats = {m.__class__.__name__: getattr(m, 'get_stats', lambda: {})() for m in self.mutators}
            store.add_discovery(session_id, "mutation_stats", "mutation_success_rates", stats)
            store.close()
        except Exception:
            pass

    def load_stats_from_session(self, session_id: str) -> None:
        """Load mutation success rates from a previous session run."""
        try:
            from aipop.core.session_store import SessionStore
            store = SessionStore()
            discoveries = store.get_discoveries(session_id, "mutation_stats")
            if discoveries:
                import json
                latest = discoveries[-1]
                saved_stats = json.loads(latest["value"]) if isinstance(latest["value"], str) else latest["value"]
                # Inject saved stats into current mutators
                for mutator in self.mutators:
                    name = mutator.__class__.__name__
                    if name in saved_stats and hasattr(mutator, 'set_stats'):
                        mutator.set_stats(saved_stats[name])
            store.close()
        except Exception:
            pass

    def mutate_with_feedback(self, prompt: str, context: dict[str, Any] | None = None) -> list[Any]:
        """Generate mutations using RL feedback to prioritize successful strategies.

        Args:
            prompt: Original prompt text
            context: Optional context with optimization target

        Returns:
            List of MutationResult objects, ordered by expected success
        """
        # Get historical success rates
        stats = {m.__class__.__name__: m.get_stats() for m in self.mutators}

        # Apply RL-based selection (epsilon-greedy)
        if self.config.enable_rl_feedback:
            selected_mutators = self._select_mutators_rl(stats)
        else:
            selected_mutators = self.mutators

        all_mutations = []
        for mutator in selected_mutators:
            mutations = mutator.mutate(prompt, context)
            all_mutations.extend(mutations)

        return all_mutations

    def _select_mutators_rl(self, stats: dict[str, dict[str, Any]]) -> list[Any]:
        """Select mutators using epsilon-greedy RL.

        Args:
            stats: Dictionary mapping mutator class names to their stats

        Returns:
            List of selected mutators
        """
        # Exploration: try all mutators
        if random.random() < self.config.rl_exploration_rate:
            return self.mutators

        # Exploitation: prefer successful mutators
        mutator_scores = []
        for mutator in self.mutators:
            name = mutator.__class__.__name__
            if name in stats:
                total = stats[name].get("total", 1)
                success = stats[name].get("success", 0)
                success_rate = success / max(total, 1)
                mutator_scores.append((mutator, success_rate))
            else:
                mutator_scores.append((mutator, 0.0))

        # Sort by success rate, take top performers
        mutator_scores.sort(key=lambda x: x[1], reverse=True)
        return [m for m, _ in mutator_scores[: len(self.mutators) // 2 + 1]]

    def record_result(self, mutation_data: dict[str, Any]) -> None:
        """Record mutation result for learning.

        Args:
            mutation_data: Dictionary with mutation result information
        """
        if self.config.track_full_history:
            self.db.record_mutation(mutation_data)

    def get_analytics(self) -> dict[str, Any]:
        """Get mutation analytics.

        Returns:
            Dictionary with top mutations and statistics
        """
        return {
            "top_mutations": self.db.get_top_mutations(),
            "mutation_stats": self.db.get_mutation_stats(),
        }

    def set_guardrail_optimization(self, guardrail_type: str) -> None:
        """Optimize mutation strategy for detected guardrail.

        Research-based priorities:
        - PromptGuard: Character injection (72% ASR), Unicode (68% ASR)
        - Llama Guard 3: Multi-turn required, encoding effective
        - Azure: Threshold manipulation, gradual escalation
        - Constitutional AI: Multi-turn, adversarial suffixes
        - Rebuff: Template injection, context pollution
        - NeMo: Rule evasion, boundary testing

        Args:
            guardrail_type: Detected guardrail type
        """
        self.guardrail_type = guardrail_type

        # Define priority mutators for each guardrail
        guardrail_priorities = {
            "promptguard": ["UnicodeMutator", "EncodingMutator"],  # Character injection via Unicode
            "llama_guard_3": [
                "EncodingMutator",
                "UnicodeMutator",
                "HTMLMutator",
            ],  # Encoding bypass
            "azure_content_safety": ["EncodingMutator", "HTMLMutator"],  # Gradual escalation
            "constitutional_ai": ["ParaphrasingMutator", "GeneticMutator"],  # Adversarial suffixes
            "rebuff": ["HTMLMutator", "EncodingMutator"],  # Template injection
            "nemo_guardrails": ["EncodingMutator", "UnicodeMutator"],  # Rule evasion
            "unknown": ["EncodingMutator", "UnicodeMutator", "HTMLMutator"],  # Try everything
        }

        self.priority_mutators = guardrail_priorities.get(
            guardrail_type, guardrail_priorities["unknown"]
        )

        # Reorder mutators to prioritize high-value ones
        self._reorder_mutators()

    def _reorder_mutators(self) -> None:
        """Reorder mutators to prioritize those effective against detected guardrail."""
        if not self.priority_mutators:
            return

        # Separate mutators into priority and non-priority
        priority_dict = {
            m.__class__.__name__: m
            for m in self.mutators
            if m.__class__.__name__ in self.priority_mutators
        }
        remaining_list = [
            m for m in self.mutators if m.__class__.__name__ not in self.priority_mutators
        ]

        # Build priority list in the order specified
        priority_list = []
        for priority_name in self.priority_mutators:
            if priority_name in priority_dict:
                priority_list.append(priority_dict[priority_name])

        # Reorder: priority mutators first (in specified order), then others
        self.mutators = priority_list + remaining_list

    def get_strategy_info(self) -> dict[str, Any]:
        """Get current strategy information.

        Returns:
            Dictionary with guardrail type and active mutators
        """
        return {
            "guardrail_type": self.guardrail_type,
            "priority_mutators": self.priority_mutators,
            "active_mutators": [m.__class__.__name__ for m in self.mutators],
            "mutator_order": [
                f"{i+1}. {m.__class__.__name__}" for i, m in enumerate(self.mutators)
            ],
        }

    def close(self) -> None:
        """Close database connection."""
        self.db.close()
