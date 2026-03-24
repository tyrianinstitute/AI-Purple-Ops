"""Cost tracking utility for per-operation cost monitoring."""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

logger = logging.getLogger(__name__)

# Pricing constants (as of November 2025)
# Sources:
# - OpenAI: https://openai.com/api/pricing/ (accessed 2025-11-19)
# - Anthropic: https://www.anthropic.com/pricing (accessed 2025-11-19)
#
# Note: Pricing subject to change. Update quarterly.
# Margin of error: ±5% (system prompts, caching, streaming overhead)

MODEL_PRICING = {
    "gpt-4o-mini": {
        "input_per_million": 0.15,
        "output_per_million": 0.60,
    },
    "gpt-4o": {
        "input_per_million": 2.50,
        "output_per_million": 10.00,
    },
    "gpt-4": {
        "input_per_million": 30.00,
        "output_per_million": 60.00,
    },
    "gpt-3.5-turbo": {
        "input_per_million": 0.50,
        "output_per_million": 1.50,
    },
    "claude-3-5-sonnet-20241022": {
        "input_per_million": 3.00,
        "output_per_million": 15.00,
    },
    "claude-3-opus-20240229": {
        "input_per_million": 15.00,
        "output_per_million": 75.00,
    },
    "claude-3-5-haiku-20241022": {
        "input_per_million": 0.80,
        "output_per_million": 4.00,
    },
}

PRICING_DATE = "2025-11-19"
PRICING_MARGIN_OF_ERROR = 0.05  # ±5%


@dataclass
class CostOperation:
    """Represents a single cost operation."""

    operation: str
    model: str
    input_tokens: int = 0
    output_tokens: int = 0
    cost: float = 0.0
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def total_tokens(self) -> int:
        """Total tokens (input + output)."""
        return self.input_tokens + self.output_tokens


class CostTracker:
    """Track token usage and cost per operation.

    Provides per-operation cost visibility and budget warnings.
    """

    def __init__(self, budget_usd: float | None = None):
        """Initialize cost tracker.

        Args:
            budget_usd: Optional budget limit in USD
        """
        self.operations: list[CostOperation] = []
        self.budget_usd = budget_usd

    def track(
        self,
        operation: str,
        model: str,
        input_tokens: int | None = None,
        output_tokens: int | None = None,
        tokens: int | None = None,  # Deprecated, for backward compat
        cost: float | None = None,
    ) -> None:
        """Track a cost operation.

        Args:
            operation: Operation name
            model: Model identifier
            input_tokens: Input token count (preferred)
            output_tokens: Output token count (preferred)
            tokens: Total tokens (deprecated, for backward compatibility)
            cost: Explicit cost (if None, auto-calculated from pricing)
        """
        # Handle backward compatibility
        if input_tokens is None and output_tokens is None:
            if tokens is not None:
                # Old API: split 40/60 (typical prompt/completion ratio)
                input_tokens = int(tokens * 0.4)
                output_tokens = int(tokens * 0.6)
            else:
                # Default to 0 if no token counts provided
                input_tokens = 0
                output_tokens = 0

        # Ensure we have non-None values
        if input_tokens is None:
            input_tokens = 0
        if output_tokens is None:
            output_tokens = 0

        # Auto-calculate cost if not provided
        if cost is None:
            cost = self._calculate_cost(model, input_tokens, output_tokens)

        self.operations.append(
            CostOperation(
                operation=operation,
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                cost=cost,
            )
        )

    def _calculate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Calculate cost from token counts.

        Args:
            model: Model identifier
            input_tokens: Input token count
            output_tokens: Output token count

        Returns:
            Cost in USD
        """
        if model not in MODEL_PRICING:
            logger.warning(f"Unknown model '{model}', using gpt-3.5-turbo pricing")
            model = "gpt-3.5-turbo"

        pricing = MODEL_PRICING[model]
        input_cost = (input_tokens / 1_000_000) * pricing["input_per_million"]
        output_cost = (output_tokens / 1_000_000) * pricing["output_per_million"]

        return input_cost + output_cost

    def get_summary(self) -> dict[str, Any]:
        """Get cost summary statistics.

        Returns:
            Dictionary with total cost, operation breakdown, and model breakdown
        """
        if not self.operations:
            return {
                "total_cost": 0.0,
                "total_input_tokens": 0,
                "total_output_tokens": 0,
                "total_tokens": 0,
                "operation_breakdown": {},
                "model_breakdown": {},
                "operation_count": 0,
                "pricing_date": PRICING_DATE,
                "margin_of_error": PRICING_MARGIN_OF_ERROR,
            }

        total_cost = sum(op.cost for op in self.operations)
        total_input = sum(op.input_tokens for op in self.operations)
        total_output = sum(op.output_tokens for op in self.operations)

        # Breakdown by operation
        operation_breakdown: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "cost": 0.0,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "count": 0,
            }
        )
        for op in self.operations:
            operation_breakdown[op.operation]["cost"] += op.cost
            operation_breakdown[op.operation]["input_tokens"] += op.input_tokens
            operation_breakdown[op.operation]["output_tokens"] += op.output_tokens
            operation_breakdown[op.operation]["total_tokens"] += op.total_tokens
            operation_breakdown[op.operation]["count"] += 1

        # Breakdown by model
        model_breakdown: dict[str, dict[str, Any]] = defaultdict(
            lambda: {
                "cost": 0.0,
                "input_tokens": 0,
                "output_tokens": 0,
                "total_tokens": 0,
                "count": 0,
            }
        )
        for op in self.operations:
            model_breakdown[op.model]["cost"] += op.cost
            model_breakdown[op.model]["input_tokens"] += op.input_tokens
            model_breakdown[op.model]["output_tokens"] += op.output_tokens
            model_breakdown[op.model]["total_tokens"] += op.total_tokens
            model_breakdown[op.model]["count"] += 1

        return {
            "total_cost": total_cost,  # Don't round - preserve full precision
            "total_input_tokens": total_input,
            "total_output_tokens": total_output,
            "total_tokens": total_input + total_output,
            "operation_breakdown": dict(operation_breakdown),
            "model_breakdown": dict(model_breakdown),
            "operation_count": len(self.operations),
            "pricing_date": PRICING_DATE,
            "margin_of_error": PRICING_MARGIN_OF_ERROR,
            "estimated_range": {
                "min": total_cost * (1 - PRICING_MARGIN_OF_ERROR),
                "max": total_cost * (1 + PRICING_MARGIN_OF_ERROR),
            },
        }

    def warn_if_over_budget(self) -> bool:
        """Check if total cost exceeds budget and warn.

        Returns:
            True if over budget, False otherwise
        """
        if self.budget_usd is None:
            return False

        total_cost = sum(op.cost for op in self.operations)
        if total_cost > self.budget_usd:
            logger.warning(f"Cost ${total_cost:.2f} exceeds budget ${self.budget_usd:.2f}")
            return True
        return False

    def reset(self) -> None:
        """Reset all tracked operations."""
        self.operations.clear()

    def get_operation_cost(self, operation: str) -> float:
        """Get total cost for a specific operation.

        Args:
            operation: Operation name

        Returns:
            Total cost for the operation
        """
        return sum(op.cost for op in self.operations if op.operation == operation)

    def get_model_cost(self, model: str) -> float:
        """Get total cost for a specific model.

        Args:
            model: Model identifier

        Returns:
            Total cost for the model
        """
        return sum(op.cost for op in self.operations if op.model == model)

    def estimate_autodan_cost(
        self,
        population_size: int,
        num_generations: int,
        model: str,
        mutator_model: str | None = None,
    ) -> dict[str, Any]:
        """Estimate AutoDAN cost before running.

        Args:
            population_size: Population size (N)
            num_generations: Number of generations (G)
            model: Target model identifier
            mutator_model: Mutator model identifier (if different from target)

        Returns:
            Dictionary with cost estimates and warnings
        """
        # Estimate queries: population_size * num_generations (fitness evaluation)
        # Plus mutation queries: population_size * num_generations * mutation_rate
        fitness_queries = population_size * num_generations
        mutation_queries = int(population_size * num_generations * 0.01)  # 1% mutation rate
        total_queries = fitness_queries + mutation_queries

        # Estimate tokens per query (typical values)
        input_tokens_per_query = 100
        output_tokens_per_query = 200

        # Calculate costs
        fitness_cost = fitness_queries * self._calculate_cost(
            model, input_tokens_per_query, output_tokens_per_query
        )
        mutation_cost = mutation_queries * self._calculate_cost(
            mutator_model or model, input_tokens_per_query, output_tokens_per_query
        )
        total_cost = fitness_cost + mutation_cost

        return {
            "estimated_queries": total_queries,
            "fitness_queries": fitness_queries,
            "mutation_queries": mutation_queries,
            "estimated_cost_usd": total_cost,
            "fitness_cost": fitness_cost,
            "mutation_cost": mutation_cost,
            "warning": total_cost > 10.0,  # Warn if >$10
            "model": model,
            "mutator_model": mutator_model or model,
        }

    def estimate_pair_cost(
        self,
        num_streams: int,
        iterations_per_stream: int,
        attacker_model: str,
        target_model: str,
    ) -> dict[str, Any]:
        """Estimate PAIR cost before running.

        Args:
            num_streams: Number of parallel streams (N)
            iterations_per_stream: Iterations per stream (K)
            attacker_model: Attacker LLM identifier
            target_model: Target model identifier

        Returns:
            Dictionary with cost estimates and warnings
        """
        # PAIR uses N * K queries (attacker + target per iteration)
        attacker_queries = num_streams * iterations_per_stream
        target_queries = num_streams * iterations_per_stream
        total_queries = attacker_queries + target_queries

        # Estimate tokens per query (typical values)
        input_tokens_per_query = 100
        output_tokens_per_query = 200

        attacker_cost = attacker_queries * self._calculate_cost(
            attacker_model, input_tokens_per_query, output_tokens_per_query
        )
        target_cost = target_queries * self._calculate_cost(
            target_model, input_tokens_per_query, output_tokens_per_query
        )
        total_cost = attacker_cost + target_cost

        return {
            "estimated_queries": total_queries,
            "attacker_queries": attacker_queries,
            "target_queries": target_queries,
            "estimated_cost_usd": total_cost,
            "attacker_cost": attacker_cost,
            "target_cost": target_cost,
            "warning": total_cost > 5.0,  # Warn if >$5 (PAIR is cheaper)
            "attacker_model": attacker_model,
            "target_model": target_model,
        }
