"""Cost estimation for LLM API calls."""

from __future__ import annotations

# Pricing per 1K tokens (as of 2025-11-08)
# Input and output pricing may differ
COST_PER_1K_TOKENS: dict[str, dict[str, float]] = {
    "gpt-4o": {"input": 0.0025, "output": 0.01},
    "gpt-4o-mini": {"input": 0.00015, "output": 0.0006},
    "gpt-4-turbo": {"input": 0.01, "output": 0.03},
    "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
    "claude-3-5-sonnet-20241022": {"input": 0.003, "output": 0.015},
    "claude-3-opus-20240229": {"input": 0.015, "output": 0.075},
    "claude-3-sonnet-20240229": {"input": 0.003, "output": 0.015},
    "claude-3-haiku-20240307": {"input": 0.00025, "output": 0.00125},
}


def estimate_cost(
    adapter: str, model: str, num_tests: int, avg_tokens: int = 200  # noqa: ARG001
) -> float:
    """Estimate cost for test run.

    Args:
        adapter: Adapter name (openai, anthropic, etc.)
        model: Model name (gpt-4o, claude-3-5-sonnet, etc.)
        num_tests: Number of tests to run
        avg_tokens: Average tokens per test (prompt + response)

    Returns:
        Estimated cost in USD
    """
    # Try exact match first
    if model in COST_PER_1K_TOKENS:
        costs = COST_PER_1K_TOKENS[model]
    else:
        # Try to find a matching model by prefix
        # Extract base model name (e.g., "gpt-4o" from "gpt-4o-mini")
        matching_models = [
            k for k in COST_PER_1K_TOKENS.keys() if model.startswith(k.rsplit("-", 1)[0])
        ]
        if matching_models:
            # Use the closest match (prefer exact prefix)
            costs = COST_PER_1K_TOKENS[matching_models[0]]
        else:
            return 0.0  # Unknown model, can't estimate

    # Simple estimation: assume equal input/output split
    avg_cost_per_1k = (costs["input"] + costs["output"]) / 2
    estimated_cost = num_tests * (avg_tokens / 1000) * avg_cost_per_1k
    # Round to 3 decimals for better precision on small costs
    return round(estimated_cost, 3)
