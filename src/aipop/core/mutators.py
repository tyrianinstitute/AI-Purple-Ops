"""Core protocols and models for mutation strategies."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass
class MutationResult:
    """Result of a single mutation operation."""

    original: str
    mutated: str
    mutation_type: str
    metadata: dict[str, Any]


class Mutator(Protocol):
    """Protocol for prompt mutation strategies."""

    def mutate(self, prompt: str, context: dict[str, Any] | None = None) -> list[MutationResult]:
        """Generate mutations of the given prompt.

        Args:
            prompt: Original prompt text
            context: Optional context (test case, previous results, etc.)

        Returns:
            List of mutation results
        """
        ...

    def get_stats(self) -> dict[str, Any]:
        """Return mutation statistics."""
        ...
