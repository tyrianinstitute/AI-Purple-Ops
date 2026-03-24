"""HTML/XML container mutation strategies."""

from __future__ import annotations

from aipop.core.mutators import MutationResult


class HTMLMutator:
    """HTML/XML container mutations: comments, script tags, CDATA."""

    def __init__(self) -> None:
        """Initialize HTML mutator."""
        self.stats = {"total": 0, "success": 0, "failure": 0}

    def mutate(self, prompt: str, context: dict | None = None) -> list[MutationResult]:
        """Generate HTML/XML container mutations.

        Args:
            prompt: Original prompt text
            context: Optional context (unused for HTML mutations)

        Returns:
            List of mutation results with HTML containers
        """
        mutations = []

        # HTML comment
        mutations.append(
            MutationResult(
                original=prompt,
                mutated=f"<!-- {prompt} -->",
                mutation_type="html_comment",
                metadata={"container": "comment"},
            )
        )

        # Script tag
        mutations.append(
            MutationResult(
                original=prompt,
                mutated=f"<script>{prompt}</script>",
                mutation_type="script_tag",
                metadata={"container": "script"},
            )
        )

        # CDATA section
        mutations.append(
            MutationResult(
                original=prompt,
                mutated=f"<![CDATA[{prompt}]]>",
                mutation_type="cdata",
                metadata={"container": "cdata"},
            )
        )

        self.stats["total"] += len(mutations)
        if mutations:
            self.stats["success"] += 1
        return mutations

    def get_stats(self) -> dict[str, Any]:
        """Return mutation statistics.

        Returns:
            Dictionary with total, success, and failure counts
        """
        return self.stats.copy()
