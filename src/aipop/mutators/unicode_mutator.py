"""Unicode-based obfuscation mutations."""

from __future__ import annotations

from aipop.core.mutators import MutationResult

# Homoglyph mappings (Cyrillic, Greek, etc.)
HOMOGLYPHS = {
    "a": ["а", "ɑ", "α"],  # Cyrillic a, Latin alpha, Greek alpha
    "e": ["е", "ė", "ε"],
    "o": ["о", "ο", "০"],
    "p": ["р", "ρ"],
    "c": ["с", "ϲ"],
    "x": ["х", "χ"],
    "y": ["у", "ү"],
    "i": ["і", "ι"],
    "n": ["п", "η"],
    "m": ["м", "μ"],
    "r": ["г", "Γ"],
    "s": ["ѕ", "ѕ"],
    "t": ["т", "τ"],
    "u": ["υ", "μ"],
    "w": ["ω", "ш"],
}

ZERO_WIDTH_CHARS = [
    "\u200b",  # Zero-width space
    "\u200c",  # Zero-width non-joiner
    "\u200d",  # Zero-width joiner
    "\ufeff",  # Zero-width no-break space
]


class UnicodeMutator:
    """Unicode-based obfuscation: homoglyphs, zero-width characters."""

    def __init__(self) -> None:
        """Initialize unicode mutator."""
        self.stats = {"total": 0, "success": 0, "failure": 0}

    def mutate(self, prompt: str, context: dict | None = None) -> list[MutationResult]:
        """Generate unicode-based mutations.

        Args:
            prompt: Original prompt text
            context: Optional context (unused for unicode mutations)

        Returns:
            List of mutation results with unicode obfuscation
        """
        mutations = []

        # Homoglyph substitution
        try:
            homoglyph = self._apply_homoglyphs(prompt)
            mutations.append(
                MutationResult(
                    original=prompt,
                    mutated=homoglyph,
                    mutation_type="homoglyph",
                    metadata={"technique": "cyrillic_substitution"},
                )
            )
        except Exception:
            self.stats["failure"] += 1

        # Zero-width insertion
        try:
            zw_mutated = self._insert_zero_width(prompt)
            mutations.append(
                MutationResult(
                    original=prompt,
                    mutated=zw_mutated,
                    mutation_type="zero_width",
                    metadata={"chars_inserted": zw_mutated.count("\u200b")},
                )
            )
        except Exception:
            self.stats["failure"] += 1

        self.stats["total"] += len(mutations)
        if mutations:
            self.stats["success"] += 1
        return mutations

    def _apply_homoglyphs(self, text: str) -> str:
        """Replace characters with visually similar homoglyphs.

        Args:
            text: Original text

        Returns:
            Text with homoglyph substitutions
        """
        result = []
        for char in text:
            if char.lower() in HOMOGLYPHS:
                result.append(HOMOGLYPHS[char.lower()][0])
            else:
                result.append(char)
        return "".join(result)

    def _insert_zero_width(self, text: str) -> str:
        """Insert zero-width characters to break tokens.

        Args:
            text: Original text

        Returns:
            Text with zero-width characters inserted
        """
        result = []
        for i, char in enumerate(text):
            result.append(char)
            if i % 3 == 0 and i > 0:  # Insert every 3 chars (skip first)
                result.append(ZERO_WIDTH_CHARS[0])
        return "".join(result)

    def get_stats(self) -> dict[str, Any]:
        """Return mutation statistics.

        Returns:
            Dictionary with total, success, and failure counts
        """
        return self.stats.copy()
