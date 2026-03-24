"""Encoding-based mutation strategies."""

from __future__ import annotations

import base64
import urllib.parse

from aipop.core.mutators import MutationResult


class EncodingMutator:
    """Encoding-based mutations: Base64, URL, ROT13, hex."""

    def __init__(self) -> None:
        """Initialize encoding mutator with statistics tracking."""
        self.stats = {"total": 0, "success": 0, "failure": 0}

    def mutate(self, prompt: str, context: dict | None = None) -> list[MutationResult]:
        """Generate encoding-based mutations.

        Args:
            prompt: Original prompt text
            context: Optional context (unused for encoding mutations)

        Returns:
            List of mutation results with different encodings
        """
        mutations = []

        # Base64 encoding
        try:
            b64 = base64.b64encode(prompt.encode()).decode()
            mutations.append(
                MutationResult(
                    original=prompt,
                    mutated=f"Decode this Base64: {b64}",
                    mutation_type="base64",
                    metadata={"encoding": "base64"},
                )
            )
        except Exception:
            self.stats["failure"] += 1

        # URL encoding
        try:
            url_enc = urllib.parse.quote(prompt)
            mutations.append(
                MutationResult(
                    original=prompt,
                    mutated=f"URL decode: {url_enc}",
                    mutation_type="url_encoding",
                    metadata={"encoding": "url"},
                )
            )
        except Exception:
            self.stats["failure"] += 1

        # ROT13 encoding
        try:
            rot13 = prompt.translate(
                str.maketrans(
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
                    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
                )
            )
            mutations.append(
                MutationResult(
                    original=prompt,
                    mutated=f"ROT13: {rot13}",
                    mutation_type="rot13",
                    metadata={"encoding": "rot13"},
                )
            )
        except Exception:
            self.stats["failure"] += 1

        # Hex encoding
        try:
            hex_enc = prompt.encode().hex()
            mutations.append(
                MutationResult(
                    original=prompt,
                    mutated=f"Hex decode: {hex_enc}",
                    mutation_type="hex",
                    metadata={"encoding": "hex"},
                )
            )
        except Exception:
            self.stats["failure"] += 1

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
