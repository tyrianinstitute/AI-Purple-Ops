"""LLM-assisted paraphrasing mutation strategies."""

from __future__ import annotations

import os
from typing import Any

from aipop.core.mutators import MutationResult


class ParaphrasingMutator:
    """LLM-assisted paraphrasing while maintaining semantic intent."""

    def __init__(
        self,
        provider: str = "openai",
        model: str | None = None,
        api_key: str | None = None,
    ) -> None:
        """Initialize paraphrasing mutator.

        Args:
            provider: LLM provider (openai, anthropic, ollama)
            model: Model name (auto-select if None)
            api_key: API key (from env if None)

        Raises:
            ValueError: If API key required but not found
        """
        self.provider = provider
        self.model = model
        self.api_key = api_key or self._get_api_key()
        self.adapter = self._create_adapter()
        self.stats = {"total": 0, "success": 0, "failure": 0, "api_errors": 0}

    def _get_api_key(self) -> str | None:
        """Get API key from environment.

        Returns:
            API key string or None
        """
        if self.provider == "openai":
            return os.getenv("OPENAI_API_KEY")
        elif self.provider == "anthropic":
            return os.getenv("ANTHROPIC_API_KEY")
        return None  # Ollama doesn't need API key

    def _create_adapter(self):
        """Create adapter for paraphrasing.

        Returns:
            Adapter instance

        Raises:
            ValueError: If API key required but not found
        """
        if self.provider == "openai":
            if not self.api_key:
                raise ValueError(
                    "OpenAI API key required for paraphrasing mutator. "
                    "Set OPENAI_API_KEY environment variable or pass api_key parameter. "
                    "Features requiring this: LLM paraphrasing, semantic mutation."
                )
            from aipop.adapters.openai import OpenAIAdapter

            return OpenAIAdapter(model=self.model or "gpt-4o-mini", api_key=self.api_key)

        elif self.provider == "anthropic":
            if not self.api_key:
                raise ValueError(
                    "Anthropic API key required for paraphrasing mutator. "
                    "Set ANTHROPIC_API_KEY environment variable or pass api_key parameter. "
                    "Features requiring this: LLM paraphrasing, semantic mutation."
                )
            from aipop.adapters.anthropic import AnthropicAdapter

            return AnthropicAdapter(
                model=self.model or "claude-3-5-haiku-20241022", api_key=self.api_key
            )

        elif self.provider == "ollama":
            # No API key needed for local Ollama
            from aipop.adapters.ollama import OllamaAdapter

            return OllamaAdapter(model=self.model or "llama3.1")

        else:
            raise ValueError(f"Unknown provider: {self.provider}")

    def mutate(self, prompt: str, context: dict | None = None) -> list[MutationResult]:
        """Generate paraphrased mutations using LLM.

        Args:
            prompt: Original prompt text
            context: Optional context (unused for paraphrasing)

        Returns:
            List of mutation results with paraphrased versions
        """
        mutations = []

        paraphrase_prompt = f"""Paraphrase the following text while maintaining its exact semantic meaning and intent. 
Generate 3 different variations that use different words and sentence structures but convey the same message.

Original: {prompt}

Generate exactly 3 paraphrases, one per line:"""

        try:
            response = self.adapter.invoke(paraphrase_prompt)
            paraphrases = response.text.strip().split("\n")

            for i, paraphrase in enumerate(paraphrases[:3]):  # Max 3
                paraphrase = paraphrase.strip()
                # Remove numbering if present (e.g., "1. ", "1) ")
                if paraphrase and any(
                    paraphrase.startswith(f"{j}") for j in ["1.", "2.", "3.", "1)", "2)", "3)"]
                ):
                    paraphrase = paraphrase.split(". ", 1)[-1].split(") ", 1)[-1]
                if paraphrase and paraphrase != prompt:
                    mutations.append(
                        MutationResult(
                            original=prompt,
                            mutated=paraphrase,
                            mutation_type="llm_paraphrase",
                            metadata={
                                "provider": self.provider,
                                "model": self.model or "auto",
                                "variation": i + 1,
                            },
                        )
                    )

            self.stats["success"] += 1

        except Exception:
            self.stats["api_errors"] += 1
            self.stats["failure"] += 1
            # Return empty list on error, don't crash

        self.stats["total"] += len(mutations)
        return mutations

    def get_stats(self) -> dict[str, Any]:
        """Return mutation statistics.

        Returns:
            Dictionary with total, success, failure, and api_errors counts
        """
        return self.stats.copy()
