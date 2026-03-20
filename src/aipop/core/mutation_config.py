"""Configuration system for mutation engine."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass
class MutationConfig:
    """Configuration for mutation engine behavior."""

    # Mutation strategies to enable
    enable_encoding: bool = True
    enable_unicode: bool = True
    enable_html: bool = True
    enable_paraphrasing: bool = False  # Requires API key
    enable_genetic: bool = False  # Requires population
    enable_gcg: bool = False  # GCG adversarial suffixes (opt-in, expensive)

    # LLM paraphrasing settings
    paraphrase_provider: str = "openai"  # openai, anthropic, ollama
    paraphrase_model: str | None = None  # auto-select if None
    paraphrase_api_key: str | None = None  # from env if None

    # Genetic algorithm settings
    genetic_population_size: int = 20
    genetic_generations: int = 10
    genetic_crossover_prob: float = 0.7
    genetic_mutation_prob: float = 0.3

    # GCG-specific configuration
    gcg_mode: str = "black-box"  # "white-box" or "black-box"
    gcg_use_library: bool = True  # Use pre-computed universal suffixes
    gcg_generate_on_demand: bool = False  # Generate new suffixes (slow)
    gcg_max_iterations: int = 100  # Max optimization iterations

    # Optimization target (configurable per test)
    optimization_target: str = "asr"  # asr, stealth, balanced

    # Feedback loop settings
    enable_rl_feedback: bool = True
    rl_learning_rate: float = 0.1
    rl_exploration_rate: float = 0.2

    # Storage settings
    db_path: Path = Path("out/mutations.duckdb")
    track_full_history: bool = True

    @classmethod
    def from_file(cls, path: Path) -> MutationConfig:
        """Load config from YAML.

        Args:
            path: Path to YAML config file

        Returns:
            MutationConfig instance (defaults if file doesn't exist)
        """
        if not path.exists():
            return cls()

        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}

        # Convert db_path string to Path if present
        if "db_path" in data and isinstance(data["db_path"], str):
            data["db_path"] = Path(data["db_path"])

        return cls(**{k: v for k, v in data.items() if k in cls.__annotations__})
