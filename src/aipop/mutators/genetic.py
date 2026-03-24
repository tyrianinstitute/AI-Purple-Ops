"""Genetic algorithm-based mutation strategies."""

from __future__ import annotations

from typing import Any

from aipop.core.mutators import MutationResult

try:
    import pygad
except ImportError:
    pygad = None  # type: ignore


class GeneticMutator:
    """Genetic algorithm-based mutation using PyGAD."""

    def __init__(self, config) -> None:
        """Initialize genetic mutator.

        Args:
            config: MutationConfig instance with genetic algorithm settings
        """
        if pygad is None:
            raise ImportError(
                "PyGAD is required for genetic mutator. Install with: pip install pygad"
            )
        self.config = config
        self.population: list[str] = []
        self.fitness_scores: list[float] = []
        self.ga_instance: Any = None
        self.stats = {"total": 0, "success": 0, "failure": 0}

    def initialize_population(self, seed_prompts: list[str]) -> None:
        """Initialize GA population from seed prompts.

        Args:
            seed_prompts: List of seed prompt strings
        """
        self.population = seed_prompts.copy()
        self.fitness_scores = [0.0] * len(seed_prompts)

    def mutate(self, prompt: str, context: dict | None = None) -> list[MutationResult]:
        """Generate mutations using genetic algorithm.

        Args:
            prompt: Original prompt text
            context: Optional context with ASR/detection data

        Returns:
            List of mutation results with evolved prompts
        """
        if pygad is None:
            return []

        if not self.population:
            self.initialize_population([prompt])

        # Define fitness function (uses context for ASR/detection data)
        def fitness_func(ga, solution, solution_idx):
            """Calculate fitness based on optimization target."""
            target = self.config.optimization_target
            if target == "asr":
                # Higher fitness = higher attack success rate
                return context.get("asr", 0.0) if context else 0.0
            elif target == "stealth":
                # Higher fitness = lower detection rate
                return 1.0 - context.get("detection_rate", 1.0) if context else 0.0
            else:  # balanced
                asr = context.get("asr", 0.0) if context else 0.0
                stealth = 1.0 - context.get("detection_rate", 1.0) if context else 0.0
                return (asr + stealth) / 2.0

        # Convert prompt to list of character codes for PyGAD
        prompt_chars = list(prompt)
        num_genes = len(prompt_chars)

        if num_genes == 0:
            return []

        # Configure PyGAD with character-level genes
        try:
            # Create initial population as list of character lists
            initial_population = []
            for _ in range(self.config.genetic_population_size):
                # Start with original prompt, add some random variation
                pop_member = prompt_chars.copy()
                initial_population.append(pop_member)

            ga_instance = pygad.GA(
                num_generations=self.config.genetic_generations,
                num_parents_mating=self.config.genetic_population_size // 2,
                fitness_func=fitness_func,
                sol_per_pop=self.config.genetic_population_size,
                num_genes=num_genes,
                gene_type=list,  # List of characters
                initial_population=initial_population,
                crossover_probability=self.config.genetic_crossover_prob,
                mutation_probability=self.config.genetic_mutation_prob,
                mutation_type="random",
                gene_space=list(
                    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 !@#$%^&*()_+-=[]{}|;:,.<>?"
                ),
            )

            # Run evolution
            ga_instance.run()

            # Extract best solution
            solution, solution_fitness, solution_idx = ga_instance.best_solution()

            # Convert solution back to string
            mutated_prompt = "".join(solution) if isinstance(solution, list) else str(solution)

            mutations = [
                MutationResult(
                    original=prompt,
                    mutated=mutated_prompt,
                    mutation_type="genetic_best",
                    metadata={
                        "fitness": float(solution_fitness),
                        "generation": self.config.genetic_generations,
                        "optimization_target": self.config.optimization_target,
                    },
                )
            ]

            self.stats["success"] += 1
            self.stats["total"] += len(mutations)
            return mutations

        except Exception:
            self.stats["failure"] += 1
            return []

    def update_fitness(self, prompt: str, fitness: float) -> None:
        """Update fitness score for a prompt (RL feedback).

        Args:
            prompt: Prompt string
            fitness: Fitness score to assign
        """
        if prompt in self.population:
            idx = self.population.index(prompt)
            self.fitness_scores[idx] = fitness

    def get_stats(self) -> dict[str, Any]:
        """Return mutation statistics.

        Returns:
            Dictionary with total, success, and failure counts
        """
        return self.stats.copy()
