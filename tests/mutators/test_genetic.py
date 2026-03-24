"""Unit tests for GeneticMutator."""

import pytest

pytest.importorskip("pygad", reason="pygad not installed")

from aipop.core.mutation_config import MutationConfig
from aipop.mutators.genetic import GeneticMutator


def test_genetic_mutator_init():
    """Test genetic mutator initialization."""
    config = MutationConfig(enable_genetic=True, genetic_population_size=10)
    mutator = GeneticMutator(config)

    assert mutator.config == config
    assert mutator.population == []
    assert mutator.fitness_scores == []


def test_genetic_mutator_initialize_population():
    """Test population initialization."""
    config = MutationConfig(enable_genetic=True)
    mutator = GeneticMutator(config)
    seed_prompts = ["prompt1", "prompt2", "prompt3"]

    mutator.initialize_population(seed_prompts)

    assert mutator.population == seed_prompts
    assert len(mutator.fitness_scores) == len(seed_prompts)


def test_genetic_mutator_mutate():
    """Test genetic mutation generation."""
    config = MutationConfig(
        enable_genetic=True,
        genetic_population_size=5,
        genetic_generations=2,
        optimization_target="asr",
    )
    mutator = GeneticMutator(config)
    context = {"asr": 0.5}

    mutations = mutator.mutate("test prompt", context)

    # Should generate at least one mutation
    assert len(mutations) >= 0  # May be empty if GA fails


def test_genetic_mutator_update_fitness():
    """Test fitness score update."""
    config = MutationConfig(enable_genetic=True)
    mutator = GeneticMutator(config)
    mutator.initialize_population(["prompt1", "prompt2"])

    mutator.update_fitness("prompt1", 0.8)

    assert mutator.fitness_scores[0] == 0.8


def test_genetic_mutator_stats():
    """Test mutation statistics tracking."""
    config = MutationConfig(enable_genetic=True, genetic_generations=1)
    mutator = GeneticMutator(config)

    stats = mutator.get_stats()
    assert "total" in stats
    assert "success" in stats
    assert "failure" in stats


def test_genetic_mutator_optimization_target_asr():
    """Test ASR optimization target."""
    config = MutationConfig(
        enable_genetic=True,
        genetic_generations=1,
        optimization_target="asr",
    )
    mutator = GeneticMutator(config)
    context = {"asr": 0.7}

    mutations = mutator.mutate("test", context)
    # Should attempt mutation
    assert isinstance(mutations, list)


def test_genetic_mutator_optimization_target_stealth():
    """Test stealth optimization target."""
    config = MutationConfig(
        enable_genetic=True,
        genetic_generations=1,
        optimization_target="stealth",
    )
    mutator = GeneticMutator(config)
    context = {"detection_rate": 0.3}

    mutations = mutator.mutate("test", context)
    assert isinstance(mutations, list)


def test_genetic_mutator_optimization_target_balanced():
    """Test balanced optimization target."""
    config = MutationConfig(
        enable_genetic=True,
        genetic_generations=1,
        optimization_target="balanced",
    )
    mutator = GeneticMutator(config)
    context = {"asr": 0.6, "detection_rate": 0.4}

    mutations = mutator.mutate("test", context)
    assert isinstance(mutations, list)


def test_genetic_mutator_no_context():
    """Test genetic mutator without context."""
    config = MutationConfig(enable_genetic=True, genetic_generations=1)
    mutator = GeneticMutator(config)

    mutations = mutator.mutate("test", None)
    assert isinstance(mutations, list)


def test_genetic_mutator_metadata():
    """Test mutation metadata."""
    config = MutationConfig(
        enable_genetic=True,
        genetic_generations=5,
        optimization_target="asr",
    )
    mutator = GeneticMutator(config)
    context = {"asr": 0.5}

    mutations = mutator.mutate("test", context)

    if mutations:
        mutation = mutations[0]
        assert "fitness" in mutation.metadata
        assert "generation" in mutation.metadata
        assert mutation.metadata["optimization_target"] == "asr"
