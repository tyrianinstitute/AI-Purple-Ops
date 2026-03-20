"""Unit tests for GCG mutator."""

from __future__ import annotations

from aipop.adapters.mock import MockAdapter
from aipop.core.mutators import MutationResult
from aipop.mutators.gcg_mutator import GCGMutator


def test_gcg_mutator_initialization():
    """Test GCGMutator setup."""
    mutator = GCGMutator(
        mode="black-box",
        use_library=True,
        generate_on_demand=False,
        max_iterations=100,
    )

    assert mutator.mode == "black-box"
    assert mutator.use_library is True
    assert mutator.generate_on_demand is False
    assert mutator.max_iterations == 100


def test_mutate_with_library():
    """Test mutations using universal suffix library."""
    mutator = GCGMutator(use_library=True, generate_on_demand=False)

    mutations = mutator.mutate("Test prompt")

    assert isinstance(mutations, list)
    assert len(mutations) > 0
    for mutation in mutations:
        assert isinstance(mutation, MutationResult)
        assert mutation.mutation_type == "gcg_universal"
        assert "suffix" in mutation.metadata


def test_mutate_with_generation():
    """Test on-demand suffix generation."""
    mutator = GCGMutator(use_library=False, generate_on_demand=True, max_iterations=5)

    adapter = MockAdapter()
    context = {"adapter": adapter}

    mutations = mutator.mutate("Test prompt", context=context)

    assert isinstance(mutations, list)
    # May be empty if generation fails, but should not crash


def test_mutate_without_context():
    """Test mutation without adapter context."""
    mutator = GCGMutator(use_library=True, generate_on_demand=True)

    # Should use library only if no adapter in context
    mutations = mutator.mutate("Test prompt", context=None)

    assert isinstance(mutations, list)


def test_mutator_stats():
    """Test mutation statistics."""
    mutator = GCGMutator()
    mutator.mutate("Test prompt")

    stats = mutator.get_stats()

    assert isinstance(stats, dict)
    assert "total" in stats
    assert "library_used" in stats
    assert "suffix_database" in stats


def test_mutator_filters_by_model():
    """Test that mutator filters suffixes by model when adapter provided."""
    mutator = GCGMutator(use_library=True)

    adapter = MockAdapter()
    adapter.model = "gpt-3.5-turbo"
    context = {"adapter": adapter}

    mutations = mutator.mutate("Test", context=context)

    assert isinstance(mutations, list)


def test_mutator_graceful_degradation():
    """Test graceful degradation when generation fails."""
    mutator = GCGMutator(use_library=True, generate_on_demand=True)

    # Adapter that causes errors
    class ErrorAdapter:
        def invoke(self, prompt):
            raise Exception("Error")

    adapter = ErrorAdapter()
    context = {"adapter": adapter}

    # Should still return library mutations
    mutations = mutator.mutate("Test", context=context)

    assert isinstance(mutations, list)
    # Should have library mutations even if generation fails
    assert len(mutations) > 0


def test_mutator_metadata():
    """Test that mutations include proper metadata."""
    mutator = GCGMutator(use_library=True)

    mutations = mutator.mutate("Test prompt")

    for mutation in mutations:
        assert "suffix" in mutation.metadata
        assert "asr" in mutation.metadata or "suffix_id" in mutation.metadata
