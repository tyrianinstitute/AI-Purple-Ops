"""Integration tests for MutationEngine."""

import tempfile
from pathlib import Path

import pytest

pytest.importorskip("duckdb", reason="duckdb not installed")

from aipop.core.mutation_config import MutationConfig
from aipop.mutators.mutation_engine import MutationEngine


def test_mutation_engine_init():
    """Test mutation engine initialization."""
    config = MutationConfig()
    engine = MutationEngine(config)

    assert engine.config == config
    assert len(engine.mutators) >= 3  # encoding, unicode, html by default


def test_mutation_engine_mutate():
    """Test basic mutation generation."""
    config = MutationConfig()
    engine = MutationEngine(config)

    mutations = engine.mutate("test prompt")

    assert len(mutations) > 0
    assert all(hasattr(m, "original") for m in mutations)
    assert all(hasattr(m, "mutated") for m in mutations)


def test_mutation_engine_mutate_with_feedback():
    """Test mutation with RL feedback."""
    config = MutationConfig(enable_rl_feedback=True)
    engine = MutationEngine(config)

    mutations = engine.mutate_with_feedback("test prompt")

    assert len(mutations) > 0


def test_mutation_engine_mutate_without_feedback():
    """Test mutation without RL feedback."""
    config = MutationConfig(enable_rl_feedback=False)
    engine = MutationEngine(config)

    mutations = engine.mutate_with_feedback("test prompt")

    assert len(mutations) > 0


def test_mutation_engine_record_result():
    """Test recording mutation results."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.duckdb"
        config = MutationConfig(db_path=db_path, track_full_history=True)
        engine = MutationEngine(config)

        engine.record_result(
            {
                "original": "test",
                "mutated": "mutated test",
                "type": "base64",
                "metadata": {},
                "success": True,
            }
        )

        analytics = engine.get_analytics()
        assert analytics is not None


def test_mutation_engine_get_analytics():
    """Test getting mutation analytics."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.duckdb"
        config = MutationConfig(db_path=db_path)
        engine = MutationEngine(config)

        analytics = engine.get_analytics()

        assert "top_mutations" in analytics
        assert "mutation_stats" in analytics


def test_mutation_engine_close():
    """Test closing mutation engine."""
    config = MutationConfig()
    engine = MutationEngine(config)

    engine.close()  # Should not raise


def test_mutation_engine_paraphrasing_disabled():
    """Test mutation engine with paraphrasing disabled (no API key)."""
    config = MutationConfig(enable_paraphrasing=False)
    engine = MutationEngine(config)

    # Should not have paraphrasing mutator
    mutator_types = [m.__class__.__name__ for m in engine.mutators]
    assert "ParaphrasingMutator" not in mutator_types


def test_mutation_engine_genetic_disabled():
    """Test mutation engine with genetic algorithm disabled."""
    config = MutationConfig(enable_genetic=False)
    engine = MutationEngine(config)

    # Should not have genetic mutator
    mutator_types = [m.__class__.__name__ for m in engine.mutators]
    assert "GeneticMutator" not in mutator_types


def test_mutation_engine_custom_db_path():
    """Test mutation engine with custom database path."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "custom.duckdb"
        config = MutationConfig(db_path=db_path)
        engine = MutationEngine(config)

        assert engine.db.db_path == db_path


def test_mutation_engine_rl_selection():
    """Test RL-based mutator selection."""
    config = MutationConfig(enable_rl_feedback=True, rl_exploration_rate=0.0)
    engine = MutationEngine(config)

    # With exploration_rate=0, should always exploit (select top performers)
    mutations = engine.mutate_with_feedback("test")
    assert len(mutations) > 0
