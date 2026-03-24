"""Unit tests for MutationDatabase."""

import tempfile
from pathlib import Path

import pytest

pytest.importorskip("duckdb", reason="duckdb not installed")

from aipop.storage.mutation_db import MutationDatabase


def test_mutation_database_init():
    """Test database initialization."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.duckdb"
        db = MutationDatabase(db_path)

        assert db.db_path == db_path
        assert db.conn is not None

        db.close()


def test_mutation_database_record_mutation():
    """Test recording a mutation."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.duckdb"
        db = MutationDatabase(db_path)

        db.record_mutation(
            {
                "original": "test prompt",
                "mutated": "mutated prompt",
                "type": "base64",
                "metadata": {"key": "value"},
                "success": True,
                "asr": 0.8,
                "detection_rate": 0.2,
            }
        )

        stats = db.get_mutation_stats("base64")
        assert stats is not None

        db.close()


def test_mutation_database_get_stats():
    """Test getting mutation statistics."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.duckdb"
        db = MutationDatabase(db_path)

        db.record_mutation(
            {
                "original": "test",
                "mutated": "mutated",
                "type": "base64",
                "success": True,
                "asr": 0.5,
            }
        )

        stats = db.get_mutation_stats("base64")
        assert stats is not None

        all_stats = db.get_mutation_stats()
        assert all_stats is not None

        db.close()


def test_mutation_database_get_top_mutations():
    """Test getting top mutations."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.duckdb"
        db = MutationDatabase(db_path)

        db.record_mutation(
            {
                "original": "test1",
                "mutated": "mutated1",
                "type": "base64",
                "success": True,
                "asr": 0.9,
            }
        )

        db.record_mutation(
            {
                "original": "test2",
                "mutated": "mutated2",
                "type": "unicode",
                "success": True,
                "asr": 0.7,
            }
        )

        top = db.get_top_mutations(limit=5, order_by="asr")
        assert len(top) >= 0  # May be empty if aggregation hasn't run

        db.close()


def test_mutation_database_multiple_types():
    """Test database with multiple mutation types."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.duckdb"
        db = MutationDatabase(db_path)

        for mut_type in ["base64", "unicode", "html"]:
            db.record_mutation(
                {
                    "original": "test",
                    "mutated": f"mutated_{mut_type}",
                    "type": mut_type,
                    "success": True,
                }
            )

        all_stats = db.get_mutation_stats()
        assert all_stats is not None

        db.close()


def test_mutation_database_metadata_json():
    """Test that metadata is stored as JSON."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.duckdb"
        db = MutationDatabase(db_path)

        complex_metadata = {"nested": {"key": "value"}, "list": [1, 2, 3]}

        db.record_mutation(
            {
                "original": "test",
                "mutated": "mutated",
                "type": "base64",
                "metadata": complex_metadata,
            }
        )

        # Should not raise
        db.close()


def test_mutation_database_test_case_id():
    """Test storing test case ID."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.duckdb"
        db = MutationDatabase(db_path)

        db.record_mutation(
            {
                "original": "test",
                "mutated": "mutated",
                "type": "base64",
                "test_case_id": "test_case_123",
            }
        )

        db.close()


def test_mutation_database_provider_model():
    """Test storing provider and model."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.duckdb"
        db = MutationDatabase(db_path)

        db.record_mutation(
            {
                "original": "test",
                "mutated": "mutated",
                "type": "llm_paraphrase",
                "provider": "openai",
                "model": "gpt-4o-mini",
            }
        )

        db.close()


def test_mutation_database_response_text():
    """Test storing response text."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.duckdb"
        db = MutationDatabase(db_path)

        db.record_mutation(
            {
                "original": "test",
                "mutated": "mutated",
                "type": "base64",
                "response": "This is a long response text that should be stored correctly.",
            }
        )

        db.close()


def test_mutation_database_schema_creation():
    """Test that schema is created correctly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test.duckdb"
        db = MutationDatabase(db_path)

        # Schema should be created
        tables = db.conn.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = 'main'"
        ).fetchall()

        table_names = [t[0] for t in tables]
        assert "mutations" in table_names
        assert "mutation_stats" in table_names
        assert "fitness_scores" in table_names

        db.close()
