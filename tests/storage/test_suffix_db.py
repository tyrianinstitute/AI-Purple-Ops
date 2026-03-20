"""Unit tests for suffix database."""

from __future__ import annotations

import pytest

from aipop.storage.suffix_db import SuffixDatabase


@pytest.fixture
def temp_db(tmp_path):
    """Create temporary database for testing."""
    db_path = tmp_path / "test_suffixes.duckdb"
    db = SuffixDatabase(db_path)
    yield db
    db.close()


def test_suffix_db_initialization(temp_db):
    """Test SuffixDatabase setup."""
    assert temp_db.db_path.exists() or str(temp_db.db_path) == ":memory:"
    assert temp_db.conn is not None


def test_store_suffix(temp_db):
    """Test storing suffixes."""
    suffix_data = {
        "id": "test_001",
        "suffix_text": "test suffix",
        "prompt": "test prompt",
        "target": "Sure",
        "asr": 0.85,
        "model_id": "gpt-3.5-turbo",
        "generation_method": "gcg",
        "mode": "black-box",
        "iterations": 100,
        "metadata": {"test": "data"},
        "verified": True,
    }

    temp_db.store_suffix(suffix_data)

    # Verify stored
    stats = temp_db.get_suffix_stats()
    assert stats["total_suffixes"] >= 1


def test_get_top_suffixes(temp_db):
    """Test retrieving best suffixes."""
    # Store multiple suffixes with different ASR
    for i in range(5):
        temp_db.store_suffix(
            {
                "id": f"test_{i}",
                "suffix_text": f"suffix {i}",
                "prompt": "test",
                "asr": 0.5 + (i * 0.1),  # 0.5, 0.6, 0.7, 0.8, 0.9
                "model_id": "gpt-3.5-turbo",
                "generation_method": "gcg",
            }
        )

    top_suffixes = temp_db.get_top_suffixes(
        min_asr=0.69, limit=10
    )  # Use 0.69 to account for floating point precision

    assert (
        len(top_suffixes) >= 3
    )  # Should get suffixes with ASR >= 0.7 (accounting for float precision)
    # Should be ordered by ASR descending
    if len(top_suffixes) > 1:
        asrs = [s["asr"] for s in top_suffixes]
        assert asrs == sorted(asrs, reverse=True)


def test_get_top_suffixes_filter_by_model(temp_db):
    """Test filtering by model ID."""
    temp_db.store_suffix(
        {
            "id": "test_1",
            "suffix_text": "suffix 1",
            "prompt": "test",
            "asr": 0.9,
            "model_id": "gpt-3.5-turbo",
            "generation_method": "gcg",
        }
    )
    temp_db.store_suffix(
        {
            "id": "test_2",
            "suffix_text": "suffix 2",
            "prompt": "test",
            "asr": 0.8,
            "model_id": "gpt-4",
            "generation_method": "gcg",
        }
    )

    gpt35_suffixes = temp_db.get_top_suffixes(model_id="gpt-3.5-turbo")
    assert len(gpt35_suffixes) >= 1
    assert all(s["model_id"] == "gpt-3.5-turbo" for s in gpt35_suffixes)


def test_get_top_suffixes_filter_by_method(temp_db):
    """Test filtering by generation method."""
    temp_db.store_suffix(
        {
            "id": "test_gcg",
            "suffix_text": "gcg suffix",
            "prompt": "test",
            "asr": 0.9,
            "generation_method": "gcg",
        }
    )
    temp_db.store_suffix(
        {
            "id": "test_autodan",
            "suffix_text": "autodan suffix",
            "prompt": "test",
            "asr": 0.8,
            "generation_method": "autodan",
        }
    )

    gcg_suffixes = temp_db.get_top_suffixes(generation_method="gcg")
    assert len(gcg_suffixes) >= 1
    assert all(s["generation_method"] == "gcg" for s in gcg_suffixes)


def test_suffix_stats(temp_db):
    """Test analytics queries."""
    # Store multiple suffixes
    for i in range(3):
        temp_db.store_suffix(
            {
                "id": f"test_{i}",
                "suffix_text": f"suffix {i}",
                "prompt": "test",
                "asr": 0.7 + (i * 0.1),
                "model_id": f"model_{i % 2}",
                "generation_method": "gcg" if i % 2 == 0 else "autodan",
            }
        )

    stats = temp_db.get_suffix_stats()

    assert "total_suffixes" in stats
    assert "avg_asr" in stats
    assert "by_model" in stats
    assert "by_method" in stats
    assert "top_suffixes" in stats

    assert stats["total_suffixes"] >= 3
    assert isinstance(stats["avg_asr"], float)


def test_suffix_stats_by_model(temp_db):
    """Test statistics grouped by model."""
    temp_db.store_suffix(
        {
            "id": "test_1",
            "suffix_text": "suffix",
            "prompt": "test",
            "asr": 0.9,
            "model_id": "gpt-3.5-turbo",
            "generation_method": "gcg",
        }
    )

    stats = temp_db.get_suffix_stats()

    assert "gpt-3.5-turbo" in stats["by_model"]
    model_stats = stats["by_model"]["gpt-3.5-turbo"]
    assert "count" in model_stats
    assert "avg_asr" in model_stats


def test_suffix_stats_by_method(temp_db):
    """Test statistics grouped by generation method."""
    temp_db.store_suffix(
        {
            "id": "test_1",
            "suffix_text": "suffix",
            "prompt": "test",
            "asr": 0.9,
            "generation_method": "gcg",
        }
    )

    stats = temp_db.get_suffix_stats()

    assert "gcg" in stats["by_method"]
    method_stats = stats["by_method"]["gcg"]
    assert "count" in method_stats
    assert "avg_asr" in method_stats


def test_store_suffix_metadata_json(temp_db):
    """Test that metadata is stored as JSON."""
    metadata = {"key1": "value1", "key2": 123}
    temp_db.store_suffix(
        {
            "id": "test_meta",
            "suffix_text": "suffix",
            "prompt": "test",
            "metadata": metadata,
        }
    )

    top_suffixes = temp_db.get_top_suffixes(
        min_asr=0.0, limit=1
    )  # Use min_asr=0.0 to include suffixes with default ASR
    assert len(top_suffixes) >= 1
    stored_meta = top_suffixes[0]["metadata"]
    assert isinstance(stored_meta, dict)
    assert stored_meta["key1"] == "value1"


def test_get_top_suffixes_limit(temp_db):
    """Test limit parameter."""
    # Store 10 suffixes
    for i in range(10):
        temp_db.store_suffix(
            {
                "id": f"test_{i}",
                "suffix_text": f"suffix {i}",
                "prompt": "test",
                "asr": 0.5 + (i * 0.05),
            }
        )

    top_5 = temp_db.get_top_suffixes(limit=5)
    assert len(top_5) <= 5


def test_min_asr_filtering(temp_db):
    """Test minimum ASR filtering."""
    temp_db.store_suffix(
        {
            "id": "high_asr",
            "suffix_text": "high",
            "prompt": "test",
            "asr": 0.9,
        }
    )
    temp_db.store_suffix(
        {
            "id": "low_asr",
            "suffix_text": "low",
            "prompt": "test",
            "asr": 0.3,
        }
    )

    high_asr_suffixes = temp_db.get_top_suffixes(min_asr=0.8)
    assert len(high_asr_suffixes) >= 1
    assert all(s["asr"] >= 0.8 for s in high_asr_suffixes)
