"""Unit tests for ResponseCache (DuckDB-backed caching)."""

from __future__ import annotations

import tempfile
import time
from pathlib import Path

import pytest

from aipop.storage.response_cache import CachedResponse, ResponseCache

# Note: ResponseCache uses different method names:
# - get_statistics() instead of get_cache_stats()
# - clear() instead of clear_cache()
# - CachedResponse has tokens_used not tokens


@pytest.fixture
def temp_cache_db():
    """Create temporary cache database."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as f:
        db_path = f.name

    # Delete the empty file so DuckDB can create a proper database
    Path(db_path).unlink(missing_ok=True)

    yield db_path

    # Cleanup
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def cache(temp_cache_db):
    """Create ResponseCache instance."""
    return ResponseCache(db_path=temp_cache_db)


# ============================================================================
# Initialization Tests
# ============================================================================


def test_cache_initialization(cache):
    """Test ResponseCache initializes correctly."""
    assert cache.db_path is not None
    assert cache.ttl_seconds > 0


def test_cache_creates_table(temp_cache_db):
    """Test cache creates table on initialization."""
    import duckdb

    cache = ResponseCache(db_path=temp_cache_db)

    # Query should work (table exists) - use DuckDB context manager
    with duckdb.connect(str(cache.db_path)) as conn:
        result = conn.execute(
            "SELECT table_name FROM information_schema.tables WHERE table_name='response_cache'"
        ).fetchone()

    assert result is not None


# ============================================================================
# Store and Retrieve Tests
# ============================================================================


def test_store_and_retrieve_response(cache):
    """Test storing and retrieving cached response."""
    prompt = "Test prompt"
    model_id = "test-model"
    response = "Test response"
    tokens = 100
    cost = 0.001

    # Store response
    cache.store_response(prompt, model_id, response, tokens, cost)

    # Retrieve response
    cached = cache.get_cached_response(prompt, model_id)

    assert cached is not None
    assert isinstance(cached, CachedResponse)
    assert cached.response == response
    assert cached.tokens_used == tokens
    assert cached.cost == cost


def test_cache_miss(cache):
    """Test cache miss returns None."""
    cached = cache.get_cached_response("nonexistent prompt", "test-model")

    assert cached is None


def test_cache_different_models(cache):
    """Test cache differentiates between models."""
    prompt = "Same prompt"
    response1 = "Response from model 1"
    response2 = "Response from model 2"

    # Store for two different models
    cache.store_response(prompt, "model-1", response1, 100, 0.001)
    cache.store_response(prompt, "model-2", response2, 100, 0.001)

    # Retrieve for each model
    cached1 = cache.get_cached_response(prompt, "model-1")
    cached2 = cache.get_cached_response(prompt, "model-2")

    assert cached1.response == response1
    assert cached2.response == response2


def test_cache_update_existing(cache):
    """Test updating existing cache entry."""
    prompt = "Test prompt"
    model_id = "test-model"

    # Store initial response
    cache.store_response(prompt, model_id, "Response 1", 100, 0.001)

    # Store updated response (same prompt + model)
    cache.store_response(prompt, model_id, "Response 2", 150, 0.002)

    # Should retrieve latest
    cached = cache.get_cached_response(prompt, model_id)
    assert cached.response == "Response 2"
    assert cached.tokens_used == 150


# ============================================================================
# TTL (Time To Live) Tests
# ============================================================================


def test_ttl_expiration(temp_cache_db):
    """Test entries expire after TTL."""
    # Create cache with 1-second TTL
    cache = ResponseCache(db_path=temp_cache_db, ttl_seconds=1)

    prompt = "Test prompt"
    model_id = "test-model"

    # Store response
    cache.store_response(prompt, model_id, "Response", 100, 0.001)

    # Should be cached immediately
    cached = cache.get_cached_response(prompt, model_id)
    assert cached is not None

    # Wait for TTL to expire
    time.sleep(1.5)

    # Should be expired now
    cached = cache.get_cached_response(prompt, model_id)
    assert cached is None


def test_ttl_custom_value(temp_cache_db):
    """Test cache with custom TTL."""
    # Long TTL (1 hour)
    cache = ResponseCache(db_path=temp_cache_db, ttl_seconds=3600)

    cache.store_response("prompt", "model", "response", 100, 0.001)

    # Should still be cached after 1 second
    time.sleep(1)
    cached = cache.get_cached_response("prompt", "model")
    assert cached is not None


# ============================================================================
# Cache Statistics Tests
# ============================================================================


def test_cache_stats_empty(cache):
    """Test cache stats with empty cache."""
    stats = cache.get_statistics()

    assert stats["total_entries"] == 0
    assert stats["total_tokens"] == 0
    assert stats["total_cost"] == 0.0
    assert stats["unique_prompts"] == 0
    assert stats["unique_models"] == 0


def test_cache_stats_with_entries(cache):
    """Test cache stats with multiple entries."""
    # Store multiple responses
    cache.store_response("prompt1", "model1", "response1", 100, 0.001)
    cache.store_response("prompt2", "model1", "response2", 150, 0.0015)
    cache.store_response("prompt1", "model2", "response3", 200, 0.002)

    stats = cache.get_statistics()

    assert stats["total_entries"] == 3
    assert stats["total_tokens"] == 450
    assert abs(stats["total_cost"] - 0.0045) < 0.0001  # Float precision
    assert stats["unique_prompts"] == 2  # prompt1, prompt2
    assert stats["unique_models"] == 2  # model1, model2


def test_cache_stats_average_cost(cache):
    """Test cache stats calculates average cost correctly."""
    cache.store_response("prompt1", "model", "response", 100, 0.001)
    cache.store_response("prompt2", "model", "response", 100, 0.003)

    stats = cache.get_statistics()

    # Average should be (0.001 + 0.003) / 2 = 0.002
    assert abs(stats["avg_cost_per_response"] - 0.002) < 0.0001


# ============================================================================
# Clear Cache Tests
# ============================================================================


def test_clear_cache(cache):
    """Test clearing entire cache."""
    # Store some responses
    cache.store_response("prompt1", "model", "response1", 100, 0.001)
    cache.store_response("prompt2", "model", "response2", 100, 0.001)

    # Verify they exist
    assert cache.get_cached_response("prompt1", "model") is not None
    assert cache.get_cached_response("prompt2", "model") is not None

    # Clear cache
    cache.clear()

    # Verify they're gone
    assert cache.get_cached_response("prompt1", "model") is None
    assert cache.get_cached_response("prompt2", "model") is None

    # Stats should be reset
    stats = cache.get_statistics()
    assert stats["total_entries"] == 0


def test_clear_cache_by_model(cache):
    """Test clearing cache for specific model."""
    # Store responses for multiple models
    cache.store_response("prompt", "model1", "response1", 100, 0.001)
    cache.store_response("prompt", "model2", "response2", 100, 0.001)

    # Clear only model1
    cache.clear(model_id="model1")

    # model1 should be cleared
    assert cache.get_cached_response("prompt", "model1") is None

    # model2 should remain
    assert cache.get_cached_response("prompt", "model2") is not None


def test_clear_cache_by_age(temp_cache_db):
    """Test clearing old cache entries."""
    cache = ResponseCache(db_path=temp_cache_db)

    # Store response
    cache.store_response("old_prompt", "model", "response", 100, 0.001)

    # Wait a bit
    time.sleep(1)

    # Store another response
    cache.store_response("new_prompt", "model", "response", 100, 0.001)

    # Clear entries older than 0.5 seconds
    cache.clear(older_than_seconds=0.5)

    # Old should be cleared, new should remain
    assert cache.get_cached_response("old_prompt", "model") is None
    assert cache.get_cached_response("new_prompt", "model") is not None


# ============================================================================
# Hash Collision Tests
# ============================================================================


def test_different_prompts_different_hashes(cache):
    """Test different prompts get different cache entries."""
    cache.store_response("prompt1", "model", "response1", 100, 0.001)
    cache.store_response("prompt2", "model", "response2", 100, 0.001)

    cached1 = cache.get_cached_response("prompt1", "model")
    cached2 = cache.get_cached_response("prompt2", "model")

    assert cached1.response == "response1"
    assert cached2.response == "response2"


def test_whitespace_sensitivity(cache):
    """Test cache is sensitive to whitespace."""
    cache.store_response("prompt", "model", "response1", 100, 0.001)
    cache.store_response("prompt ", "model", "response2", 100, 0.001)  # Extra space

    # Should be different entries
    cached1 = cache.get_cached_response("prompt", "model")
    cached2 = cache.get_cached_response("prompt ", "model")

    assert cached1.response == "response1"
    assert cached2.response == "response2"


# ============================================================================
# Persistence Tests
# ============================================================================


def test_cache_persists_across_instances(temp_cache_db):
    """Test cache persists when creating new instance."""
    # Create cache and store data
    cache1 = ResponseCache(db_path=temp_cache_db)
    cache1.store_response("prompt", "model", "response", 100, 0.001)
    cache1.close()

    # Create new cache instance with same DB
    cache2 = ResponseCache(db_path=temp_cache_db)
    cached = cache2.get_cached_response("prompt", "model")

    assert cached is not None
    assert cached.response == "response"

    cache2.close()


# ============================================================================
# Concurrent Access Tests
# ============================================================================


def test_multiple_stores_same_prompt(cache):
    """Test multiple stores to same prompt don't cause errors."""
    prompt = "same prompt"
    model = "model"

    # Store multiple times rapidly
    for i in range(10):
        cache.store_response(prompt, model, f"response{i}", 100, 0.001)

    # Should have the latest
    cached = cache.get_cached_response(prompt, model)
    assert cached is not None
    assert "response" in cached.response


# ============================================================================
# Edge Cases
# ============================================================================


def test_empty_prompt(cache):
    """Test caching empty prompt."""
    cache.store_response("", "model", "response", 100, 0.001)
    cached = cache.get_cached_response("", "model")

    assert cached is not None
    assert cached.response == "response"


def test_very_long_prompt(cache):
    """Test caching very long prompt."""
    long_prompt = "A" * 10000  # 10k characters
    cache.store_response(long_prompt, "model", "response", 100, 0.001)

    cached = cache.get_cached_response(long_prompt, "model")
    assert cached is not None


def test_unicode_prompt(cache):
    """Test caching prompt with Unicode characters."""
    prompt = "测试提示词 🔥 émoji"
    cache.store_response(prompt, "model", "response", 100, 0.001)

    cached = cache.get_cached_response(prompt, "model")
    assert cached is not None


def test_zero_cost(cache):
    """Test caching with zero cost."""
    cache.store_response("prompt", "model", "response", 0, 0.0)

    cached = cache.get_cached_response("prompt", "model")
    assert cached is not None
    assert cached.cost == 0.0


def test_close_and_reopen(temp_cache_db):
    """Test closing and reopening cache."""
    cache = ResponseCache(db_path=temp_cache_db)
    cache.store_response("prompt", "model", "response", 100, 0.001)
    cache.close()

    # Reopen
    cache = ResponseCache(db_path=temp_cache_db)
    cached = cache.get_cached_response("prompt", "model")
    assert cached is not None
    cache.close()
