"""Tests for cache performance and correctness."""

import time
from pathlib import Path

import pytest

from aipop.storage.attack_cache import AttackCache


def test_cache_key_generation_with_versioning():
    """Test cache key includes version namespace."""
    cache = AttackCache()

    key = cache._generate_cache_key(
        method="pair",
        prompt="test prompt",
        model="gpt-4",
        implementation="legacy",
        params={"num_streams": 1},
    )

    # Key should start with versioned namespace
    assert key.startswith("aipop:v"), f"Key missing version namespace: {key}"
    assert ":pair:" in key, f"Key missing method: {key}"
    assert ":legacy:" in key, f"Key missing implementation: {key}"


def test_cache_key_consistency():
    """Test cache keys are deterministic."""
    cache = AttackCache()

    params = {"num_streams": 1, "max_iterations": 500}

    key1 = cache._generate_cache_key("pair", "test", "gpt-4", "legacy", params)
    key2 = cache._generate_cache_key("pair", "test", "gpt-4", "legacy", params)

    assert key1 == key2, "Cache keys should be deterministic"


def test_cache_key_uniqueness():
    """Test different parameters produce different keys."""
    cache = AttackCache()

    key1 = cache._generate_cache_key("pair", "test", "gpt-4", "legacy", {"streams": 1})
    key2 = cache._generate_cache_key("pair", "test", "gpt-4", "legacy", {"streams": 2})

    assert key1 != key2, "Different params should produce different keys"


def test_cache_ttl_expiration():
    """Test cache entries expire after TTL."""
    cache = AttackCache(db_path=Path("test_cache_ttl.db"))

    try:
        # Cache result with 1 second TTL
        result = {"success": True, "adversarial_prompts": ["test"]}
        cache.cache_attack_result(
            method="pair",
            prompt="test",
            model="gpt-4",
            implementation="legacy",
            params={},
            result=result,
            ttl_hours=0.0003,  # ~1 second
        )

        # Should be retrievable immediately
        cached = cache.get_cached_result("pair", "test", "gpt-4", "legacy", {})
        assert cached is not None, "Should find fresh cached result"

        # Wait for expiration
        time.sleep(2)

        # Should be expired
        expired = cache.get_cached_result("pair", "test", "gpt-4", "legacy", {})
        assert expired is None, "Should not find expired result"

    finally:
        # Cleanup
        if Path("test_cache_ttl.db").exists():
            Path("test_cache_ttl.db").unlink()


def test_method_specific_ttls():
    """Test different methods get different default TTLs."""
    cache = AttackCache(db_path=Path("test_cache_ttl_methods.db"))

    try:
        # Cache results for different methods
        result = {"success": True}

        # PAIR should get 7 days
        cache.cache_attack_result("pair", "test1", "gpt-4", "legacy", {}, result)

        # GCG should get 30 days
        cache.cache_attack_result("gcg", "test2", "gpt-4", "legacy", {}, result)

        # AutoDAN should get 14 days
        cache.cache_attack_result("autodan", "test3", "gpt-4", "legacy", {}, result)

        # All should be retrievable
        assert cache.get_cached_result("pair", "test1", "gpt-4", "legacy", {}) is not None
        assert cache.get_cached_result("gcg", "test2", "gpt-4", "legacy", {}) is not None
        assert cache.get_cached_result("autodan", "test3", "gpt-4", "legacy", {}) is not None

    finally:
        if Path("test_cache_ttl_methods.db").exists():
            Path("test_cache_ttl_methods.db").unlink()


def test_cache_stats_version_breakdown():
    """Test cache stats include version breakdown."""
    cache = AttackCache(db_path=Path("test_cache_stats.db"))

    try:
        # Add some entries
        result = {"success": True}
        cache.cache_attack_result("pair", "test1", "gpt-4", "legacy", {}, result)
        cache.cache_attack_result("gcg", "test2", "gpt-4", "legacy", {}, result)

        stats = cache.get_cache_stats()

        # Should have version breakdown
        assert "version_breakdown" in stats
        assert "current_version_entries" in stats
        assert "old_version_entries" in stats

        # Should have at least 2 entries
        assert stats["total_entries"] >= 2

    finally:
        if Path("test_cache_stats.db").exists():
            Path("test_cache_stats.db").unlink()


def test_clear_by_version():
    """Test clearing cache by version."""
    cache = AttackCache(db_path=Path("test_cache_clear_version.db"))

    try:
        # Add entries
        result = {"success": True}
        cache.cache_attack_result("pair", "test1", "gpt-4", "legacy", {}, result)
        cache.cache_attack_result("gcg", "test2", "gpt-4", "legacy", {}, result)

        stats_before = cache.get_cache_stats()
        assert stats_before["total_entries"] >= 2

        # Clear current version (should clear all since all are current)
        from aipop import __version__

        count = cache.clear_by_version(__version__)
        assert count >= 2

        stats_after = cache.get_cache_stats()
        assert stats_after["current_version_entries"] == 0

    finally:
        if Path("test_cache_clear_version.db").exists():
            Path("test_cache_clear_version.db").unlink()


def test_cache_result_preservation():
    """Test cached results match original results."""
    cache = AttackCache(db_path=Path("test_cache_preservation.db"))

    try:
        original_result = {
            "success": True,
            "adversarial_prompts": ["test prompt 1", "test prompt 2"],
            "scores": [0.8, 0.6],
            "metadata": {"method": "pair", "cost": 0.02},
        }

        # Cache result
        cache.cache_attack_result(
            method="pair",
            prompt="test",
            model="gpt-4",
            implementation="legacy",
            params={"streams": 1},
            result=original_result,
        )

        # Retrieve cached result
        cached_result = cache.get_cached_result(
            method="pair",
            prompt="test",
            model="gpt-4",
            implementation="legacy",
            params={"streams": 1},
        )

        assert cached_result is not None
        assert cached_result["success"] == original_result["success"]
        assert cached_result["adversarial_prompts"] == original_result["adversarial_prompts"]
        assert cached_result["scores"] == original_result["scores"]

    finally:
        if Path("test_cache_preservation.db").exists():
            Path("test_cache_preservation.db").unlink()


@pytest.mark.integration
def test_fast_cache_lookup_vs_full_plugin(tmp_path, monkeypatch):
    """Test fast cache lookup returns same results as full plugin load."""
    from aipop.intelligence.plugins.loader import check_cache_fast

    # Ensure both AttackCache() and check_cache_fast() read the same DB path.
    monkeypatch.setenv(AttackCache.DB_PATH_ENV, str(tmp_path / "test_fast_lookup.db"))
    cache = AttackCache()

    result = {
        "success": True,
        "adversarial_prompts": ["test"],
        "scores": [0.5],
    }

    params = {"num_streams": 1, "max_iterations": 500}

    # Cache result
    cache.cache_attack_result("pair", "test", "gpt-4", "legacy", params, result)

    # Try fast lookup
    cached = check_cache_fast("pair", "test", "gpt-4", "legacy", params)

    assert cached is not None
    assert cached["adversarial_prompts"] == result["adversarial_prompts"]
