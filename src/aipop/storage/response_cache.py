"""Response cache for verification test runs using DuckDB."""

from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import duckdb
except ImportError:
    duckdb = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


@dataclass
class CachedResponse:
    """Cached response from model."""

    prompt_hash: str
    model_id: str
    response: str
    timestamp: float
    tokens_used: int
    cost: float


class ResponseCache:
    """DuckDB-backed response cache with TTL and statistics."""

    def __init__(
        self,
        db_path: str | Path = "out/response_cache.duckdb",
        ttl_days: int = 7,
        ttl_seconds: int | None = None,
    ):
        """Initialize response cache.

        Args:
            db_path: Path to DuckDB database
            ttl_days: Time-to-live for cache entries in days (default: 7)
            ttl_seconds: Time-to-live in seconds (overrides ttl_days if provided)
        """
        if duckdb is None:
            raise ImportError(
                "DuckDB is required for this feature. "
                "Install with: pip install ai-purple-ops[intelligence]"
            )
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Support both ttl_days and ttl_seconds for backwards compatibility
        if ttl_seconds is not None:
            self.ttl_seconds = ttl_seconds
        else:
            self.ttl_seconds = ttl_days * 24 * 60 * 60

        self._init_db()

        # Statistics
        self.hits = 0
        self.misses = 0

    def _init_db(self):
        """Initialize database schema."""
        with duckdb.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS response_cache (
                    id INTEGER PRIMARY KEY,
                    prompt_hash VARCHAR NOT NULL,
                    model_id VARCHAR NOT NULL,
                    response TEXT NOT NULL,
                    timestamp DOUBLE NOT NULL,
                    tokens_used INTEGER DEFAULT 0,
                    cost DOUBLE DEFAULT 0.0,
                    UNIQUE(prompt_hash, model_id)
                )
            """
            )

            conn.execute(
                """
                CREATE SEQUENCE IF NOT EXISTS response_cache_id_seq START 1
            """
            )

            # Index for fast lookups
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_prompt_model 
                ON response_cache(prompt_hash, model_id)
            """
            )

            # Index for TTL cleanup
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_timestamp 
                ON response_cache(timestamp)
            """
            )

    def get_cached_response(self, prompt: str, model_id: str) -> CachedResponse | None:
        """Get cached response if available and not expired.

        Args:
            prompt: The prompt text
            model_id: Model identifier

        Returns:
            CachedResponse if found and valid, None otherwise
        """
        prompt_hash = self._hash_prompt(prompt)
        current_time = time.time()
        expiry_time = current_time - self.ttl_seconds

        with duckdb.connect(str(self.db_path)) as conn:
            result = conn.execute(
                """
                SELECT prompt_hash, model_id, response, timestamp, 
                       tokens_used, cost
                FROM response_cache
                WHERE prompt_hash = ? AND model_id = ? AND timestamp > ?
                """,
                [prompt_hash, model_id, expiry_time],
            ).fetchone()

            if result:
                self.hits += 1
                logger.debug(f"Cache HIT: {prompt_hash[:8]}... ({model_id})")
                return CachedResponse(
                    prompt_hash=result[0],
                    model_id=result[1],
                    response=result[2],
                    timestamp=result[3],
                    tokens_used=result[4],
                    cost=result[5],
                )
            else:
                self.misses += 1
                logger.debug(f"Cache MISS: {prompt_hash[:8]}... ({model_id})")
                return None

    def store_response(
        self,
        prompt: str,
        model_id: str,
        response: str,
        tokens_used: int = 0,
        cost: float = 0.0,
    ) -> None:
        """Store response in cache.

        Args:
            prompt: The prompt text
            model_id: Model identifier
            response: Model response
            tokens_used: Number of tokens used
            cost: API cost in dollars
        """
        prompt_hash = self._hash_prompt(prompt)
        current_time = time.time()

        with duckdb.connect(str(self.db_path)) as conn:
            # Upsert: replace if exists
            conn.execute(
                """
                INSERT INTO response_cache 
                (id, prompt_hash, model_id, response, timestamp, tokens_used, cost)
                VALUES (
                    nextval('response_cache_id_seq'), ?, ?, ?, ?, ?, ?
                )
                ON CONFLICT (prompt_hash, model_id) 
                DO UPDATE SET
                    response = excluded.response,
                    timestamp = excluded.timestamp,
                    tokens_used = excluded.tokens_used,
                    cost = excluded.cost
                """,
                [prompt_hash, model_id, response, current_time, tokens_used, cost],
            )

        logger.debug(f"Cached response: {prompt_hash[:8]}... ({model_id})")

    def cleanup_expired(self) -> int:
        """Remove expired cache entries.

        Returns:
            Number of entries removed
        """
        current_time = time.time()
        expiry_time = current_time - self.ttl_seconds

        with duckdb.connect(str(self.db_path)) as conn:
            result = conn.execute(
                """
                DELETE FROM response_cache
                WHERE timestamp < ?
                RETURNING id
                """,
                [expiry_time],
            ).fetchall()

            count = len(result)
            if count > 0:
                logger.info(f"Cleaned up {count} expired cache entries")
            return count

    def get_statistics(self) -> dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        with duckdb.connect(str(self.db_path)) as conn:
            total_entries = conn.execute("SELECT COUNT(*) FROM response_cache").fetchone()[0]

            total_tokens = (
                conn.execute("SELECT SUM(tokens_used) FROM response_cache").fetchone()[0] or 0
            )

            total_cost = conn.execute("SELECT SUM(cost) FROM response_cache").fetchone()[0] or 0.0

            unique_prompts = (
                conn.execute("SELECT COUNT(DISTINCT prompt_hash) FROM response_cache").fetchone()[0]
                or 0
            )

            unique_models = (
                conn.execute("SELECT COUNT(DISTINCT model_id) FROM response_cache").fetchone()[0]
                or 0
            )

            models = conn.execute(
                """
                SELECT model_id, COUNT(*), SUM(tokens_used), SUM(cost)
                FROM response_cache
                GROUP BY model_id
                """
            ).fetchall()

        hit_rate = self.hits / (self.hits + self.misses) if (self.hits + self.misses) > 0 else 0.0
        avg_cost_per_response = total_cost / total_entries if total_entries > 0 else 0.0

        return {
            "total_entries": total_entries,
            "hits": self.hits,
            "misses": self.misses,
            "hit_rate": hit_rate,
            "total_tokens": total_tokens,
            "total_cost": total_cost,
            "unique_prompts": unique_prompts,
            "unique_models": unique_models,
            "avg_cost_per_response": avg_cost_per_response,
            "by_model": [
                {
                    "model_id": model_id,
                    "entries": count,
                    "tokens": tokens,
                    "cost": cost,
                }
                for model_id, count, tokens, cost in models
            ],
        }

    def clear(self, model_id: str | None = None, older_than_seconds: float | None = None) -> int:
        """Clear cache entries.

        Args:
            model_id: Only clear entries for this model (default: all models)
            older_than_seconds: Only clear entries older than this (default: all ages)

        Returns:
            Number of entries removed
        """
        with duckdb.connect(str(self.db_path)) as conn:
            conditions = []
            params = []

            if model_id is not None:
                conditions.append("model_id = ?")
                params.append(model_id)

            if older_than_seconds is not None:
                cutoff_time = time.time() - older_than_seconds
                conditions.append("timestamp < ?")
                params.append(cutoff_time)

            where_clause = " AND ".join(conditions) if conditions else "1=1"
            query = f"DELETE FROM response_cache WHERE {where_clause} RETURNING id"

            result = conn.execute(query, params).fetchall()
            count = len(result)
            logger.info(f"Cleared {count} cache entries")
            return count

    def close(self) -> None:
        """Close cache database connection.

        Note: With context manager pattern, connections are auto-closed.
        This method is a no-op for backwards compatibility.
        """

    def _hash_prompt(self, prompt: str) -> str:
        """Generate hash for prompt.

        Args:
            prompt: Prompt text

        Returns:
            SHA256 hash of prompt
        """
        return hashlib.sha256(prompt.encode("utf-8")).hexdigest()
