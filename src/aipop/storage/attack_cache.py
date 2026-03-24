"""Attack cache for AutoDAN and PAIR results using DuckDB.

Caches expensive attack operations to reduce API costs and improve performance.
Supports both DuckDB storage and JSON export for portability.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
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
class AutoDANCacheEntry:
    """Cached AutoDAN result."""

    prompt_hash: str
    prompt: str
    response: str
    fitness: float
    generation: int
    timestamp: float
    cost_usd: float


@dataclass
class PAIRCacheEntry:
    """Cached PAIR result."""

    conversation_hash: str
    attacker_model: str
    history: list[dict[str, Any]]
    final_prompt: str
    success: bool
    num_iterations: int
    timestamp: float
    cost_usd: float


class AttackCache:
    """DuckDB cache for expensive attack operations."""

    # Single source of truth for cache location when callers don't pass db_path.
    # Tests can set this to isolate cache DBs under tmp paths.
    DB_PATH_ENV = "AIPOP_ATTACK_CACHE_DB"

    def __init__(self, db_path: str | Path | None = None):
        """Initialize attack cache.

        Args:
            db_path: Path to DuckDB database
        """
        if duckdb is None:
            raise ImportError(
                "DuckDB is required for this feature. "
                "Install with: pip install ai-purple-ops[intelligence]"
            )
        if db_path is None:
            db_path = os.getenv(self.DB_PATH_ENV) or "out/attack_cache.duckdb"
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _init_tables(self):
        """Initialize database schema."""
        with duckdb.connect(str(self.db_path)) as conn:
            # AutoDAN cache table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS autodan_cache (
                    prompt_hash VARCHAR PRIMARY KEY,
                    prompt TEXT NOT NULL,
                    response TEXT,
                    fitness DOUBLE,
                    generation INT,
                    timestamp DOUBLE NOT NULL,
                    cost_usd DOUBLE DEFAULT 0.0
                )
            """
            )

            # PAIR cache table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS pair_cache (
                    conversation_hash VARCHAR PRIMARY KEY,
                    attacker_model VARCHAR NOT NULL,
                    history JSON,
                    final_prompt TEXT,
                    success BOOLEAN,
                    num_iterations INT,
                    timestamp DOUBLE NOT NULL,
                    cost_usd DOUBLE DEFAULT 0.0
                )
            """
            )

            # Generalized attack results cache (for all methods)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS attack_results_cache (
                    cache_key VARCHAR PRIMARY KEY,
                    method VARCHAR NOT NULL,
                    prompt TEXT NOT NULL,
                    model VARCHAR NOT NULL,
                    implementation VARCHAR NOT NULL,
                    params JSON,
                    result JSON NOT NULL,
                    timestamp DOUBLE NOT NULL,
                    expires_at DOUBLE NOT NULL,
                    cost_usd DOUBLE DEFAULT 0.0
                )
            """
            )

            # Indexes for fast lookups
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_autodan_hash 
                ON autodan_cache(prompt_hash)
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_cache_expires 
                ON attack_results_cache(expires_at)
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_cache_method 
                ON attack_results_cache(method, model)
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_pair_hash 
                ON pair_cache(conversation_hash)
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_autodan_timestamp 
                ON autodan_cache(timestamp)
            """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_pair_timestamp 
                ON pair_cache(timestamp)
            """
            )

    def get_autodan_response(self, prompt: str) -> AutoDANCacheEntry | None:
        """Get cached AutoDAN response if available.

        Args:
            prompt: Prompt text

        Returns:
            Cached entry if found, None otherwise
        """
        prompt_hash = self._hash_prompt(prompt)

        with duckdb.connect(str(self.db_path)) as conn:
            result = conn.execute(
                """
                SELECT prompt_hash, prompt, response, fitness, generation, timestamp, cost_usd
                FROM autodan_cache
                WHERE prompt_hash = ?
            """,
                [prompt_hash],
            ).fetchone()

            if result:
                logger.debug(f"Cache HIT: AutoDAN {prompt_hash[:8]}...")
                return AutoDANCacheEntry(
                    prompt_hash=result[0],
                    prompt=result[1],
                    response=result[2] or "",
                    fitness=result[3] or 0.0,
                    generation=result[4] or 0,
                    timestamp=result[5],
                    cost_usd=result[6] or 0.0,
                )

            logger.debug(f"Cache MISS: AutoDAN {prompt_hash[:8]}...")
            return None

    def store_autodan_response(
        self,
        prompt: str,
        response: str,
        fitness: float,
        generation: int,
        cost_usd: float = 0.0,
    ) -> None:
        """Store AutoDAN response in cache.

        Args:
            prompt: Prompt text
            response: Model response
            fitness: Fitness score
            generation: Generation number
            cost_usd: API cost
        """
        prompt_hash = self._hash_prompt(prompt)
        timestamp = time.time()

        with duckdb.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                INSERT INTO autodan_cache 
                (prompt_hash, prompt, response, fitness, generation, timestamp, cost_usd)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (prompt_hash) 
                DO UPDATE SET
                    response = excluded.response,
                    fitness = excluded.fitness,
                    generation = excluded.generation,
                    timestamp = excluded.timestamp,
                    cost_usd = excluded.cost_usd
            """,
                [prompt_hash, prompt, response, fitness, generation, timestamp, cost_usd],
            )

        logger.debug(f"Cached AutoDAN response: {prompt_hash[:8]}...")

    def get_pair_response(
        self, objective: str, attacker_model: str, history: list[dict[str, Any]]
    ) -> PAIRCacheEntry | None:
        """Get cached PAIR response if available.

        Args:
            objective: Attack objective
            attacker_model: Attacker model name
            history: Conversation history

        Returns:
            Cached entry if found, None otherwise
        """
        # Create hash from objective + attacker + history signature
        history_sig = json.dumps(history, sort_keys=True)
        conversation_key = f"{objective}:{attacker_model}:{history_sig}"
        conversation_hash = self._hash_prompt(conversation_key)

        with duckdb.connect(str(self.db_path)) as conn:
            result = conn.execute(
                """
                SELECT conversation_hash, attacker_model, history, final_prompt, 
                       success, num_iterations, timestamp, cost_usd
                FROM pair_cache
                WHERE conversation_hash = ?
            """,
                [conversation_hash],
            ).fetchone()

            if result:
                logger.debug(f"Cache HIT: PAIR {conversation_hash[:8]}...")
                return PAIRCacheEntry(
                    conversation_hash=result[0],
                    attacker_model=result[1],
                    history=json.loads(result[2]) if result[2] else [],
                    final_prompt=result[3] or "",
                    success=result[4] or False,
                    num_iterations=result[5] or 0,
                    timestamp=result[6],
                    cost_usd=result[7] or 0.0,
                )

            logger.debug(f"Cache MISS: PAIR {conversation_hash[:8]}...")
            return None

    def store_pair_response(
        self,
        objective: str,
        attacker_model: str,
        history: list[dict[str, Any]],
        final_prompt: str,
        success: bool,
        num_iterations: int,
        cost_usd: float = 0.0,
    ) -> None:
        """Store PAIR response in cache.

        Args:
            objective: Attack objective
            attacker_model: Attacker model name
            history: Conversation history
            final_prompt: Final prompt used
            success: Whether attack succeeded
            num_iterations: Number of iterations
            cost_usd: API cost
        """
        history_sig = json.dumps(history, sort_keys=True)
        conversation_key = f"{objective}:{attacker_model}:{history_sig}"
        conversation_hash = self._hash_prompt(conversation_key)
        timestamp = time.time()

        with duckdb.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                INSERT INTO pair_cache 
                (conversation_hash, attacker_model, history, final_prompt, 
                 success, num_iterations, timestamp, cost_usd)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (conversation_hash) 
                DO UPDATE SET
                    history = excluded.history,
                    final_prompt = excluded.final_prompt,
                    success = excluded.success,
                    num_iterations = excluded.num_iterations,
                    timestamp = excluded.timestamp,
                    cost_usd = excluded.cost_usd
            """,
                [
                    conversation_hash,
                    attacker_model,
                    json.dumps(history),
                    final_prompt,
                    success,
                    num_iterations,
                    timestamp,
                    cost_usd,
                ],
            )

        logger.debug(f"Cached PAIR response: {conversation_hash[:8]}...")

    def export_to_json(self, output_path: Path) -> None:
        """Export cache to JSON for portability.

        Args:
            output_path: Path to output JSON file
        """
        with duckdb.connect(str(self.db_path)) as conn:
            # Export AutoDAN cache
            autodan_df = conn.execute("SELECT * FROM autodan_cache").df()
            autodan_records = autodan_df.to_dict("records")

            # Export PAIR cache
            pair_df = conn.execute("SELECT * FROM pair_cache").df()
            pair_records = pair_df.to_dict("records")

        # Write to JSON
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(
                {
                    "autodan": autodan_records,
                    "pair": pair_records,
                },
                f,
                indent=2,
                default=str,  # Handle datetime/timestamp
            )

        logger.info(f"Exported cache to {output_path}")

    def clear_autodan_cache(self) -> int:
        """Clear all AutoDAN cache entries.

        Returns:
            Number of entries removed
        """
        with duckdb.connect(str(self.db_path)) as conn:
            result = conn.execute("DELETE FROM autodan_cache RETURNING prompt_hash").fetchall()
            count = len(result)
            logger.info(f"Cleared {count} AutoDAN cache entries")
            return count

    def clear_pair_cache(self) -> int:
        """Clear all PAIR cache entries.

        Returns:
            Number of entries removed
        """
        with duckdb.connect(str(self.db_path)) as conn:
            result = conn.execute("DELETE FROM pair_cache RETURNING conversation_hash").fetchall()
            count = len(result)
            logger.info(f"Cleared {count} PAIR cache entries")
            return count

    def cleanup_expired(self, ttl_days: int = 7) -> int:
        """Remove expired cache entries.

        Args:
            ttl_days: Time-to-live in days

        Returns:
            Number of entries removed
        """
        current_time = time.time()
        expiry_time = current_time - (ttl_days * 24 * 60 * 60)

        with duckdb.connect(str(self.db_path)) as conn:
            autodan_result = conn.execute(
                "DELETE FROM autodan_cache WHERE timestamp < ? RETURNING prompt_hash",
                [expiry_time],
            ).fetchall()

            pair_result = conn.execute(
                "DELETE FROM pair_cache WHERE timestamp < ? RETURNING conversation_hash",
                [expiry_time],
            ).fetchall()

            count = len(autodan_result) + len(pair_result)
            if count > 0:
                logger.info(f"Cleaned up {count} expired cache entries")
            return count

    def get_statistics(self) -> dict[str, Any]:
        """Get cache statistics.

        Returns:
            Dictionary with cache stats
        """
        with duckdb.connect(str(self.db_path)) as conn:
            autodan_count = conn.execute("SELECT COUNT(*) FROM autodan_cache").fetchone()[0]
            pair_count = conn.execute("SELECT COUNT(*) FROM pair_cache").fetchone()[0]

            autodan_cost = (
                conn.execute("SELECT SUM(cost_usd) FROM autodan_cache").fetchone()[0] or 0.0
            )
            pair_cost = conn.execute("SELECT SUM(cost_usd) FROM pair_cache").fetchone()[0] or 0.0

        return {
            "autodan_entries": autodan_count,
            "pair_entries": pair_count,
            "total_entries": autodan_count + pair_count,
            "autodan_cost": autodan_cost,
            "pair_cost": pair_cost,
            "total_cost": autodan_cost + pair_cost,
        }

    def _hash_prompt(self, prompt: str) -> str:
        """Generate hash for prompt.

        Args:
            prompt: Prompt text

        Returns:
            SHA256 hash
        """
        return hashlib.sha256(prompt.encode("utf-8")).hexdigest()

    # Generalized caching methods for all attack types

    def cache_attack_result(
        self,
        method: str,
        prompt: str,
        model: str,
        implementation: str,
        params: dict[str, Any],
        result: Any,
        ttl_hours: int | None = None,
    ) -> str:
        """Cache attack result with method-specific TTL.

        Args:
            method: Attack method (pair, gcg, autodan)
            prompt: Target prompt
            model: Target model
            implementation: official or legacy
            params: Attack parameters (streams, iterations, etc)
            result: Attack result to cache (AttackResult object)
            ttl_hours: Time to live in hours (if None, uses method-specific default)

        Returns:
            Cache key (hash)
        """
        # Method-specific TTLs based on attack cost and volatility
        method_ttls = {
            "pair": 24 * 7,  # 7 days - expensive API-based attacks
            "gcg": 24 * 30,  # 30 days - deterministic local GPU attacks
            "autodan": 24 * 14,  # 14 days - moderate cost GA-based attacks
        }

        if ttl_hours is None:
            ttl_hours = method_ttls.get(method, 24 * 7)  # Default to 7 days

        cache_key = self._generate_cache_key(method, prompt, model, implementation, params)

        # Serialize result to JSON
        if hasattr(result, "__dict__"):
            result_dict = result.__dict__
        else:
            result_dict = result

        cost = (
            result_dict.get("metadata", {}).get("cost", 0.0)
            if isinstance(result_dict, dict)
            else 0.0
        )

        with duckdb.connect(str(self.db_path)) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO attack_results_cache 
                (cache_key, method, prompt, model, implementation, params, result, timestamp, expires_at, cost_usd)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    cache_key,
                    method,
                    prompt,
                    model,
                    implementation,
                    json.dumps(params),
                    json.dumps(result_dict),
                    time.time(),
                    time.time() + (ttl_hours * 3600),
                    cost,
                ],
            )

        logger.info(f"Cached {method} result for {model} (key: {cache_key[:12]}...)")
        return cache_key

    def get_cached_result(
        self,
        method: str,
        prompt: str,
        model: str,
        implementation: str,
        params: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Retrieve cached result if not expired.

        Args:
            method: Attack method
            prompt: Target prompt
            model: Target model
            implementation: official or legacy
            params: Attack parameters

        Returns:
            Cached result dict or None if not found/expired
        """
        cache_key = self._generate_cache_key(method, prompt, model, implementation, params)

        with duckdb.connect(str(self.db_path)) as conn:
            result = conn.execute(
                """
                SELECT result, expires_at, cost_usd FROM attack_results_cache
                WHERE cache_key = ? AND expires_at > ?
                """,
                [cache_key, time.time()],
            ).fetchone()

            if result:
                result_json, expires_at, cost = result
                logger.info(f"Cache hit for {method}/{model} (saved ${cost:.4f})")
                return json.loads(result_json)

        return None

    def _generate_cache_key(
        self,
        method: str,
        prompt: str,
        model: str,
        implementation: str,
        params: dict[str, Any],
    ) -> str:
        """Generate deterministic cache key with versioning.

        Args:
            method: Attack method
            prompt: Target prompt
            model: Target model
            implementation: official or legacy
            params: Attack parameters

        Returns:
            Namespaced cache key: aipop:v{VERSION}:{method}:{hash}
        """
        # Get tool version
        from aipop import __version__

        # Sort params for consistent hashing
        sorted_params = json.dumps(params, sort_keys=True)

        # Create hash of prompt + model + params
        hash_input = f"{prompt}:{model}:{implementation}:{sorted_params}"
        content_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

        # Format: aipop:v{VERSION}:{method}:{implementation}:{hash}
        cache_key = f"aipop:v{__version__}:{method}:{implementation}:{content_hash}"

        return cache_key

    def get_cache_stats(self) -> dict[str, Any]:
        """Get comprehensive cache statistics including version breakdown.

        Returns:
            Dictionary with cache stats including hit rate and cost savings
        """
        with duckdb.connect(str(self.db_path)) as conn:
            # General results cache
            results_count = conn.execute("SELECT COUNT(*) FROM attack_results_cache").fetchone()[0]
            results_valid = conn.execute(
                "SELECT COUNT(*) FROM attack_results_cache WHERE expires_at > ?",
                [time.time()],
            ).fetchone()[0]
            results_cost = (
                conn.execute(
                    "SELECT SUM(cost_usd) FROM attack_results_cache WHERE expires_at > ?",
                    [time.time()],
                ).fetchone()[0]
                or 0.0
            )

            # Version breakdown (extract version from cache_key)
            try:
                version_stats = conn.execute(
                    """
                    SELECT 
                        CASE 
                            WHEN cache_key LIKE 'aipop:v%' 
                            THEN SUBSTRING(cache_key FROM 8 FOR POSITION(':' IN SUBSTRING(cache_key FROM 8)) - 1)
                            ELSE 'unversioned'
                        END as version,
                        COUNT(*) as count
                    FROM attack_results_cache
                    GROUP BY version
                """
                ).fetchall()
                version_breakdown = {version: count for version, count in version_stats}
            except Exception:
                version_breakdown = {}

            # Get current version
            from aipop import __version__

            current_version_entries = version_breakdown.get(__version__, 0)
            old_version_entries = results_count - current_version_entries

            # Legacy caches
            autodan_count = conn.execute("SELECT COUNT(*) FROM autodan_cache").fetchone()[0]
            pair_count = conn.execute("SELECT COUNT(*) FROM pair_cache").fetchone()[0]

            # Database size
            db_size_bytes = self.db_path.stat().st_size if self.db_path.exists() else 0
            db_size_mb = db_size_bytes / (1024 * 1024)

            return {
                "total_entries": results_count + autodan_count + pair_count,
                "valid_entries": results_valid,
                "expired_entries": results_count - results_valid,
                "current_version_entries": current_version_entries,
                "old_version_entries": old_version_entries,
                "version_breakdown": version_breakdown,
                "total_cost_saved": results_cost,
                "db_size_mb": db_size_mb,
                "results_cache": results_count,
                "autodan_cache": autodan_count,
                "pair_cache": pair_count,
            }

    def clear_expired(self) -> int:
        """Clear expired cache entries from all tables.

        Returns:
            Number of entries cleared
        """
        with duckdb.connect(str(self.db_path)) as conn:
            results = conn.execute(
                "DELETE FROM attack_results_cache WHERE expires_at < ? RETURNING cache_key",
                [time.time()],
            ).fetchall()

            count = len(results)
            if count > 0:
                logger.info(f"Cleared {count} expired cache entries")
            return count

    def clear_all(self) -> int:
        """Clear all cache entries from all tables.

        Returns:
            Number of entries cleared
        """
        with duckdb.connect(str(self.db_path)) as conn:
            results = conn.execute(
                "DELETE FROM attack_results_cache RETURNING cache_key"
            ).fetchall()
            autodan = conn.execute("DELETE FROM autodan_cache RETURNING prompt_hash").fetchall()
            pair = conn.execute("DELETE FROM pair_cache RETURNING conversation_hash").fetchall()

            count = len(results) + len(autodan) + len(pair)
            if count > 0:
                logger.info(f"Cleared all {count} cache entries")
            return count

    def clear_by_version(self, version: str | None = None) -> int:
        """Clear cache entries for a specific version.

        Args:
            version: Version to clear (e.g., "0.7.1"). If None, clears non-current versions.

        Returns:
            Number of entries cleared
        """
        with duckdb.connect(str(self.db_path)) as conn:
            if version is None:
                # Clear all non-current versions
                from aipop import __version__

                version = __version__

                # Count entries NOT matching current version
                count = conn.execute(
                    "SELECT COUNT(*) FROM attack_results_cache WHERE cache_key NOT LIKE ?",
                    [f"aipop:v{version}:%"],
                ).fetchone()[0]

                # Delete non-current versions
                conn.execute(
                    "DELETE FROM attack_results_cache WHERE cache_key NOT LIKE ?",
                    [f"aipop:v{version}:%"],
                )

                logger.info(f"Cleared {count} old version cache entries (kept v{version})")
            else:
                # Clear specific version
                count = conn.execute(
                    "SELECT COUNT(*) FROM attack_results_cache WHERE cache_key LIKE ?",
                    [f"aipop:v{version}:%"],
                ).fetchone()[0]

                conn.execute(
                    "DELETE FROM attack_results_cache WHERE cache_key LIKE ?",
                    [f"aipop:v{version}:%"],
                )

                logger.info(f"Cleared {count} cache entries for version {version}")

            return count
