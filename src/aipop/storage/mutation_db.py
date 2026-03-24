"""DuckDB-based storage for mutation statistics and history."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

try:
    import duckdb
except ImportError:
    duckdb = None  # type: ignore[assignment]


class MutationDatabase:
    """DuckDB-based storage for mutation statistics and history."""

    def __init__(self, db_path: Path) -> None:
        """Initialize mutation database.

        Args:
            db_path: Path to DuckDB database file
        """
        if duckdb is None:
            raise ImportError(
                "DuckDB is required for this feature. "
                "Install with: pip install ai-purple-ops[intelligence]"
            )
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.conn = duckdb.connect(str(db_path))
        except duckdb.IOException:
            import os
            fallback = self.db_path.with_stem(f"{self.db_path.stem}_{os.getpid()}")
            self.db_path = fallback
            self.conn = duckdb.connect(str(self.db_path))
        self._init_schema()

    def _init_schema(self) -> None:
        """Create tables for mutation tracking."""
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mutations (
                id INTEGER PRIMARY KEY,
                timestamp TIMESTAMP,
                original_prompt TEXT,
                mutated_prompt TEXT,
                mutation_type VARCHAR,
                mutation_metadata VARCHAR,
                test_case_id VARCHAR,
                success BOOLEAN,
                asr FLOAT,
                detection_rate FLOAT,
                response TEXT,
                provider VARCHAR,
                model VARCHAR
            )
        """
        )

        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS mutation_stats (
                mutation_type VARCHAR PRIMARY KEY,
                total_attempts INTEGER,
                successes INTEGER,
                failures INTEGER,
                avg_asr FLOAT,
                avg_detection_rate FLOAT,
                last_updated TIMESTAMP
            )
        """
        )

        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fitness_scores (
                prompt_hash VARCHAR PRIMARY KEY,
                prompt TEXT,
                fitness_score FLOAT,
                optimization_target VARCHAR,
                last_updated TIMESTAMP
            )
        """
        )

    def record_mutation(self, mutation_data: dict[str, Any]) -> None:
        """Record a single mutation attempt.

        Args:
            mutation_data: Dictionary with mutation information
        """
        metadata_json = json.dumps(mutation_data.get("metadata", {}))

        # Get next ID
        result = self.conn.execute("SELECT MAX(id) FROM mutations").fetchone()
        next_id = (result[0] or 0) + 1

        self.conn.execute(
            """
            INSERT INTO mutations (
                id, timestamp, original_prompt, mutated_prompt, mutation_type,
                mutation_metadata, test_case_id, success, asr, detection_rate,
                response, provider, model
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            [
                next_id,
                datetime.now(UTC),
                mutation_data.get("original"),
                mutation_data.get("mutated"),
                mutation_data.get("type"),
                metadata_json,
                mutation_data.get("test_case_id"),
                mutation_data.get("success"),
                mutation_data.get("asr"),
                mutation_data.get("detection_rate"),
                mutation_data.get("response"),
                mutation_data.get("provider"),
                mutation_data.get("model"),
            ],
        )

        # Update aggregated stats
        self._update_stats(mutation_data.get("type"))

    def _update_stats(self, mutation_type: str | None) -> None:
        """Update aggregated mutation statistics.

        Args:
            mutation_type: Type of mutation
        """
        if not mutation_type:
            return

        # Calculate stats from mutations table
        result = self.conn.execute(
            """
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN success = true THEN 1 ELSE 0 END) as successes,
                SUM(CASE WHEN success = false THEN 1 ELSE 0 END) as failures,
                AVG(asr) as avg_asr,
                AVG(detection_rate) as avg_detection_rate
            FROM mutations
            WHERE mutation_type = ?
        """,
            [mutation_type],
        ).fetchone()

        if result:
            self.conn.execute(
                """
                INSERT INTO mutation_stats (
                    mutation_type, total_attempts, successes, failures,
                    avg_asr, avg_detection_rate, last_updated
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (mutation_type) DO UPDATE SET
                    total_attempts = EXCLUDED.total_attempts,
                    successes = EXCLUDED.successes,
                    failures = EXCLUDED.failures,
                    avg_asr = EXCLUDED.avg_asr,
                    avg_detection_rate = EXCLUDED.avg_detection_rate,
                    last_updated = EXCLUDED.last_updated
            """,
                [
                    mutation_type,
                    result[0] or 0,
                    result[1] or 0,
                    result[2] or 0,
                    result[3] or 0.0,
                    result[4] or 0.0,
                    datetime.now(UTC),
                ],
            )

    def get_mutation_stats(self, mutation_type: str | None = None) -> list[tuple] | tuple | None:
        """Get aggregated mutation statistics.

        Args:
            mutation_type: Optional mutation type filter

        Returns:
            Statistics tuple or list of tuples
        """
        if mutation_type:
            query = "SELECT * FROM mutation_stats WHERE mutation_type = ?"
            result = self.conn.execute(query, [mutation_type]).fetchone()
            return result
        else:
            query = "SELECT * FROM mutation_stats"
            result = self.conn.execute(query).fetchall()
            return result

    def get_top_mutations(self, limit: int = 10, order_by: str = "asr") -> list[tuple]:
        """Get top-performing mutations.

        Args:
            limit: Maximum number of results
            order_by: Column to order by (asr or detection_rate)

        Returns:
            List of tuples with top mutations
        """
        # Validate order_by
        if order_by not in ["asr", "detection_rate"]:
            order_by = "asr"

        query = f"""
            SELECT mutation_type, mutated_prompt, AVG(asr) as avg_asr, AVG(detection_rate) as avg_detection_rate
            FROM mutations
            GROUP BY mutation_type, mutated_prompt
            ORDER BY AVG({order_by}) DESC
            LIMIT ?
        """
        return self.conn.execute(query, [limit]).fetchall()

    def close(self) -> None:
        """Close database connection."""
        self.conn.close()
