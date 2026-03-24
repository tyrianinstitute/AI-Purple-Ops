"""DuckDB storage for adversarial suffixes."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import duckdb
except ImportError:
    duckdb = None  # type: ignore[assignment]


class SuffixDatabase:
    """Store and retrieve adversarial suffixes in DuckDB."""

    def __init__(self, db_path: Path | str = Path("out/suffixes.duckdb")) -> None:
        """Initialize suffix database.

        Args:
            db_path: Path to DuckDB database file
        """
        if duckdb is None:
            raise ImportError(
                "DuckDB is required for this feature. "
                "Install with: pip install ai-purple-ops[intelligence]"
            )
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.conn = duckdb.connect(str(self.db_path))
        except duckdb.IOException:
            import os
            fallback = self.db_path.with_stem(f"{self.db_path.stem}_{os.getpid()}")
            self.db_path = fallback
            self.conn = duckdb.connect(str(self.db_path))
        self._init_schema()

    def _init_schema(self) -> None:
        """Create table for suffix storage."""
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS suffixes (
                id VARCHAR PRIMARY KEY,
                suffix_text TEXT NOT NULL,
                prompt TEXT NOT NULL,
                target TEXT,
                asr REAL DEFAULT 0.0,
                model_id VARCHAR,
                generation_method VARCHAR,
                mode VARCHAR,
                iterations INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata TEXT,  -- JSON string
                verified BOOLEAN DEFAULT FALSE
            )
        """
        )
        self.conn.commit()

    def store_suffix(self, suffix_data: dict[str, Any]) -> None:
        """Store generated suffix with metadata.

        Args:
            suffix_data: Dictionary containing:
                - id: Unique identifier
                - suffix_text: The adversarial suffix
                - prompt: Base prompt used
                - target: Target output prefix
                - asr: Attack Success Rate (0.0-1.0)
                - model_id: Model tested against
                - generation_method: "gcg", "autodan", etc.
                - mode: "white-box" or "black-box"
                - iterations: Number of optimization iterations
                - metadata: Additional metadata dict
                - verified: Whether suffix was verified
        """
        suffix_id = suffix_data.get("id", f"suffix_{datetime.now().timestamp()}")
        metadata_json = json.dumps(suffix_data.get("metadata", {}))

        self.conn.execute(
            """
            INSERT OR REPLACE INTO suffixes (
                id, suffix_text, prompt, target, asr, model_id,
                generation_method, mode, iterations, metadata, verified
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                suffix_id,
                suffix_data["suffix_text"],
                suffix_data.get("prompt", ""),
                suffix_data.get("target", ""),
                suffix_data.get("asr", 0.0),
                suffix_data.get("model_id"),
                suffix_data.get("generation_method", "gcg"),
                suffix_data.get("mode", "black-box"),
                suffix_data.get("iterations", 0),
                metadata_json,
                suffix_data.get("verified", False),
            ),
        )
        self.conn.commit()

    def get_top_suffixes(
        self,
        model_id: str | None = None,
        min_asr: float = 0.6,
        limit: int = 100,
        generation_method: str | None = None,
    ) -> list[dict[str, Any]]:
        """Retrieve best suffixes.

        Args:
            model_id: Filter by model ID
            min_asr: Minimum ASR threshold
            limit: Maximum number of results
            generation_method: Filter by method ("gcg", "autodan", etc.)

        Returns:
            List of suffix dictionaries ordered by ASR (descending)
        """
        query = "SELECT * FROM suffixes WHERE asr >= ?"
        params: list[Any] = [min_asr]

        if model_id:
            query += " AND model_id = ?"
            params.append(model_id)

        if generation_method:
            query += " AND generation_method = ?"
            params.append(generation_method)

        query += " ORDER BY asr DESC LIMIT ?"
        params.append(limit)

        rows = self.conn.execute(query, params).fetchall()

        results = []
        for row in rows:
            results.append(
                {
                    "id": row[0],
                    "suffix_text": row[1],
                    "prompt": row[2],
                    "target": row[3],
                    "asr": row[4],
                    "model_id": row[5],
                    "generation_method": row[6],
                    "mode": row[7],
                    "iterations": row[8],
                    "timestamp": row[9].isoformat() if row[9] else None,
                    "metadata": json.loads(row[10]) if row[10] else {},
                    "verified": row[11],
                }
            )

        return results

    def get_suffix_stats(self) -> dict[str, Any]:
        """Get analytics: ASR by model, by method, success rates.

        Returns:
            Dictionary with statistics:
            - total_suffixes: Total count
            - avg_asr: Average ASR across all suffixes
            - by_model: ASR statistics grouped by model
            - by_method: ASR statistics grouped by generation method
            - top_suffixes: Top 10 suffixes by ASR
        """
        # Total count and average ASR
        total_result = self.conn.execute("SELECT COUNT(*), AVG(asr) FROM suffixes").fetchone()
        total_suffixes = total_result[0] or 0
        avg_asr = total_result[1] or 0.0

        # By model
        model_stats = self.conn.execute(
            """
            SELECT model_id, COUNT(*), AVG(asr), MAX(asr), MIN(asr)
            FROM suffixes
            WHERE model_id IS NOT NULL
            GROUP BY model_id
            ORDER BY AVG(asr) DESC
        """
        ).fetchall()

        by_model = {}
        for row in model_stats:
            by_model[row[0]] = {
                "count": row[1],
                "avg_asr": row[2],
                "max_asr": row[3],
                "min_asr": row[4],
            }

        # By method
        method_stats = self.conn.execute(
            """
            SELECT generation_method, COUNT(*), AVG(asr), MAX(asr)
            FROM suffixes
            GROUP BY generation_method
            ORDER BY AVG(asr) DESC
        """
        ).fetchall()

        by_method = {}
        for row in method_stats:
            by_method[row[0] or "unknown"] = {
                "count": row[1],
                "avg_asr": row[2],
                "max_asr": row[3],
            }

        # Top suffixes
        top_suffixes = self.get_top_suffixes(limit=10)

        return {
            "total_suffixes": total_suffixes,
            "avg_asr": avg_asr,
            "by_model": by_model,
            "by_method": by_method,
            "top_suffixes": top_suffixes,
        }

    def close(self) -> None:
        """Close the database connection."""
        self.conn.close()
