"""DuckDB storage for guardrail fingerprint results."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

try:
    import duckdb
except ImportError:
    duckdb = None  # type: ignore[assignment]

if TYPE_CHECKING:
    from aipop.intelligence.fingerprint_models import FingerprintResult


class FingerprintDB:
    """Store fingerprint results in DuckDB with JSON export."""

    def __init__(self, db_path: Path | str = Path("out/fingerprints.duckdb")):
        """Initialize DuckDB connection and schema."""
        if duckdb is None:
            raise ImportError(
                "DuckDB is required for this feature. "
                "Install with: pip install ai-purple-ops[intelligence]"
            )
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # Use access_mode to avoid exclusive locks on concurrent runs
        try:
            self.conn = duckdb.connect(str(self.db_path))
        except duckdb.IOException:
            # Another process holds the lock -- use a per-process DB
            import os
            fallback = self.db_path.with_stem(f"{self.db_path.stem}_{os.getpid()}")
            self.db_path = fallback
            self.conn = duckdb.connect(str(self.db_path))
        self._init_schema()

    def _init_schema(self) -> None:
        """Create fingerprints table if it doesn't exist."""
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS fingerprints (
                id INTEGER PRIMARY KEY,
                model_id TEXT NOT NULL,
                adapter_type TEXT NOT NULL,
                guardrail_type TEXT NOT NULL,
                confidence REAL NOT NULL,
                detection_method TEXT NOT NULL,
                all_scores TEXT,  -- JSON string
                evidence TEXT,    -- JSON string
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                probe_count INTEGER,
                avg_latency_ms REAL,
                uncertain BOOLEAN DEFAULT FALSE,
                suggestions TEXT  -- JSON string
            )
        """
        )

    def store_fingerprint(self, model_id: str, result: FingerprintResult) -> None:
        """Store result in DuckDB and export to JSON."""
        # Get next ID
        max_id_result = self.conn.execute("SELECT MAX(id) FROM fingerprints").fetchone()
        next_id = (max_id_result[0] or 0) + 1

        # Insert to DuckDB
        self.conn.execute(
            """
            INSERT INTO fingerprints 
            (id, model_id, adapter_type, guardrail_type, confidence, detection_method,
             all_scores, evidence, probe_count, avg_latency_ms, uncertain, suggestions)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            [
                next_id,
                model_id,
                result.adapter_type,
                result.guardrail_type,
                result.confidence,
                result.detection_method,
                json.dumps(result.all_scores),
                json.dumps(result.evidence),
                result.probe_count,
                result.avg_latency_ms,
                result.uncertain,
                json.dumps(result.suggestions),
            ],
        )

        # Also export to JSON file for easy inspection
        json_path = Path("out/fingerprints") / f"{model_id.replace(':', '_')}.json"
        json_path.parent.mkdir(parents=True, exist_ok=True)
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)

    def get_cached_fingerprint(self, model_id: str) -> FingerprintResult | None:
        """Retrieve cached result (skip if older than 24 hours)."""
        from aipop.intelligence.fingerprint_models import FingerprintResult

        result = self.conn.execute(
            """
            SELECT * FROM fingerprints 
            WHERE model_id = ? 
            AND timestamp > CURRENT_TIMESTAMP - INTERVAL '24 hours'
            ORDER BY timestamp DESC 
            LIMIT 1
        """,
            [model_id],
        ).fetchone()

        if result:
            return FingerprintResult.from_row(result)
        return None

    def get_all_fingerprints(self) -> list[FingerprintResult]:
        """Get all stored fingerprints."""
        from aipop.intelligence.fingerprint_models import FingerprintResult

        results = self.conn.execute("SELECT * FROM fingerprints ORDER BY timestamp DESC").fetchall()
        return [FingerprintResult.from_row(row) for row in results]

    def clear_cache(self, model_id: str | None = None) -> None:
        """Clear cached fingerprints (all or for specific model)."""
        if model_id:
            self.conn.execute("DELETE FROM fingerprints WHERE model_id = ?", [model_id])
        else:
            self.conn.execute("DELETE FROM fingerprints")
