"""Session persistence for cross-run state management.

Stores discovered attack surfaces, successful payloads, fingerprint results,
and conversation state across multiple `aipop run` invocations. Uses SQLite
for simplicity and zero locking issues.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


class SessionStore:
    """SQLite-backed session store for multi-run persistence."""

    def __init__(self, db_path: str | Path = ".aipop/sessions.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                target_name TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                phase TEXT DEFAULT 'recon',
                metadata TEXT DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS discoveries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                discovery_type TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            );

            CREATE TABLE IF NOT EXISTS run_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                suite TEXT,
                adapter TEXT,
                model TEXT,
                total INTEGER,
                passed INTEGER,
                failed INTEGER,
                summary_path TEXT,
                evidence_path TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES sessions(session_id)
            );

            CREATE INDEX IF NOT EXISTS idx_discoveries_session ON discoveries(session_id);
            CREATE INDEX IF NOT EXISTS idx_runs_session ON run_history(session_id);
        """)
        self.conn.commit()

    def create_session(self, session_id: str, target_name: str = "", metadata: dict[str, Any] | None = None) -> None:
        """Create a new session."""
        now = datetime.now(UTC).isoformat()
        self.conn.execute(
            "INSERT OR REPLACE INTO sessions (session_id, target_name, created_at, updated_at, metadata) VALUES (?, ?, ?, ?, ?)",
            (session_id, target_name, now, now, json.dumps(metadata or {})),
        )
        self.conn.commit()

    def get_session(self, session_id: str) -> dict[str, Any] | None:
        """Get session by ID."""
        row = self.conn.execute("SELECT * FROM sessions WHERE session_id = ?", (session_id,)).fetchone()
        if row:
            return dict(row)
        return None

    def list_sessions(self) -> list[dict[str, Any]]:
        """List all sessions."""
        rows = self.conn.execute("SELECT * FROM sessions ORDER BY updated_at DESC").fetchall()
        return [dict(r) for r in rows]

    def update_phase(self, session_id: str, phase: str) -> None:
        """Update session phase (recon, attack, report)."""
        now = datetime.now(UTC).isoformat()
        self.conn.execute(
            "UPDATE sessions SET phase = ?, updated_at = ? WHERE session_id = ?",
            (phase, now, session_id),
        )
        self.conn.commit()

    def add_discovery(self, session_id: str, discovery_type: str, key: str, value: Any) -> None:
        """Record a discovery (fingerprint, successful payload, attack surface)."""
        now = datetime.now(UTC).isoformat()
        self.conn.execute(
            "INSERT INTO discoveries (session_id, discovery_type, key, value, created_at) VALUES (?, ?, ?, ?, ?)",
            (session_id, discovery_type, key, json.dumps(value) if not isinstance(value, str) else value, now),
        )
        self.conn.commit()

    def get_discoveries(self, session_id: str, discovery_type: str | None = None) -> list[dict[str, Any]]:
        """Get discoveries for a session, optionally filtered by type."""
        if discovery_type:
            rows = self.conn.execute(
                "SELECT * FROM discoveries WHERE session_id = ? AND discovery_type = ? ORDER BY created_at",
                (session_id, discovery_type),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT * FROM discoveries WHERE session_id = ? ORDER BY created_at",
                (session_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    def add_run(self, session_id: str, run_id: str, suite: str, adapter: str, model: str,
                total: int, passed: int, failed: int, summary_path: str = "", evidence_path: str = "") -> None:
        """Record a completed run."""
        now = datetime.now(UTC).isoformat()
        self.conn.execute(
            "INSERT INTO run_history (session_id, run_id, suite, adapter, model, total, passed, failed, summary_path, evidence_path, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (session_id, run_id, suite, adapter, model, total, passed, failed, summary_path, evidence_path, now),
        )
        now_ts = datetime.now(UTC).isoformat()
        self.conn.execute("UPDATE sessions SET updated_at = ? WHERE session_id = ?", (now_ts, session_id))
        self.conn.commit()

    def get_runs(self, session_id: str) -> list[dict[str, Any]]:
        """Get run history for a session."""
        rows = self.conn.execute(
            "SELECT * FROM run_history WHERE session_id = ? ORDER BY created_at DESC",
            (session_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def export_session(self, session_id: str) -> dict[str, Any]:
        """Export full session state for sharing."""
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session not found: {session_id}")
        return {
            "session": session,
            "discoveries": self.get_discoveries(session_id),
            "runs": self.get_runs(session_id),
        }

    def close(self) -> None:
        self.conn.close()
