"""Payload manager with tagging, success tracking, and versioning.

Manages payloads from multiple sources:
- SecLists wordlists
- Git repositories
- Manual entry
- Built-in MCP exploits
"""

from __future__ import annotations

import json
import logging
import uuid
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class PayloadManager:
    """Manages custom payloads with tagging, success tracking, and versioning.

    Features:
    - Import SecLists wordlists by category
    - Sync payloads from Git repositories
    - Track which payloads work (success rate)
    - Filter by tool, category, success rate
    - Export top-performing payloads

    Example:
        >>> manager = PayloadManager(db_path="out/payloads.db")
        >>> manager.import_seclists("/opt/SecLists", ["fuzzing", "passwords"])
        >>>
        >>> # Get payloads for specific tool
        >>> payloads = manager.get_payloads_for_tool("read_file", "path_traversal")
        >>>
        >>> # Mark successful payload
        >>> manager.mark_success(payload="../../../flag.txt", tool="read_file", evidence="Found flag!")
    """

    def __init__(self, db_path: Path | str | None = None) -> None:
        """Initialize payload manager.

        Args:
            db_path: Path to DuckDB database file (default: out/payloads.db)
        """
        import duckdb

        if db_path is None:
            db_path = Path("out/payloads/payloads.db")

        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Initialize database
        self.conn = duckdb.connect(str(self.db_path))
        self._initialize_schema()

        logger.info(f"Payload manager initialized: {self.db_path}")

    def _initialize_schema(self) -> None:
        """Initializes database schema from SQL file."""
        schema_path = Path(__file__).parent.parent.parent.parent / "configs" / "schemas" / "payloads.sql"

        if schema_path.exists():
            with open(schema_path) as f:
                schema_sql = f.read()

            # Remove comment-only lines first
            lines = []
            for line in schema_sql.split("\n"):
                stripped = line.strip()
                # Keep line if it's not a pure comment line
                if stripped and not stripped.startswith("--"):
                    lines.append(line)

            cleaned_sql = "\n".join(lines)

            # Execute each statement separately
            for statement in cleaned_sql.split(";"):
                statement = statement.strip()
                if statement:
                    try:
                        self.conn.execute(statement)
                        logger.debug(f"Schema statement executed: {statement[:50]}...")
                    except Exception as e:
                        logger.warning(f"Schema statement failed: {e}")
                        logger.debug(f"Failed statement: {statement[:200]}...")
        else:
            logger.warning(f"Schema file not found: {schema_path}")
            # Create minimal schema
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS payloads (
                    payload_id VARCHAR PRIMARY KEY,
                    payload_text VARCHAR NOT NULL,
                    category VARCHAR NOT NULL,
                    source VARCHAR NOT NULL,
                    tool_name VARCHAR,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """
            )

    def import_seclists(self, path: str | Path, categories: list[str] | None = None) -> int:
        """Import SecLists wordlists.

        Args:
            path: Path to SecLists directory (e.g., /opt/SecLists)
            categories: Categories to import (e.g., ["fuzzing", "passwords"])
                       If None, imports all

        Returns:
            Number of payloads imported
        """
        from aipop.payloads.seclists_importer import SecListsImporter

        importer = SecListsImporter(seclists_path=Path(path))
        payloads = importer.import_categories(categories or [])

        # Store in database
        count = 0
        for payload_data in payloads:
            self.add_payload(
                payload_text=payload_data["text"],
                category=payload_data["category"],
                source="seclists",
                source_path=payload_data["source_path"],
                tool_name=payload_data.get("tool_name"),
                tags=payload_data.get("tags"),
            )
            count += 1

        logger.info(f"Imported {count} payloads from SecLists")
        return count

    def import_git_repo(self, repo_url: str, branch: str = "main") -> int:
        """Clone/pull Git repo with custom payloads.

        Args:
            repo_url: Git repository URL
            branch: Branch to checkout

        Returns:
            Number of payloads imported
        """
        from aipop.payloads.git_sync import GitSync

        sync = GitSync(repo_url=repo_url, branch=branch)
        payload_files = sync.sync_and_discover()

        # Import discovered payload files
        count = 0
        for file_path in payload_files:
            with open(file_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self.add_payload(
                            payload_text=line,
                            category=self._infer_category(file_path),
                            source="git",
                            source_path=repo_url,
                        )
                        count += 1

        logger.info(f"Imported {count} payloads from Git: {repo_url}")
        return count

    def add_payload(
        self,
        payload_text: str,
        category: str,
        source: str,
        source_path: str | None = None,
        tool_name: str | None = None,
        description: str | None = None,
        tags: list[str] | None = None,
    ) -> str:
        """Add a single payload to the database.

        Args:
            payload_text: The payload string
            category: Category (sqli, xss, path_traversal, etc.)
            source: Source type (seclists, git, manual, mcp_exploits)
            source_path: Original file path or URL
            tool_name: Tool this payload targets
            description: Optional description
            tags: Additional tags

        Returns:
            Payload ID
        """
        payload_id = str(uuid.uuid4())

        self.conn.execute(
            """
            INSERT INTO payloads (
                payload_id, payload_text, category, source, source_path,
                tool_name, description, tags
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                payload_id,
                payload_text,
                category,
                source,
                source_path,
                tool_name,
                description,
                json.dumps(tags) if tags else None,
            ),
        )

        return payload_id

    def get_payloads_for_tool(
        self,
        tool_name: str,
        category: str | None = None,
        limit: int = 100,
        order_by_success: bool = True,
    ) -> list[dict[str, Any]]:
        """Retrieve payloads by tool/category with success rate ordering.

        Args:
            tool_name: Tool name to filter by
            category: Category to filter by (optional)
            limit: Maximum number of payloads
            order_by_success: Order by success rate (highest first)

        Returns:
            List of payload dicts with success statistics
        """
        query = """
            SELECT 
                p.payload_id,
                p.payload_text,
                p.category,
                p.source,
                p.tool_name,
                p.description,
                p.tags,
                COALESCE(ps.success_rate, 0) as success_rate,
                COALESCE(ps.total_attempts, 0) as total_attempts
            FROM payloads p
            LEFT JOIN payload_stats ps ON p.payload_id = ps.payload_id
            WHERE (p.tool_name = ? OR p.tool_name IS NULL)
        """

        params = [tool_name]

        if category:
            query += " AND p.category = ?"
            params.append(category)

        if order_by_success:
            query += " ORDER BY success_rate DESC, total_attempts DESC"

        query += f" LIMIT {limit}"

        result = self.conn.execute(query, params).fetchall()

        payloads = []
        for row in result:
            payloads.append(
                {
                    "payload_id": row[0],
                    "payload_text": row[1],
                    "category": row[2],
                    "source": row[3],
                    "tool_name": row[4],
                    "description": row[5],
                    "tags": json.loads(row[6]) if row[6] else [],
                    "success_rate": float(row[7]),
                    "total_attempts": int(row[8]),
                }
            )

        return payloads

    def mark_success(
        self,
        payload: str,
        tool: str,
        evidence: str,
        engagement_id: str | None = None,
        adapter_name: str = "unknown",
        target_url: str | None = None,
    ) -> None:
        """Track which payloads work for future prioritization.

        Args:
            payload: Payload text that was used
            tool: Tool name it was used with
            evidence: Evidence of success (response snippet)
            engagement_id: Link to engagement
            adapter_name: Adapter that was used
            target_url: Target URL
        """
        # Find payload ID
        result = self.conn.execute(
            "SELECT payload_id FROM payloads WHERE payload_text = ? LIMIT 1", (payload,)
        ).fetchone()

        if not result:
            # Payload not in DB yet, add it
            payload_id = self.add_payload(
                payload_text=payload,
                category="unknown",
                source="manual",
                tool_name=tool,
            )
        else:
            payload_id = result[0]

        # Record success
        success_id = str(uuid.uuid4())
        self.conn.execute(
            """
            INSERT INTO payload_success (
                success_id, payload_id, engagement_id, tool_name,
                adapter_name, target_url, success, response_snippet
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                success_id,
                payload_id,
                engagement_id,
                tool,
                adapter_name,
                target_url,
                True,
                evidence[:500],  # First 500 chars
            ),
        )

        logger.info(f"Marked payload as successful: {payload[:50]}...")

    def get_top_payloads(
        self, limit: int = 10, category: str | None = None
    ) -> list[dict[str, Any]]:
        """Get top-performing payloads by success rate.

        Args:
            limit: Number of top payloads to return
            category: Filter by category (optional)

        Returns:
            List of top payload dicts
        """
        query = """
            SELECT 
                payload_text,
                category,
                tool_name,
                success_rate,
                successes,
                total_attempts
            FROM payload_stats
            WHERE total_attempts > 0
        """

        if category:
            query += f" AND category = '{category}'"

        query += f" ORDER BY success_rate DESC, total_attempts DESC LIMIT {limit}"

        result = self.conn.execute(query).fetchall()

        payloads = []
        for row in result:
            payloads.append(
                {
                    "payload": row[0],
                    "category": row[1],
                    "tool_name": row[2],
                    "success_rate": float(row[3]),
                    "successes": int(row[4]),
                    "total_attempts": int(row[5]),
                }
            )

        return payloads

    def _infer_category(self, file_path: Path) -> str:
        """Infers payload category from file path.

        Args:
            file_path: Path to payload file

        Returns:
            Category string
        """
        path_str = str(file_path).lower()

        if "sqli" in path_str or "sql" in path_str:
            return "sqli"
        elif "xss" in path_str:
            return "xss"
        elif "path" in path_str or "traversal" in path_str:
            return "path_traversal"
        elif "command" in path_str or "rce" in path_str:
            return "command_injection"
        elif "ssrf" in path_str:
            return "ssrf"
        elif "fuzzing" in path_str or "fuzz" in path_str:
            return "fuzzing"
        else:
            return "unknown"

    def list_payloads(
        self,
        category: str | None = None,
        tool: str | None = None,
        top: int | None = None,
    ) -> list[dict[str, Any]]:
        """List payloads with optional filters.

        Args:
            category: Filter by category
            tool: Filter by tool name
            top: Limit number of results

        Returns:
            List of payload dictionaries
        """
        query = "SELECT * FROM payloads WHERE 1=1"
        params = []

        if category:
            query += " AND category = ?"
            params.append(category)
        if tool:
            query += " AND tool_name = ?"
            params.append(tool)

        query += " ORDER BY created_at DESC"

        if top:
            query += f" LIMIT {top}"

        results = self.conn.execute(query, params).fetchall()
        return results

    def search_payloads(self, query: str) -> list[str]:
        """Search payloads by keyword.

        Args:
            query: Search term

        Returns:
            List of matching payload texts
        """
        sql = """
            SELECT payload_text FROM payloads 
            WHERE payload_text LIKE ? OR category LIKE ? OR description LIKE ?
            LIMIT 100
        """
        pattern = f"%{query}%"
        results = self.conn.execute(sql, (pattern, pattern, pattern)).fetchall()
        return [row[0] for row in results]

    def get_statistics(self) -> dict[str, Any]:
        """Gets payload database statistics.

        Returns:
            Statistics dict
        """
        total_payloads = self.conn.execute("SELECT COUNT(*) FROM payloads").fetchone()[0]
        total_attempts = self.conn.execute("SELECT COUNT(*) FROM payload_success").fetchone()[0]

        categories = self.conn.execute(
            """
            SELECT category, COUNT(*) 
            FROM payloads 
            GROUP BY category
        """
        ).fetchall()

        return {
            "total_payloads": total_payloads,
            "total_attempts": total_attempts,
            "categories": {cat: count for cat, count in categories},
        }

    def close(self) -> None:
        """Closes database connection."""
        if self.conn:
            self.conn.close()
        logger.info("Payload manager closed")
