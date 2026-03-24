"""Generic traffic capture system for all adapters.

Captures HTTP request/response pairs for evidence collection, HAR export,
and professional reporting. Works across all adapters (OpenAI, Anthropic, MCP, custom).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from aipop.core.models import ModelResponse

logger = logging.getLogger(__name__)


@dataclass
class CapturedRequest:
    """Represents a captured HTTP request/response pair.

    Attributes:
        request_id: Unique identifier for this request
        timestamp: ISO 8601 timestamp when request was made
        adapter_name: Name of adapter that made the request
        method: HTTP method (GET, POST, etc.)
        url: Request URL
        headers: Request headers dict
        body: Request body (string or dict)
        response_status: HTTP status code
        response_headers: Response headers dict
        response_body: Response body
        response_time_ms: Response time in milliseconds
        model_response: Original ModelResponse object
        evidence_tags: Tags for categorization (e.g., ["prompt_injection", "bypass"])
    """

    request_id: str
    timestamp: str
    adapter_name: str
    method: str
    url: str
    headers: dict[str, str]
    body: str | dict | None
    response_status: int | None
    response_headers: dict[str, str] | None
    response_body: str | None
    response_time_ms: float
    model_response: ModelResponse | None = None
    evidence_tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "request_id": self.request_id,
            "timestamp": self.timestamp,
            "adapter_name": self.adapter_name,
            "method": self.method,
            "url": self.url,
            "headers": self.headers,
            "body": self.body,
            "response_status": self.response_status,
            "response_headers": self.response_headers,
            "response_body": self.response_body,
            "response_time_ms": self.response_time_ms,
            "evidence_tags": self.evidence_tags,
        }


class TrafficCapture:
    """Captures all adapter HTTP traffic for evidence and analysis.

    Features:
    - Capture request/response pairs from ANY adapter
    - Store in DuckDB for querying
    - Export to HAR format for Burp Suite
    - Tag evidence for categorization
    - Filter by adapter, time range, tags

    Example:
        >>> capture = TrafficCapture(session_id="test_001", output_dir=Path("out"))
        >>> capture.capture_request(
        ...     adapter_name="openai",
        ...     method="POST",
        ...     url="https://api.openai.com/v1/chat/completions",
        ...     headers={"Authorization": "Bearer ..."},
        ...     body={"messages": [...]},
        ...     response=model_response,
        ...     response_time_ms=234.5
        ... )
        >>> har_path = capture.export_har()
    """

    def __init__(self, session_id: str, output_dir: Path | str) -> None:
        """Initialize traffic capture.

        Args:
            session_id: Unique identifier for this capture session
            output_dir: Directory to store capture files
        """
        self.session_id = session_id
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # In-memory storage (for current session)
        self.requests: list[CapturedRequest] = []

        # DuckDB connection (lazy init)
        self._db_conn = None

        logger.info(f"Traffic capture initialized: session_id={session_id}")

    def capture_request(
        self,
        adapter_name: str,
        method: str,
        url: str,
        headers: dict[str, str],
        body: str | dict | None,
        response: ModelResponse,
        response_time_ms: float,
        response_status: int | None = None,
        response_headers: dict[str, str] | None = None,
        response_body: str | None = None,
        evidence_tags: list[str] | None = None,
    ) -> str:
        """Captures a request/response pair.

        Args:
            adapter_name: Name of adapter (e.g., "openai", "mcp", "anthropic")
            method: HTTP method
            url: Request URL
            headers: Request headers
            body: Request body
            response: ModelResponse object
            response_time_ms: Response time in milliseconds
            response_status: HTTP status code (if available)
            response_headers: Response headers (if available)
            response_body: Raw response body (if available)
            evidence_tags: Tags for categorization

        Returns:
            Request ID for reference
        """
        import uuid

        request_id = str(uuid.uuid4())
        timestamp = datetime.now(UTC).isoformat()

        # Sanitize sensitive headers (don't log auth tokens)
        sanitized_headers = self._sanitize_headers(headers)
        sanitized_response_headers = self._sanitize_headers(response_headers or {})

        captured = CapturedRequest(
            request_id=request_id,
            timestamp=timestamp,
            adapter_name=adapter_name,
            method=method,
            url=url,
            headers=sanitized_headers,
            body=body,
            response_status=response_status or 200,
            response_headers=sanitized_response_headers,
            response_body=response_body or response.text,
            response_time_ms=response_time_ms,
            model_response=response,
            evidence_tags=evidence_tags or [],
        )

        self.requests.append(captured)

        # Persist to DuckDB
        self._store_in_db(captured)

        logger.debug(f"Captured request: {request_id} ({adapter_name} -> {url})")

        return request_id

    def _sanitize_headers(self, headers: dict[str, str]) -> dict[str, str]:
        """Sanitizes sensitive headers for logging.

        Args:
            headers: Original headers dict

        Returns:
            Sanitized headers with tokens redacted
        """
        sanitized = dict(headers)

        sensitive_keys = ["authorization", "api-key", "x-api-key", "cookie", "x-auth-token"]

        for key in sanitized:
            if key.lower() in sensitive_keys:
                # Keep first/last 4 chars for debugging
                value = sanitized[key]
                if len(value) > 12:
                    sanitized[key] = f"{value[:4]}...{value[-4:]}"
                else:
                    sanitized[key] = "***REDACTED***"

        return sanitized

    def _store_in_db(self, captured: CapturedRequest) -> None:
        """Stores captured request in DuckDB.

        Args:
            captured: CapturedRequest to store
        """
        try:
            import duckdb

            if self._db_conn is None:
                db_path = self.output_dir / f"traffic_{self.session_id}.db"
                self._db_conn = duckdb.connect(str(db_path))

                # Create table if not exists
                self._db_conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS traffic_capture (
                        request_id VARCHAR PRIMARY KEY,
                        timestamp TIMESTAMP,
                        adapter_name VARCHAR,
                        method VARCHAR,
                        url VARCHAR,
                        headers JSON,
                        body JSON,
                        response_status INTEGER,
                        response_headers JSON,
                        response_body VARCHAR,
                        response_time_ms DOUBLE,
                        evidence_tags JSON
                    )
                """
                )

            # Insert captured request
            self._db_conn.execute(
                """
                INSERT INTO traffic_capture VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    captured.request_id,
                    captured.timestamp,
                    captured.adapter_name,
                    captured.method,
                    captured.url,
                    json.dumps(captured.headers),
                    json.dumps(captured.body) if isinstance(captured.body, dict) else captured.body,
                    captured.response_status,
                    json.dumps(captured.response_headers),
                    captured.response_body,
                    captured.response_time_ms,
                    json.dumps(captured.evidence_tags),
                ),
            )

        except ImportError:
            logger.warning("DuckDB not available, skipping database storage")
        except Exception as e:
            logger.error(f"Failed to store in DuckDB: {e}")

    def export_har(self, output_path: str | None = None) -> Path:
        """Exports captured traffic to HAR (HTTP Archive) format.

        HAR format is compatible with:
        - Burp Suite (import via Proxy → HTTP history → Import)
        - Chrome DevTools (Network tab → Import)
        - Firefox DevTools
        - Charles Proxy
        - Fiddler

        Args:
            output_path: Optional custom output path

        Returns:
            Path to generated HAR file
        """
        from aipop.intelligence.har_exporter import HARExporter

        exporter = HARExporter(session_id=self.session_id)
        har_data = exporter.export(self.requests)

        if output_path:
            har_path = Path(output_path)
        else:
            har_path = self.output_dir / f"traffic_{self.session_id}.har"

        har_path.parent.mkdir(parents=True, exist_ok=True)
        with open(har_path, "w") as f:
            json.dump(har_data, f, indent=2)

        logger.info(f"Exported HAR: {har_path} ({len(self.requests)} requests)")

        return har_path

    def export_json(self, output_path: str | None = None) -> Path:
        """Exports captured traffic to JSON format.

        Args:
            output_path: Optional custom output path

        Returns:
            Path to generated JSON file
        """
        if output_path:
            json_path = Path(output_path)
        else:
            json_path = self.output_dir / f"traffic_{self.session_id}.json"

        json_path.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "session_id": self.session_id,
            "captured_at": datetime.now(UTC).isoformat(),
            "total_requests": len(self.requests),
            "requests": [req.to_dict() for req in self.requests],
        }

        with open(json_path, "w") as f:
            json.dump(data, f, indent=2)

        logger.info(f"Exported JSON: {json_path}")

        return json_path

    def filter_by_adapter(self, adapter_name: str) -> list[CapturedRequest]:
        """Filters requests by adapter name.

        Args:
            adapter_name: Adapter to filter by

        Returns:
            Filtered list of requests
        """
        return [req for req in self.requests if req.adapter_name == adapter_name]

    def filter_by_tags(self, tags: list[str]) -> list[CapturedRequest]:
        """Filters requests by evidence tags.

        Args:
            tags: Tags to filter by (any match)

        Returns:
            Filtered list of requests
        """
        return [req for req in self.requests if any(tag in req.evidence_tags for tag in tags)]

    def get_statistics(self) -> dict[str, Any]:
        """Gets statistics about captured traffic.

        Returns:
            Statistics dict with counts, timing, adapters
        """
        if not self.requests:
            return {
                "total_requests": 0,
                "adapters": [],
                "avg_response_time_ms": 0,
                "total_response_time_ms": 0,
            }

        adapters = {}
        total_time = 0

        for req in self.requests:
            adapters[req.adapter_name] = adapters.get(req.adapter_name, 0) + 1
            total_time += req.response_time_ms

        return {
            "total_requests": len(self.requests),
            "adapters": adapters,
            "avg_response_time_ms": total_time / len(self.requests),
            "total_response_time_ms": total_time,
            "evidence_tags": self._count_tags(),
        }

    def _count_tags(self) -> dict[str, int]:
        """Counts evidence tags across all requests.

        Returns:
            Dict of tag -> count
        """
        tag_counts = {}
        for req in self.requests:
            for tag in req.evidence_tags:
                tag_counts[tag] = tag_counts.get(tag, 0) + 1
        return tag_counts

    def close(self) -> None:
        """Closes database connection and finalizes capture."""
        if self._db_conn:
            self._db_conn.close()
            self._db_conn = None

        logger.info(f"Traffic capture closed: {len(self.requests)} requests captured")
