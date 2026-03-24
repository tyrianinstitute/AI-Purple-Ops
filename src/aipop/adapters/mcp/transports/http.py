"""HTTP transport for MCP with streamable POST+SSE and legacy fallback.

Implements both modern streamable HTTP (2025-06-18 spec) and legacy HTTP+SSE
for backward compatibility. Supports proxy, rate limiting, and SSE streaming.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Generator
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from aipop.adapters.mcp.errors import (
    MCPProtocolError,
    MCPTimeoutError,
    MCPTransportError,
)
from aipop.adapters.mcp.protocol import (
    JSONRPCRequest,
    JSONRPCResponse,
    ProtocolNegotiator,
)
from aipop.adapters.mcp.transports.base import (
    BaseTransport,
    SessionInfo,
    TransportConfig,
)

logger = logging.getLogger(__name__)


class HTTPTransport(BaseTransport):
    """HTTP transport supporting streamable POST+SSE and legacy HTTP+SSE.

    Modern (2025 spec):
    - Single endpoint POST /mcp
    - Accept: application/json, text/event-stream
    - MCP-Session-Id header for session management
    - MCP-Protocol-Version header

    Legacy (2024 spec):
    - GET /mcp for SSE notifications
    - POST /messages?sessionId=... for requests

    Features:
    - Automatic transport detection and fallback
    - Connection pooling with keep-alive
    - Proxy support (HTTP CONNECT, SOCKS5)
    - Retry logic with exponential backoff
    - SSE streaming for long-running requests
    """

    def __init__(
        self,
        base_url: str,
        config: TransportConfig | None = None,
        auth_header: dict[str, str] | None = None,
    ) -> None:
        """Initialize HTTP transport.

        Args:
            base_url: Base URL of MCP server (e.g., https://example.com)
            config: Transport configuration
            auth_header: Authentication headers (e.g., {"Authorization": "Bearer token"})
        """
        super().__init__(config)
        self.base_url = base_url.rstrip("/")
        self.auth_header = auth_header or {}

        # Determine endpoint path
        self.endpoint_path = self._detect_endpoint_path()
        self.endpoint_url = urljoin(self.base_url, self.endpoint_path)

        # Session management
        self.session_id: str | None = None
        self.use_legacy_transport = False

        # Create requests session with retry logic
        self.session = self._create_session()

        logger.debug(f"HTTP transport initialized: {self.endpoint_url}")

    def _detect_endpoint_path(self) -> str:
        """Detect MCP endpoint path from URL.

        Returns:
            Endpoint path (e.g., /mcp, /api/mcp)
        """
        parsed = urlparse(self.base_url)
        path = parsed.path.rstrip("/")

        # If URL already includes path, use it
        if path and path != "/":
            return path

        # Default to /mcp
        return "/mcp"

    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic and connection pooling.

        Returns:
            Configured requests.Session
        """
        session = requests.Session()

        # Configure retry strategy
        retry_strategy = Retry(
            total=self.config.max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],
        )

        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=10,
            pool_maxsize=10,
        )

        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Set proxies from config or environment
        if self.config.proxy:
            session.proxies = self._build_proxy_config()
        else:
            # Respect environment variables (HTTP_PROXY, HTTPS_PROXY)
            session.trust_env = True

        # TLS verification
        session.verify = self.config.verify_tls

        return session

    def connect(self) -> SessionInfo:
        """Establish connection and test endpoint availability.

        Returns:
            SessionInfo with connection details

        Raises:
            MCPTransportError: If connection fails
            MCPTimeoutError: If connection times out
        """
        try:
            # Test connectivity with OPTIONS or HEAD
            headers = self._build_headers()

            response = self.session.head(
                self.endpoint_url,
                headers=headers,
                timeout=self.config.timeout_connection,
            )

            # Check for MCP-Protocol-Version header
            protocol_version = response.headers.get("MCP-Protocol-Version", "unknown")

            session_info = SessionInfo(
                session_id=self.session_id,
                transport_type="http",
                server_version=protocol_version,
                capabilities={"streaming": True},
                connected_at=time.time(),
            )

            self._mark_connected(session_info)
            logger.info(
                f"Connected to MCP server: {self.endpoint_url} (version: {protocol_version})"
            )

            return session_info

        except requests.Timeout as e:
            raise MCPTimeoutError(
                f"Connection timeout to {self.endpoint_url}",
                timeout_type="connection",
                timeout_seconds=self.config.timeout_connection,
            ) from e
        except requests.RequestException as e:
            raise MCPTransportError(
                f"Failed to connect to {self.endpoint_url}: {e}",
                transport_type="http",
            ) from e

    def send_request(self, request: JSONRPCRequest) -> JSONRPCResponse:
        """Send JSON-RPC request via HTTP POST.

        Args:
            request: JSON-RPC request

        Returns:
            JSON-RPC response

        Raises:
            MCPTransportError: If request fails
            MCPTimeoutError: If request times out
            MCPProtocolError: If response is malformed
        """
        headers = self._build_headers()
        headers["Content-Type"] = "application/json"
        headers["Accept"] = "application/json, text/event-stream"

        # Add session ID if available
        if self.session_id:
            headers["MCP-Session-Id"] = self.session_id

        try:
            response = self.session.post(
                self.endpoint_url,
                json=request.to_dict(),
                headers=headers,
                timeout=(self.config.timeout_connection, self.config.timeout_read),
                stream=True,  # Enable streaming for SSE
            )

            # Check for rate limiting
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After", "60")
                from aipop.adapters.mcp.errors import MCPRateLimitError

                raise MCPRateLimitError(
                    "Rate limit exceeded",
                    retry_after=int(retry_after) if retry_after.isdigit() else 60,
                    limit=int(response.headers.get("X-RateLimit-Limit", 0)),
                    remaining=int(response.headers.get("X-RateLimit-Remaining", 0)),
                )

            response.raise_for_status()

            # Extract session ID from response headers
            if "MCP-Session-Id" in response.headers:
                self.session_id = response.headers["MCP-Session-Id"]

            # Check content type for SSE vs JSON
            content_type = response.headers.get("Content-Type", "")

            if "text/event-stream" in content_type:
                # SSE streaming response
                return self._handle_sse_response(response, request.id)
            else:
                # Regular JSON response
                return self._handle_json_response(response)

        except requests.Timeout as e:
            raise MCPTimeoutError(
                f"Request timeout to {self.endpoint_url}",
                timeout_type="read",
                timeout_seconds=self.config.timeout_read,
            ) from e
        except requests.RequestException as e:
            # Check if we should try legacy transport
            if "404" in str(e) or "Not Found" in str(e):
                logger.warning("Modern endpoint failed, attempting legacy transport")
                self.use_legacy_transport = True
                return self._send_legacy_request(request)

            raise MCPTransportError(
                f"HTTP request failed: {e}",
                transport_type="http",
            ) from e

    def _handle_json_response(self, response: requests.Response) -> JSONRPCResponse:
        """Handle regular JSON response.

        Args:
            response: requests.Response object

        Returns:
            Parsed JSONRPCResponse

        Raises:
            MCPProtocolError: If response is not valid JSON or JSON-RPC
        """
        try:
            data = response.json()
        except json.JSONDecodeError as e:
            # Server might have returned HTML error page
            content_preview = response.text[:500]
            if response.text.strip().startswith("<"):
                raise MCPProtocolError(
                    f"Server returned HTML instead of JSON (status {response.status_code})",
                    raw_response=content_preview,
                ) from e
            raise MCPProtocolError(
                f"Invalid JSON response: {e}",
                raw_response=content_preview,
            ) from e

        # Verify JSON-RPC version
        version = ProtocolNegotiator.detect_version(data)
        if not ProtocolNegotiator.is_compatible(version):
            logger.warning(f"Server using JSON-RPC {version}, expected 2.0")

        try:
            return JSONRPCResponse.from_dict(data)
        except (KeyError, ValueError) as e:
            raise MCPProtocolError(
                f"Invalid JSON-RPC response: {e}",
                raw_response=str(data),
            ) from e

    def _handle_sse_response(
        self, response: requests.Response, request_id: str | int | None
    ) -> JSONRPCResponse:
        """Handle Server-Sent Events streaming response.

        Args:
            response: requests.Response with SSE stream
            request_id: Original request ID to match response

        Returns:
            Assembled JSONRPCResponse from SSE events

        Raises:
            MCPProtocolError: If SSE stream is malformed
        """
        # Parse SSE events
        events = list(self._parse_sse_stream(response))

        if not events:
            raise MCPProtocolError("Empty SSE stream")

        # For streaming responses, the last event should contain the final result
        # Earlier events may contain progress updates
        last_event = events[-1]

        try:
            return JSONRPCResponse.from_dict(last_event)
        except (KeyError, ValueError) as e:
            raise MCPProtocolError(
                f"Invalid SSE event data: {e}",
                raw_response=str(last_event),
            ) from e

    def _parse_sse_stream(
        self, response: requests.Response
    ) -> Generator[dict[str, Any], None, None]:
        """Parse Server-Sent Events stream.

        Args:
            response: requests.Response with SSE content

        Yields:
            Parsed JSON objects from SSE events
        """
        event_data = []

        for line in response.iter_lines(decode_unicode=True):
            if not line:
                # Empty line signals end of event
                if event_data:
                    # Join data lines and parse JSON
                    data_str = "\n".join(event_data)
                    try:
                        yield json.loads(data_str)
                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse SSE event data: {e}")
                    event_data = []
                continue

            if line.startswith("data:"):
                # Extract data payload
                data = line[5:].strip()
                if data:
                    event_data.append(data)
            elif line.startswith("event:"):
                # Event type (we can log this for debugging)
                event_type = line[6:].strip()
                logger.debug(f"SSE event type: {event_type}")
            elif line.startswith("id:"):
                # Event ID (ignore for now)
                pass
            elif line.startswith("retry:"):
                # Retry timeout (ignore for now)
                pass

    def _send_legacy_request(self, request: JSONRPCRequest) -> JSONRPCResponse:
        """Send request using legacy HTTP+SSE transport.

        Args:
            request: JSON-RPC request

        Returns:
            JSON-RPC response
        """
        # Legacy transport uses POST to /messages with sessionId query param
        legacy_url = urljoin(self.base_url, "/messages")

        params = {}
        if self.session_id:
            params["sessionId"] = self.session_id

        headers = self._build_headers()
        headers["Content-Type"] = "application/json"

        try:
            response = self.session.post(
                legacy_url,
                json=request.to_dict(),
                headers=headers,
                params=params,
                timeout=(self.config.timeout_connection, self.config.timeout_read),
            )

            response.raise_for_status()
            return self._handle_json_response(response)

        except requests.RequestException as e:
            raise MCPTransportError(
                f"Legacy transport request failed: {e}",
                transport_type="http-legacy",
            ) from e

    def send_notification(self, request: JSONRPCRequest) -> None:
        """Send JSON-RPC notification (no response expected).

        Args:
            request: JSON-RPC notification (id must be None)
        """
        if request.id is not None:
            raise ValueError("Notifications must have id=None")

        headers = self._build_headers()
        headers["Content-Type"] = "application/json"

        if self.session_id:
            headers["MCP-Session-Id"] = self.session_id

        try:
            self.session.post(
                self.endpoint_url,
                json=request.to_dict(),
                headers=headers,
                timeout=(self.config.timeout_connection, self.config.timeout_write),
            )
        except requests.RequestException as e:
            logger.warning(f"Failed to send notification: {e}")

    def _build_headers(self) -> dict[str, str]:
        """Build HTTP headers with auth and custom headers.

        Returns:
            Complete header dictionary
        """
        headers = {
            "User-Agent": "AI-Purple-Ops-MCP/1.1.1",
            "MCP-Protocol-Version": "1.1",
        }

        # Add auth headers
        headers.update(self.auth_header)

        # Add custom headers from config
        if self.config.custom_headers:
            headers.update(self.config.custom_headers)

        return headers

    def close(self) -> None:
        """Close HTTP session and clean up resources."""
        if self.session:
            self.session.close()
        self._mark_disconnected()
        logger.debug("HTTP transport closed")

    def get_capabilities(self) -> list[str]:
        """Get transport-specific capabilities.

        Returns:
            List of capability names
        """
        return ["streaming", "http", "proxy_support"]
