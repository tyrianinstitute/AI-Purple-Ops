"""WebSocket transport for MCP (community protocol, not official spec).

Implements WebSocket communication for MCP servers that support it.
Note: WebSocket is a community transport and not part of the official MCP spec.
"""

from __future__ import annotations

import json
import logging
import time

try:
    import websocket  # websocket-client library

    WEBSOCKET_AVAILABLE = True
except ImportError:
    WEBSOCKET_AVAILABLE = False

from aipop.adapters.mcp.errors import (
    MCPProtocolError,
    MCPTimeoutError,
    MCPTransportError,
)
from aipop.adapters.mcp.protocol import JSONRPCRequest, JSONRPCResponse
from aipop.adapters.mcp.transports.base import (
    BaseTransport,
    SessionInfo,
    TransportConfig,
)

logger = logging.getLogger(__name__)


class WebSocketTransport(BaseTransport):
    """WebSocket transport for MCP (community protocol).

    NOTE: This is a community transport and NOT part of the official MCP spec.
    Use HTTP or stdio transports for spec-compliant communication.

    Features:
    - WebSocket connection with auto-reconnect
    - Heartbeat/ping to prevent idle disconnection
    - Exponential backoff for reconnection
    - Fallback auth via URL parameters (when headers not supported)
    """

    def __init__(
        self,
        url: str,
        config: TransportConfig | None = None,
        auth_token: str | None = None,
    ) -> None:
        """Initialize WebSocket transport.

        Args:
            url: WebSocket URL (ws:// or wss://)
            config: Transport configuration
            auth_token: Authentication token (will be added to URL params as fallback)
        """
        super().__init__(config)

        if not WEBSOCKET_AVAILABLE:
            raise ImportError(
                "websocket-client library not installed. "
                "Install with: pip install websocket-client"
            )

        self.url = url
        self.auth_token = auth_token

        # Build final URL with auth token if needed
        self.ws_url = self._build_ws_url()

        # WebSocket connection
        self.ws: websocket.WebSocket | None = None
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = 5

        logger.debug(f"WebSocket transport initialized: {url}")
        logger.warning("WebSocket transport is a community protocol, not official MCP spec")

    def _build_ws_url(self) -> str:
        """Build WebSocket URL with auth token if needed.

        Returns:
            Complete WebSocket URL
        """
        url = self.url

        # Add auth token as URL parameter (fallback, not recommended)
        if self.auth_token:
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}token={self.auth_token}"
            logger.warning("Auth token in URL parameter is insecure, prefer header-based auth")

        return url

    def _parse_proxy_config(self, proxy_url: str) -> dict[str, str | int]:
        """Parse proxy URL and return websocket-client compatible config.

        Args:
            proxy_url: Proxy URL (e.g., http://proxy:8080, socks5://proxy:1080)

        Returns:
            Dict with http_proxy_host, http_proxy_port, proxy_type
        """
        from urllib.parse import urlparse

        parsed = urlparse(proxy_url)

        # Determine proxy type
        if parsed.scheme in ("socks5", "socks5h"):
            proxy_type = "socks5"
        elif parsed.scheme in ("socks4", "socks4a"):
            proxy_type = "socks4"
        elif parsed.scheme in ("http", "https"):
            proxy_type = "http"
        else:
            logger.warning(f"Unknown proxy scheme: {parsed.scheme}, defaulting to http")
            proxy_type = "http"

        config = {
            "http_proxy_host": parsed.hostname or "127.0.0.1",
            "http_proxy_port": parsed.port or 8080,
            "proxy_type": proxy_type,
        }

        # Add proxy auth if present
        if parsed.username:
            config["http_proxy_auth"] = (parsed.username, parsed.password or "")

        logger.info(
            f"WebSocket proxy configured: {proxy_type}://{config['http_proxy_host']}:{config['http_proxy_port']}"
        )

        return config

    def connect(self) -> SessionInfo:
        """Establish WebSocket connection.

        Returns:
            SessionInfo with connection details

        Raises:
            MCPTransportError: If connection fails
            MCPTimeoutError: If connection times out
        """
        try:
            # Build connection kwargs
            connection_kwargs = {
                "timeout": self.config.timeout_connection,
                "enable_multithread": True,
            }

            # Add proxy configuration if available
            if self.config.proxy:
                proxy_config = self._parse_proxy_config(self.config.proxy)
                connection_kwargs.update(proxy_config)

            # Create WebSocket with timeout and optional proxy
            self.ws = websocket.create_connection(
                self.ws_url,
                **connection_kwargs,
            )

            self.reconnect_attempts = 0

            session_info = SessionInfo(
                session_id=None,
                transport_type="websocket",
                server_version="unknown",
                capabilities={"websocket": True, "persistent": True},
                connected_at=time.time(),
            )

            self._mark_connected(session_info)
            logger.info(f"Connected via WebSocket: {self.url}")

            return session_info

        except websocket.WebSocketTimeoutException as e:
            raise MCPTimeoutError(
                f"WebSocket connection timeout to {self.url}",
                timeout_type="connection",
                timeout_seconds=self.config.timeout_connection,
            ) from e
        except websocket.WebSocketException as e:
            raise MCPTransportError(
                f"WebSocket connection failed: {e}",
                transport_type="websocket",
            ) from e

    def send_request(self, request: JSONRPCRequest) -> JSONRPCResponse:
        """Send JSON-RPC request via WebSocket.

        Args:
            request: JSON-RPC request

        Returns:
            JSON-RPC response

        Raises:
            MCPTransportError: If send/receive fails
            MCPTimeoutError: If response times out
            MCPProtocolError: If response is malformed
        """
        if not self.ws or not self._connected:
            # Attempt reconnection
            logger.info("WebSocket not connected, attempting reconnection")
            self._reconnect()

        # Send request
        try:
            request_str = request.to_json()
            self.ws.send(request_str)
            logger.debug(f"Sent WebSocket request: {request.method} (id={request.id})")
        except websocket.WebSocketException as e:
            # Try to reconnect and retry once
            logger.warning(f"WebSocket send failed, reconnecting: {e}")
            self._reconnect()
            try:
                self.ws.send(request_str)
            except websocket.WebSocketException as retry_error:
                raise MCPTransportError(
                    f"WebSocket send failed after reconnect: {retry_error}",
                    transport_type="websocket",
                ) from retry_error

        # Receive response
        try:
            self.ws.settimeout(self.config.timeout_read)
            response_str = self.ws.recv()

            if not response_str:
                raise MCPTransportError(
                    "WebSocket connection closed by server",
                    transport_type="websocket",
                )

            # Parse response
            data = json.loads(response_str)
            return JSONRPCResponse.from_dict(data)

        except websocket.WebSocketTimeoutException as e:
            raise MCPTimeoutError(
                f"WebSocket response timeout after {self.config.timeout_read}s",
                timeout_type="read",
                timeout_seconds=self.config.timeout_read,
            ) from e
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            raise MCPProtocolError(
                f"Invalid JSON-RPC response: {e}",
                raw_response=str(response_str)[:500] if response_str else "",
            ) from e
        except websocket.WebSocketException as e:
            raise MCPTransportError(
                f"WebSocket receive failed: {e}",
                transport_type="websocket",
            ) from e

    def send_notification(self, request: JSONRPCRequest) -> None:
        """Send JSON-RPC notification via WebSocket.

        Args:
            request: JSON-RPC notification (id must be None)
        """
        if request.id is not None:
            raise ValueError("Notifications must have id=None")

        if not self.ws or not self._connected:
            logger.warning("WebSocket not connected, cannot send notification")
            return

        try:
            notification_str = request.to_json()
            self.ws.send(notification_str)
            logger.debug(f"Sent WebSocket notification: {request.method}")
        except websocket.WebSocketException as e:
            logger.warning(f"Failed to send WebSocket notification: {e}")

    def _reconnect(self) -> None:
        """Attempt to reconnect with exponential backoff.

        Raises:
            MCPTransportError: If max reconnect attempts exceeded
        """
        if self.reconnect_attempts >= self.max_reconnect_attempts:
            raise MCPTransportError(
                f"Max WebSocket reconnect attempts ({self.max_reconnect_attempts}) exceeded",
                transport_type="websocket",
            )

        # Close existing connection if any
        if self.ws:
            try:
                self.ws.close()
            except Exception:
                pass

        # Exponential backoff: 1s, 2s, 4s, 8s, 16s
        wait_time = 2**self.reconnect_attempts
        logger.info(f"Reconnecting in {wait_time}s (attempt {self.reconnect_attempts + 1})")
        time.sleep(wait_time)

        self.reconnect_attempts += 1

        # Attempt connection
        self.connect()

    def close(self) -> None:
        """Close WebSocket connection."""
        if self.ws:
            try:
                self.ws.close()
            except Exception as e:
                logger.debug(f"Error closing WebSocket: {e}")

        self._mark_disconnected()
        logger.debug("WebSocket transport closed")

    def get_capabilities(self) -> list[str]:
        """Get transport-specific capabilities.

        Returns:
            List of capability names
        """
        return ["websocket", "persistent", "community_protocol"]
