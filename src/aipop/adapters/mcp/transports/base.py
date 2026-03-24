"""Abstract transport protocol for MCP communication.

Defines the interface that all MCP transports must implement,
allowing seamless switching between HTTP, stdio, and WebSocket.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from aipop.adapters.mcp.protocol import JSONRPCRequest, JSONRPCResponse


@dataclass
class TransportConfig:
    """Configuration for transport layer.

    Attributes:
        timeout_connection: Connection timeout in seconds
        timeout_read: Read timeout in seconds
        timeout_write: Write timeout in seconds
        timeout_idle: Idle timeout for SSE streams in seconds
        max_retries: Maximum retry attempts
        proxy: HTTP/SOCKS5 proxy URL (e.g., http://proxy:8080)
        verify_tls: Verify TLS certificates
        custom_headers: Additional HTTP headers
    """

    timeout_connection: int = 30
    timeout_read: int = 120
    timeout_write: int = 10
    timeout_idle: int = 300
    max_retries: int = 3
    proxy: str | None = None
    verify_tls: bool = True
    custom_headers: dict[str, str] | None = None


@dataclass
class SessionInfo:
    """Information about active MCP session.

    Attributes:
        session_id: Server-assigned session identifier
        transport_type: Transport used (http, stdio, websocket)
        server_version: MCP protocol version server supports
        capabilities: Server capabilities from initialize response
        connected_at: Timestamp when connection was established
    """

    session_id: str | None
    transport_type: str
    server_version: str | None
    capabilities: dict[str, Any]
    connected_at: float


class MCPTransport(Protocol):
    """Abstract protocol for MCP transport implementations.

    All transports must implement these methods to provide a uniform
    interface for protocol-level code.
    """

    def connect(self) -> SessionInfo:
        """Establish connection to MCP server.

        Returns:
            SessionInfo with connection details

        Raises:
            MCPTransportError: If connection fails
            MCPTimeoutError: If connection times out
        """
        ...

    def send_request(self, request: JSONRPCRequest) -> JSONRPCResponse:
        """Send JSON-RPC request and receive response.

        Args:
            request: JSON-RPC request to send

        Returns:
            JSON-RPC response from server

        Raises:
            MCPTransportError: If send/receive fails
            MCPTimeoutError: If request times out
            MCPProtocolError: If response is malformed
        """
        ...

    def send_notification(self, request: JSONRPCRequest) -> None:
        """Send JSON-RPC notification (no response expected).

        Args:
            request: JSON-RPC notification (id must be None)

        Raises:
            MCPTransportError: If send fails
        """
        ...

    def is_connected(self) -> bool:
        """Check if transport is currently connected.

        Returns:
            True if connected and ready for requests
        """
        ...

    def close(self) -> None:
        """Close connection and clean up resources.

        Should be idempotent (safe to call multiple times).
        """
        ...

    def get_capabilities(self) -> list[str]:
        """Get transport-specific capabilities.

        Returns:
            List of capability names (e.g., ["streaming", "batch"])
        """
        ...


class BaseTransport:
    """Base implementation with common transport functionality.

    Provides shared utilities for all transport types:
    - Configuration management
    - Connection state tracking
    - Error handling helpers
    """

    def __init__(self, config: TransportConfig | None = None) -> None:
        """Initialize base transport.

        Args:
            config: Transport configuration (uses defaults if None)
        """
        self.config = config or TransportConfig()
        self._connected = False
        self._session_info: SessionInfo | None = None

    def is_connected(self) -> bool:
        """Check if transport is connected."""
        return self._connected

    def _mark_connected(self, session_info: SessionInfo) -> None:
        """Mark transport as connected and store session info.

        Args:
            session_info: Session information from connection
        """
        self._connected = True
        self._session_info = session_info

    def _mark_disconnected(self) -> None:
        """Mark transport as disconnected."""
        self._connected = False
        self._session_info = None

    def get_session_info(self) -> SessionInfo | None:
        """Get current session information.

        Returns:
            SessionInfo if connected, None otherwise
        """
        return self._session_info

    def _build_proxy_config(self) -> dict[str, str] | None:
        """Build proxy configuration from config and environment.

        Returns:
            Proxy dict for requests library or None
        """
        if self.config.proxy:
            return {
                "http": self.config.proxy,
                "https": self.config.proxy,
            }
        return None
