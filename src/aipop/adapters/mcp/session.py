"""MCP session management with initialize handshake and capability negotiation.

Handles the complete session lifecycle:
1. Initialize handshake with version negotiation
2. Capability parsing and validation
3. Session state tracking
4. Session expiry detection and auto-reinitialize
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from aipop.adapters.mcp.capabilities import (
    CapabilityValidator,
    ServerCapabilities,
)
from aipop.adapters.mcp.errors import MCPSessionError
from aipop.adapters.mcp.protocol import (
    JSONRPCResponse,
    create_request,
)
from aipop.adapters.mcp.transports.base import MCPTransport

logger = logging.getLogger(__name__)


# MCP protocol version we support
SUPPORTED_PROTOCOL_VERSIONS = ["1.1", "1.0", "2024-11-05", "2025-03-26", "2025-06-18"]
PREFERRED_VERSION = "1.1"


@dataclass
class ClientInfo:
    """Client information sent during initialize.

    Attributes:
        name: Client name (AI Purple Ops)
        version: Client version
    """

    name: str = "AI-Purple-Ops-MCP"
    version: str = "1.1.1"

    def to_dict(self) -> dict[str, str]:
        """Convert to dictionary for JSON-RPC."""
        return {"name": self.name, "version": self.version}


@dataclass
class ServerInfo:
    """Server information from initialize response.

    Attributes:
        name: Server name
        version: Server version
        protocol_version: MCP protocol version server uses
    """

    name: str
    version: str
    protocol_version: str

    @classmethod
    def from_initialize_response(cls, result: dict[str, Any]) -> ServerInfo:
        """Parse server info from initialize response.

        Args:
            result: Result object from initialize JSON-RPC response

        Returns:
            ServerInfo instance
        """
        server_info = result.get("serverInfo", {})
        return cls(
            name=server_info.get("name", "unknown"),
            version=server_info.get("version", "unknown"),
            protocol_version=result.get("protocolVersion", "unknown"),
        )


@dataclass
class SessionState:
    """Current MCP session state.

    Attributes:
        initialized: Whether initialize handshake completed
        session_id: Server-assigned session ID (if any)
        server_info: Server information from initialize
        capabilities: Server capabilities
        validator: Capability validator for method checking
        connected_at: Timestamp when session started
        last_activity: Timestamp of last successful request
    """

    initialized: bool = False
    session_id: str | None = None
    server_info: ServerInfo | None = None
    capabilities: ServerCapabilities | None = None
    validator: CapabilityValidator | None = None
    connected_at: float | None = None
    last_activity: float | None = None

    def is_active(self) -> bool:
        """Check if session is active and initialized."""
        return self.initialized and self.session_id is not None

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = time.time()

    def time_since_activity(self) -> float:
        """Get seconds since last activity.

        Returns:
            Seconds since last activity, or 0 if never active
        """
        if self.last_activity is None:
            return 0.0
        return time.time() - self.last_activity


class SessionManager:
    """Manages MCP session lifecycle and state.

    Responsibilities:
    - Perform initialize handshake with version negotiation
    - Parse and validate server capabilities
    - Detect session expiry and reinitialize automatically
    - Send initialized notification after handshake
    - Track session state and activity
    """

    def __init__(self, transport: MCPTransport, client_info: ClientInfo | None = None) -> None:
        """Initialize session manager.

        Args:
            transport: MCP transport (HTTP, stdio, WebSocket)
            client_info: Client information (defaults to AI Purple Ops)
        """
        self.transport = transport
        self.client_info = client_info or ClientInfo()
        self.state = SessionState()
        self.auto_reinitialize = True  # Auto-reinit on session expiry
        self.next_request_id = 1

        logger.debug("Session manager initialized")

    def initialize(self) -> ServerInfo:
        """Perform initialize handshake with server.

        Returns:
            ServerInfo from server

        Raises:
            MCPSessionError: If initialization fails
            MCPProtocolError: If response is malformed
        """
        logger.info("Starting MCP initialize handshake")

        # Build initialize request
        params = {
            "protocolVersion": PREFERRED_VERSION,
            "capabilities": self._get_client_capabilities(),
            "clientInfo": self.client_info.to_dict(),
        }

        request = create_request(
            method="initialize",
            params=params,
            request_id=self._get_next_id(),
        )

        # Send initialize request
        try:
            response = self.transport.send_request(request)
        except Exception as e:
            raise MCPSessionError(f"Initialize handshake failed: {e}") from e

        # Check for errors
        if response.is_error:
            error_msg = response.error.message if response.error else "Unknown error"
            raise MCPSessionError(f"Initialize failed: {error_msg}")

        # Parse response
        result = response.result or {}

        # Extract server info
        server_info = ServerInfo.from_initialize_response(result)

        # Validate protocol version
        if server_info.protocol_version not in SUPPORTED_PROTOCOL_VERSIONS:
            logger.warning(
                f"Server uses unsupported protocol version: {server_info.protocol_version}. "
                f"Supported versions: {SUPPORTED_PROTOCOL_VERSIONS}. "
                "Proceeding anyway, but compatibility issues may occur."
            )

        # Parse capabilities
        capabilities = ServerCapabilities.from_initialize_response(result)

        # Create validator
        validator = CapabilityValidator(capabilities)

        # Update session state
        self.state.initialized = True
        self.state.server_info = server_info
        self.state.capabilities = capabilities
        self.state.validator = validator
        self.state.connected_at = time.time()
        self.state.update_activity()

        logger.info(
            f"Initialize handshake complete: {server_info.name} v{server_info.version} "
            f"(protocol {server_info.protocol_version})"
        )
        logger.info(f"Capabilities: {capabilities.summary()}")

        # Send initialized notification
        self._send_initialized_notification()

        return server_info

    def _get_client_capabilities(self) -> dict[str, Any]:
        """Get client capabilities to send during initialize.

        Returns:
            Client capabilities dict
        """
        # We support all capabilities as a client
        return {
            "tools": {},
            "resources": {},
            "prompts": {},
            "completion": {},
            "logging": {},
        }

    def _send_initialized_notification(self) -> None:
        """Send initialized notification to server after handshake."""
        notification = create_request(
            method="initialized",
            params={},
            request_id=None,  # Notifications have no ID
        )

        try:
            self.transport.send_notification(notification)
            logger.debug("Sent initialized notification")
        except Exception as e:
            logger.warning(f"Failed to send initialized notification: {e}")

    def send_request(self, method: str, params: dict[str, Any] | None = None) -> JSONRPCResponse:
        """Send JSON-RPC request with session management.

        Args:
            method: JSON-RPC method name
            params: Method parameters

        Returns:
            JSON-RPC response

        Raises:
            MCPSessionError: If session not initialized or expired
            MCPMethodNotAvailableError: If method not supported
        """
        # Ensure session is initialized
        if not self.state.initialized:
            raise MCPSessionError(
                "Session not initialized. Call initialize() first.",
                session_id=self.state.session_id,
            )

        # Validate method against capabilities
        if self.state.validator and method != "initialize":
            try:
                self.state.validator.validate_method(method)
            except Exception:
                # Log but don't fail - some methods might not require capabilities
                logger.debug(f"Method validation skipped for: {method}")

        # Build request
        request = create_request(
            method=method,
            params=params,
            request_id=self._get_next_id(),
        )

        # Send request
        try:
            response = self.transport.send_request(request)
            self.state.update_activity()
        except Exception as e:
            # Check if this is a session expiry error
            if "session" in str(e).lower() or "expired" in str(e).lower():
                if self.auto_reinitialize:
                    logger.warning("Session expired, reinitializing")
                    self.reinitialize()
                    # Retry request
                    response = self.transport.send_request(request)
                    self.state.update_activity()
                else:
                    raise MCPSessionError(
                        "Session expired. Reinitialize to continue.",
                        session_id=self.state.session_id,
                    ) from e
            else:
                raise

        # Check for session expiry in response error
        if response.is_error and response.error:
            if response.error.code == -32001:  # Invalid session
                if self.auto_reinitialize:
                    logger.warning("Session expired (error -32001), reinitializing")
                    self.reinitialize()
                    # Retry request
                    request.id = self._get_next_id()  # New request ID
                    response = self.transport.send_request(request)
                    self.state.update_activity()
                else:
                    raise MCPSessionError(
                        f"Session expired: {response.error.message}",
                        session_id=self.state.session_id,
                    )

        return response

    def reinitialize(self) -> ServerInfo:
        """Reinitialize session after expiry.

        Returns:
            ServerInfo from new session
        """
        logger.info("Reinitializing session")
        self.state = SessionState()  # Reset state
        return self.initialize()

    def shutdown(self) -> None:
        """Gracefully shutdown session.

        Sends shutdown request if server supports it, then closes transport.
        """
        if not self.state.initialized:
            return

        # Try to send shutdown request (not all servers support this)
        try:
            request = create_request(
                method="shutdown",
                params={},
                request_id=self._get_next_id(),
            )
            self.transport.send_request(request)
            logger.info("Shutdown request sent")
        except Exception as e:
            logger.debug(f"Shutdown request failed (server may not support it): {e}")

        # Close transport
        self.transport.close()
        self.state = SessionState()  # Reset state
        logger.info("Session shutdown complete")

    def _get_next_id(self) -> int:
        """Get next request ID.

        Returns:
            Sequential request ID
        """
        request_id = self.next_request_id
        self.next_request_id += 1
        return request_id

    def get_capabilities(self) -> ServerCapabilities | None:
        """Get current server capabilities.

        Returns:
            ServerCapabilities if initialized, None otherwise
        """
        return self.state.capabilities

    def get_server_info(self) -> ServerInfo | None:
        """Get server information.

        Returns:
            ServerInfo if initialized, None otherwise
        """
        return self.state.server_info

    def is_initialized(self) -> bool:
        """Check if session is initialized.

        Returns:
            True if initialized, False otherwise
        """
        return self.state.initialized
