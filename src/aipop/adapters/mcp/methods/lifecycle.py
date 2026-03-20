"""Lifecycle methods: initialize, initialized, shutdown.

These methods manage the MCP session lifecycle and are handled
by the SessionManager. This module provides convenience wrappers.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aipop.adapters.mcp.session import ServerInfo, SessionManager

logger = logging.getLogger(__name__)


class LifecycleMethods:
    """Convenience wrapper for lifecycle methods.

    Note: The actual initialize/initialized/shutdown logic is implemented
    in SessionManager. This class provides method documentation and
    helper functions.
    """

    def __init__(self, session_manager: SessionManager) -> None:
        """Initialize lifecycle methods wrapper.

        Args:
            session_manager: Session manager instance
        """
        self.session_manager = session_manager

    def initialize(self) -> ServerInfo:
        """Perform initialize handshake.

        This is the first method called when connecting to an MCP server.
        It negotiates protocol version and exchanges capabilities.

        Returns:
            ServerInfo with server name, version, and protocol version

        Raises:
            MCPSessionError: If initialization fails

        Example:
            >>> lifecycle = LifecycleMethods(session_manager)
            >>> server_info = lifecycle.initialize()
            >>> print(f"Connected to {server_info.name} v{server_info.version}")
        """
        return self.session_manager.initialize()

    def send_initialized(self) -> None:
        """Send initialized notification.

        This is automatically called by SessionManager after initialize.
        You typically don't need to call this manually.

        Note:
            This is a notification (no response expected).
        """
        self.session_manager._send_initialized_notification()

    def shutdown(self) -> None:
        """Gracefully shutdown MCP session.

        Sends shutdown request (if server supports it) and closes transport.
        Call this when done with the MCP server to clean up resources.

        Example:
            >>> lifecycle.shutdown()
            >>> # Server connection is now closed
        """
        self.session_manager.shutdown()

    def reinitialize(self) -> ServerInfo:
        """Reinitialize session after expiry.

        This is automatically called by SessionManager when it detects
        session expiry. You can also call it manually to refresh the session.

        Returns:
            ServerInfo from new session
        """
        return self.session_manager.reinitialize()
