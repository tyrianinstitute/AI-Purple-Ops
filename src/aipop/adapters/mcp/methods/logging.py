"""Logging methods: logging/setLevel and notifications/message handlers."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from aipop.adapters.mcp.session import SessionManager

logger = logging.getLogger(__name__)

LogLevel = Literal["debug", "info", "notice", "warning", "error", "critical", "alert", "emergency"]


class LoggingMethods:
    """Logging API implementation."""

    def __init__(self, session_manager: SessionManager) -> None:
        """Initialize logging methods."""
        self.session_manager = session_manager

    def set_level(self, level: LogLevel) -> None:
        """Set server log level."""
        params = {"level": level}
        response = self.session_manager.send_request("logging/setLevel", params)

        if response.is_error:
            logger.warning(
                f"logging/setLevel failed: {response.error.message if response.error else 'Unknown'}"
            )
        else:
            logger.info(f"Server log level set to: {level}")

    def handle_log_message(self, message_data: dict) -> None:
        """Handle incoming log message notification from server."""
        level = message_data.get("level", "info")
        data = message_data.get("data", "")

        # Map MCP log levels to Python logging
        level_map = {
            "debug": logging.DEBUG,
            "info": logging.INFO,
            "notice": logging.INFO,
            "warning": logging.WARNING,
            "error": logging.ERROR,
            "critical": logging.CRITICAL,
            "alert": logging.CRITICAL,
            "emergency": logging.CRITICAL,
        }

        log_level = level_map.get(level, logging.INFO)
        logger.log(log_level, f"[MCP Server] {data}")
