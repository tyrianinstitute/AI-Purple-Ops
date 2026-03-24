"""MCP transport layer implementations.

Supports three transport types:
- HTTP: Streamable POST+SSE (2025 spec) and legacy HTTP+SSE fallback
- stdio: Local process communication via stdin/stdout
- WebSocket: Community transport (not official spec)

All transports implement the MCPTransport protocol for uniform interface.
"""

from __future__ import annotations

__all__ = ["HTTPTransport", "MCPTransport", "StdioTransport", "WebSocketTransport"]


# Lazy imports
def __getattr__(name: str):
    """Lazy import to avoid loading heavy dependencies until needed."""
    if name == "MCPTransport":
        from aipop.adapters.mcp.transports.base import MCPTransport

        return MCPTransport
    if name == "HTTPTransport":
        from aipop.adapters.mcp.transports.http import HTTPTransport

        return HTTPTransport
    if name == "StdioTransport":
        from aipop.adapters.mcp.transports.stdio import StdioTransport

        return StdioTransport
    if name == "WebSocketTransport":
        from aipop.adapters.mcp.transports.websocket import WebSocketTransport

        return WebSocketTransport
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
