"""Model Context Protocol (MCP) adapter implementation.

Provides full MCP v1.1 (2025-06-18) spec compliance with three transport layers
(HTTP POST+SSE, stdio, WebSocket) and dual-mode operation (target adapter + tool provider).

Key Features:
- Three transports: HTTP (streamable + legacy SSE), stdio, WebSocket
- Full spec: tools, resources, prompts, completion, logging
- Authentication: Bearer/API key (OAuth 2.1 planned for v1.1.2)
- Three discovery modes: manual, smart probe, full scan
- Rate limiting, caching, retry logic, circuit breakers
- Comprehensive diagnostics and troubleshooting

Example Usage:
    >>> from aipop.adapters.mcp_adapter import MCPAdapter
    >>> adapter = MCPAdapter.from_config("adapters/my_mcp_server.yaml")
    >>> response = adapter.invoke("List available tools")
    >>> print(response.text)
"""

from __future__ import annotations

__all__ = [
    "MCPAdapter",
    "MCPAuthError",
    "MCPError",
    "MCPProtocolError",
    "MCPSessionError",
    "MCPTransportError",
]


# Lazy imports to avoid circular dependencies
def __getattr__(name: str):
    """Lazy import to avoid loading heavy dependencies until needed."""
    if name == "MCPAdapter":
        from aipop.adapters.mcp_adapter import MCPAdapter

        return MCPAdapter
    if name == "MCPError":
        from aipop.adapters.mcp.errors import MCPError

        return MCPError
    if name == "MCPProtocolError":
        from aipop.adapters.mcp.errors import MCPProtocolError

        return MCPProtocolError
    if name == "MCPTransportError":
        from aipop.adapters.mcp.errors import MCPTransportError

        return MCPTransportError
    if name == "MCPAuthError":
        from aipop.adapters.mcp.errors import MCPAuthError

        return MCPAuthError
    if name == "MCPSessionError":
        from aipop.adapters.mcp.errors import MCPSessionError

        return MCPSessionError
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
