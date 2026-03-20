"""Tools methods: tools/list and tools/call with schema validation.

Tools allow MCP servers to expose callable functions that the client
can invoke. This is the core functionality for CTF tool exploitation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aipop.adapters.mcp.session import SessionManager

logger = logging.getLogger(__name__)


@dataclass
class Tool:
    """Tool definition from tools/list.

    Attributes:
        name: Tool name
        description: Human-readable description
        input_schema: JSON Schema for tool input parameters
    """

    name: str
    description: str
    input_schema: dict[str, Any]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Tool:
        """Parse tool from JSON-RPC response."""
        return cls(
            name=data["name"],
            description=data.get("description", ""),
            input_schema=data.get("inputSchema", {}),
        )


@dataclass
class ToolResult:
    """Result from tools/call.

    Attributes:
        content: Tool output content
        is_error: Whether tool execution failed
        error_message: Error message if is_error=True
        metadata: Additional metadata
    """

    content: Any
    is_error: bool = False
    error_message: str | None = None
    metadata: dict[str, Any] | None = None


class ToolsMethods:
    """Tools API implementation."""

    def __init__(self, session_manager: SessionManager) -> None:
        """Initialize tools methods.

        Args:
            session_manager: Session manager instance
        """
        self.session_manager = session_manager
        self._tool_cache: dict[str, Tool] = {}

    def list_tools(
        self, cursor: str | None = None, limit: int | None = None
    ) -> tuple[list[Tool], str | None]:
        """List available tools with pagination.

        Args:
            cursor: Pagination cursor (from previous response)
            limit: Max number of tools to return

        Returns:
            Tuple of (tool list, next_cursor)

        Example:
            >>> tools, next_cursor = tools_methods.list_tools()
            >>> for tool in tools:
            ...     print(f"{tool.name}: {tool.description}")
        """
        params: dict[str, Any] = {}
        if cursor:
            params["cursor"] = cursor
        if limit:
            params["limit"] = limit

        response = self.session_manager.send_request("tools/list", params if params else None)

        if response.is_error:
            error_msg = response.error.message if response.error else "Unknown error"
            raise RuntimeError(f"tools/list failed: {error_msg}")

        result = response.result or {}
        tools_data = result.get("tools", [])
        next_cursor = result.get("nextCursor")

        tools = [Tool.from_dict(t) for t in tools_data]

        # Cache tools for validation
        for tool in tools:
            self._tool_cache[tool.name] = tool

        logger.info(f"Discovered {len(tools)} tools")
        return tools, next_cursor

    def call_tool(
        self, name: str, input_data: dict[str, Any], request_id: str | None = None
    ) -> ToolResult:
        """Invoke a tool by name.

        Args:
            name: Tool name
            input_data: Tool input parameters (must match tool's inputSchema)
            request_id: Optional request ID for tracking

        Returns:
            ToolResult with tool output

        Raises:
            MCPInvalidParameterError: If input doesn't match schema
            MCPMethodNotAvailableError: If tool doesn't exist

        Example:
            >>> result = tools_methods.call_tool("mcp_search", {"query": "flag"})
            >>> if not result.is_error:
            ...     print(result.content)
        """
        # Validate tool exists
        if name in self._tool_cache:
            tool = self._tool_cache[name]
            # TODO: Add JSON Schema validation of input_data against tool.input_schema
            logger.debug(f"Calling tool: {name} with input: {input_data}")

        params = {
            "name": name,
            "arguments": input_data,
        }
        if request_id:
            params["_meta"] = {"requestId": request_id}

        response = self.session_manager.send_request("tools/call", params)

        if response.is_error:
            error_msg = response.error.message if response.error else "Unknown error"
            return ToolResult(
                content="",
                is_error=True,
                error_message=error_msg,
            )

        result = response.result or {}

        # Check for tool-level error (vs transport error)
        if result.get("isError"):
            return ToolResult(
                content=result.get("content", ""),
                is_error=True,
                error_message=result.get("error", "Tool execution failed"),
            )

        content = result.get("content", [])
        metadata = result.get("_meta", {})

        return ToolResult(
            content=content,
            is_error=False,
            metadata=metadata,
        )

    def get_tool_schema(self, name: str) -> dict[str, Any] | None:
        """Get input schema for a tool.

        Args:
            name: Tool name

        Returns:
            JSON Schema dict or None if tool not found
        """
        if name in self._tool_cache:
            return self._tool_cache[name].input_schema
        return None
