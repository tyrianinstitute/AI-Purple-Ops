"""MCP method implementations.

Implements all MCP spec methods:
- Lifecycle: initialize, initialized, shutdown
- Tools: tools/list, tools/call
- Resources: resources/list, resources/read, resources/templates/list
- Prompts: prompts/list, prompts/get
- Completion: completion/complete
- Logging: logging/setLevel, notifications/message
"""

from __future__ import annotations

__all__ = [
    "CompletionMethods",
    "LifecycleMethods",
    "LoggingMethods",
    "PromptsMethods",
    "ResourcesMethods",
    "ToolsMethods",
]


# Lazy imports
def __getattr__(name: str):
    """Lazy import to avoid loading heavy dependencies until needed."""
    if name == "LifecycleMethods":
        from aipop.adapters.mcp.methods.lifecycle import LifecycleMethods

        return LifecycleMethods
    if name == "ToolsMethods":
        from aipop.adapters.mcp.methods.tools import ToolsMethods

        return ToolsMethods
    if name == "ResourcesMethods":
        from aipop.adapters.mcp.methods.resources import ResourcesMethods

        return ResourcesMethods
    if name == "PromptsMethods":
        from aipop.adapters.mcp.methods.prompts import PromptsMethods

        return PromptsMethods
    if name == "CompletionMethods":
        from aipop.adapters.mcp.methods.completion import CompletionMethods

        return CompletionMethods
    if name == "LoggingMethods":
        from aipop.adapters.mcp.methods.logging import LoggingMethods

        return LoggingMethods
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
