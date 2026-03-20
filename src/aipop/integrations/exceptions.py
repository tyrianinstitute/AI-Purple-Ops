"""Exceptions for tool integrations."""

from __future__ import annotations

from aipop.utils.errors import HarnessError


class ToolExecutionError(HarnessError):
    """Error during tool execution."""


class ToolNotAvailableError(HarnessError):
    """Tool is not installed or configured."""


class ToolOutputParseError(HarnessError):
    """Error parsing tool output."""
