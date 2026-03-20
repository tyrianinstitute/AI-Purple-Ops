"""MCP response parser for hint extraction and context-aware pivoting.

Analyzes MCP tool responses to extract:
- Tool discoveries (new functions mentioned in errors)
- File path hints
- Success/failure signals
- Actionable intelligence for next steps
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ParsedHints:
    """Hints extracted from MCP tool response.

    Attributes:
        tools_discovered: New tool names found in response
        file_paths: File paths mentioned in response
        secrets_hinted: Hints about secrets/flags (without full disclosure)
        error_type: Type of error (permission, not_found, syntax, etc.)
        success: Whether operation succeeded
        actionable_next_steps: Suggested next actions
        raw_text: Original response text (first 500 chars)
    """

    tools_discovered: list[str]
    file_paths: list[str]
    secrets_hinted: list[str]
    error_type: str | None
    success: bool
    actionable_next_steps: list[str]
    raw_text: str


class MCPResponseParser:
    """Parses MCP tool responses for actionable intelligence.

    Used by orchestrator to make intelligent decisions about next steps.
    """

    # Patterns for tool discovery
    TOOL_PATTERNS = [
        r"call the (\w+) (?:function|tool)",
        r"(?:function|tool) (?:named |called )?(\w+)",
        r"available (?:functions|tools): ([\w, ]+)",
        r"you (?:can|may) use (\w+)",
        r"try calling (\w+)",
    ]

    # Patterns for file path extraction
    FILE_PATH_PATTERNS = [
        r"(/[a-zA-Z0-9_\-./]+)",  # Unix paths
        r"([A-Z]:\\[a-zA-Z0-9_\-\\]+)",  # Windows paths
        r"(~/[a-zA-Z0-9_\-./]+)",  # Home directory paths
    ]

    # Error type indicators
    ERROR_INDICATORS = {
        "permission": ["permission denied", "unauthorized", "access denied", "forbidden"],
        "not_found": ["not found", "does not exist", "no such file", "404"],
        "syntax": ["syntax error", "invalid syntax", "parse error"],
        "invalid_params": ["invalid parameter", "missing parameter", "wrong type"],
        "rate_limit": ["rate limit", "too many requests", "throttled"],
        "timeout": ["timeout", "timed out", "connection timeout"],
    }

    # Success indicators
    SUCCESS_INDICATORS = [
        "success",
        "completed",
        "ok",
        "retrieved",
        "found",
        "returned",
    ]

    def parse(self, response: Any, tool_name: str = "") -> ParsedHints:  # noqa: ANN401
        """Parse MCP tool response for hints.

        Args:
            response: Tool response (ToolResult object or string)
            tool_name: Name of tool that produced this response

        Returns:
            ParsedHints with extracted intelligence
        """
        # Convert to string
        from aipop.adapters.mcp.methods.tools import ToolResult

        if isinstance(response, ToolResult):
            if response.is_error:
                text = response.error_message or ""
                is_error = True
            else:
                text = str(response.content)
                is_error = False
        else:
            text = str(response)
            is_error = "error" in text.lower()

        # Extract tools
        tools_discovered = self._extract_tools(text)

        # Extract file paths
        file_paths = self._extract_file_paths(text)

        # Detect secrets hints (not full secrets, just hints)
        secrets_hinted = self._extract_secret_hints(text)

        # Classify error type
        error_type = self._classify_error(text) if is_error else None

        # Determine success
        success = self._is_success(text, is_error)

        # Generate actionable next steps
        next_steps = self._suggest_next_steps(
            text, tools_discovered, file_paths, error_type, success
        )

        return ParsedHints(
            tools_discovered=tools_discovered,
            file_paths=file_paths,
            secrets_hinted=secrets_hinted,
            error_type=error_type,
            success=success,
            actionable_next_steps=next_steps,
            raw_text=text[:500],
        )

    def _extract_tools(self, text: str) -> list[str]:
        """Extract tool names mentioned in text.

        Args:
            text: Response text

        Returns:
            List of discovered tool names
        """
        tools = []
        text_lower = text.lower()

        for pattern in self.TOOL_PATTERNS:
            matches = re.findall(pattern, text_lower, re.IGNORECASE)
            for match in matches:
                # Handle comma-separated lists
                if "," in match:
                    tools.extend(t.strip() for t in match.split(","))
                else:
                    tools.append(match.strip())

        # Deduplicate and clean
        tools = [t for t in set(tools) if t and len(t) > 2]

        if tools:
            logger.info(f"🔍 Discovered tools: {tools}")

        return tools

    def _extract_file_paths(self, text: str) -> list[str]:
        """Extract file paths from text.

        Args:
            text: Response text

        Returns:
            List of file paths
        """
        paths = []

        for pattern in self.FILE_PATH_PATTERNS:
            matches = re.findall(pattern, text)
            paths.extend(matches)

        # Filter out obvious false positives
        paths = [p for p in set(paths) if len(p) > 3 and not p.endswith("...")]

        if paths:
            logger.debug(f"Found file paths: {paths}")

        return paths

    def _extract_secret_hints(self, text: str) -> list[str]:
        """Extract hints about secrets (not the secrets themselves).

        Args:
            text: Response text

        Returns:
            List of hints like "the secret is a color" or "password is 8 digits"
        """
        hints = []
        text_lower = text.lower()

        # Patterns that suggest secret hints
        hint_patterns = [
            r"(?:secret|password|flag) is (?:a |an )?([a-zA-Z\s]+)",
            r"(?:secret|password|flag) has (\d+) (?:characters|digits|letters)",
            r"(?:secret|password|flag) starts with ([a-zA-Z0-9])",
            r"(?:secret|password|flag) contains ([a-zA-Z\s]+)",
            r"hint: (.+)",
        ]

        for pattern in hint_patterns:
            matches = re.findall(pattern, text_lower)
            hints.extend(matches)

        if hints:
            logger.info(f"💡 Secret hints: {hints}")

        return hints

    def _classify_error(self, text: str) -> str | None:
        """Classify error type.

        Args:
            text: Error message text

        Returns:
            Error type string or None
        """
        text_lower = text.lower()

        for error_type, indicators in self.ERROR_INDICATORS.items():
            if any(ind in text_lower for ind in indicators):
                logger.debug(f"Error classified as: {error_type}")
                return error_type

        return "unknown" if "error" in text_lower else None

    def _is_success(self, text: str, is_error: bool) -> bool:
        """Determine if operation was successful.

        Args:
            text: Response text
            is_error: Whether response indicates error

        Returns:
            True if successful
        """
        if is_error:
            return False

        text_lower = text.lower()

        # Check for explicit success indicators
        if any(ind in text_lower for ind in self.SUCCESS_INDICATORS):
            return True

        # Heuristic: if response has substantial content, likely success
        if len(text) > 50 and not any(neg in text_lower for neg in ["error", "failed", "denied"]):
            return True

        return False

    def _suggest_next_steps(
        self,
        text: str,
        tools_discovered: list[str],
        file_paths: list[str],
        error_type: str | None,
        success: bool,
    ) -> list[str]:
        """Generate actionable next step suggestions.

        Args:
            text: Response text
            tools_discovered: Discovered tool names
            file_paths: Discovered file paths
            error_type: Error classification
            success: Whether operation succeeded

        Returns:
            List of suggested actions
        """
        suggestions = []

        # Tool discoveries suggest calling them
        for tool in tools_discovered:
            suggestions.append(f"Call the '{tool}' tool")

        # File paths suggest reading them
        for path in file_paths[:3]:  # Limit to avoid spam
            suggestions.append(f"Try reading file: {path}")

        # Error-specific suggestions
        if error_type == "permission":
            suggestions.append("Try path traversal to escape restricted directory")
            suggestions.append("Enumerate accessible files/directories")

        elif error_type == "not_found":
            suggestions.append("Try common secret file paths (/flag.txt, /.env)")
            suggestions.append("Try path variations (flag, FLAG, flag.txt)")

        elif error_type == "syntax":
            suggestions.append("Try encoding the payload (URL encode, Base64)")
            suggestions.append("Try escaping special characters")

        elif error_type == "invalid_params":
            suggestions.append("Review tool schema for required parameters")
            suggestions.append("Try minimal valid input")

        # Success-specific suggestions
        if success:
            if len(text) > 200:
                suggestions.append("Parse response for flags/secrets")
                suggestions.append("Check for embedded file paths or tool references")
            else:
                suggestions.append("Response short - try expanding query scope")

        return suggestions


class MCPConversationState:
    """Maintains state across multi-turn MCP exploitation.

    Tracks:
    - Tools discovered and called
    - Files accessed
    - Errors encountered
    - Flags/secrets found
    - Attack history
    """

    def __init__(self) -> None:
        """Initialize conversation state."""
        self.tools_discovered: set[str] = set()
        self.tools_called: dict[str, int] = {}  # tool_name -> call_count
        self.files_accessed: set[str] = set()
        self.errors_encountered: list[tuple[str, str]] = []  # (tool, error_type)
        self.flags_found: list[str] = []
        self.secrets_found: list[str] = []
        self.parser = MCPResponseParser()

    def update(
        self, tool_name: str, response: Any, result_score: Any = None
    ) -> ParsedHints:  # noqa: ANN401
        """Update state based on tool response.

        Args:
            tool_name: Tool that was called
            response: Tool response
            result_score: Optional scorer result

        Returns:
            Parsed hints from response
        """
        # Parse response
        hints = self.parser.parse(response, tool_name)

        # Update state
        self.tools_discovered.update(hints.tools_discovered)

        if tool_name not in self.tools_called:
            self.tools_called[tool_name] = 0
        self.tools_called[tool_name] += 1

        self.files_accessed.update(hints.file_paths)

        if hints.error_type:
            self.errors_encountered.append((tool_name, hints.error_type))

        # Update flags/secrets from scorer if provided
        if result_score and hasattr(result_score, "flags_found"):
            for flag in result_score.flags_found:
                if flag not in self.flags_found:
                    self.flags_found.append(flag)
                    logger.info(f"🎯 FLAG CAPTURED: {flag}")

        if result_score and hasattr(result_score, "secrets_found"):
            self.secrets_found.extend(result_score.secrets_found)

        return hints

    def get_summary(self) -> str:
        """Get human-readable state summary.

        Returns:
            Markdown summary of conversation state
        """
        lines = ["# Attack State Summary\n"]

        lines.append(f"**Tools Discovered:** {len(self.tools_discovered)}")
        if self.tools_discovered:
            lines.append(f"  - {', '.join(self.tools_discovered)}\n")

        lines.append(f"**Tools Called:** {sum(self.tools_called.values())} total")
        if self.tools_called:
            for tool, count in self.tools_called.items():
                lines.append(f"  - {tool}: {count}x")
        lines.append("")

        lines.append(f"**Files Accessed:** {len(self.files_accessed)}")
        if self.files_accessed:
            for path in list(self.files_accessed)[:10]:
                lines.append(f"  - {path}")
        lines.append("")

        lines.append(f"**Errors Encountered:** {len(self.errors_encountered)}")
        error_summary = {}
        for _, error_type in self.errors_encountered:
            error_summary[error_type] = error_summary.get(error_type, 0) + 1
        for error_type, count in error_summary.items():
            lines.append(f"  - {error_type}: {count}x")
        lines.append("")

        lines.append(f"**🚩 Flags Found:** {len(self.flags_found)}")
        for flag in self.flags_found:
            lines.append(f"  - {flag}")
        lines.append("")

        lines.append(f"**🔑 Secrets Exfiltrated:** {len(self.secrets_found)}")

        return "\n".join(lines)

    def should_pivot(self) -> bool:
        """Determine if attack should pivot to new strategy.

        Returns:
            True if pivot recommended
        """
        # Pivot if same tool called too many times unsuccessfully
        for tool, count in self.tools_called.items():
            if count > 5 and not self.flags_found:
                logger.info(f"Pivot recommended: '{tool}' called {count}x with no flags")
                return True

        # Pivot if too many permission errors
        permission_errors = [e for e in self.errors_encountered if e[1] == "permission"]
        if len(permission_errors) > 3:
            logger.info("Pivot recommended: repeated permission errors")
            return True

        return False

    def get_next_untried_tool(self) -> str | None:
        """Get a discovered tool that hasn't been called yet.

        Returns:
            Tool name or None
        """
        for tool in self.tools_discovered:
            if tool not in self.tools_called:
                return tool
        return None
