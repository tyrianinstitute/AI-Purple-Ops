"""MCP-specific scorers for flag detection and success measurement.

Detects CTF flags, secrets, and exploitation success in MCP tool responses.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class MCPScorerResult:
    """Result from MCP scorer evaluation.

    Attributes:
        success: Whether objective was achieved
        score: Numeric score (0.0 to 1.0)
        flags_found: List of detected flags
        secrets_found: List of detected secrets
        evidence: Raw evidence data
        explanation: Human-readable explanation
    """

    success: bool
    score: float
    flags_found: list[str]
    secrets_found: list[str]
    evidence: dict[str, Any]
    explanation: str


class FlagDetectionScorer:
    """Detects CTF flags in MCP tool responses.

    Recognizes common flag formats:
    - flag{...}
    - FLAG{...}
    - CTF{...}
    - HTB{...} - HackTheBox
    - [FLAG]...[/FLAG]
    - Custom patterns
    """

    # Common CTF flag patterns
    FLAG_PATTERNS = [
        r"flag\{[^}]+\}",  # flag{...}
        r"FLAG\{[^}]+\}",  # FLAG{...}
        r"CTF\{[^}]+\}",  # CTF{...}
        r"HTB\{[^}]+\}",  # HTB{...} - HackTheBox flags
        r"\[FLAG\](.+?)\[/FLAG\]",  # [FLAG]...[/FLAG]
        r"secret[_\s]*(?:key|flag|password)[:\s]+([a-zA-Z0-9_\-]+)",  # secret_key: xyz
        r"(?:password|pwd|pass)[:\s]+([a-zA-Z0-9_\-]{8,})",  # password: xyz
    ]

    def __init__(self, custom_patterns: list[str] | None = None) -> None:
        """Initialize flag detector.

        Args:
            custom_patterns: Additional regex patterns for custom flag formats
        """
        self.patterns = self.FLAG_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)

        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.patterns]

    def score(self, text: str) -> MCPScorerResult:
        """Score text for flag presence.

        Args:
            text: Text to analyze (tool response, error message, etc.)

        Returns:
            MCPScorerResult with detected flags
        """
        flags_found = []

        for pattern in self.compiled_patterns:
            matches = pattern.findall(text)
            for match in matches:
                # Handle tuple matches from groups
                flag = match if isinstance(match, str) else match[0]
                if flag and flag not in flags_found:
                    flags_found.append(flag)
                    logger.info(f"🚩 FLAG DETECTED: {flag}")

        success = len(flags_found) > 0
        score = 1.0 if success else 0.0

        explanation = f"Found {len(flags_found)} flag(s)" if success else "No flags detected"

        return MCPScorerResult(
            success=success,
            score=score,
            flags_found=flags_found,
            secrets_found=[],
            evidence={"raw_text": text[:500]},
            explanation=explanation,
        )


class ToolExecutionScorer:
    """Scores successful MCP tool execution.

    Determines if a tool call achieved the intended objective:
    - Tool executed without errors
    - Returned meaningful data
    - Exposed new attack surface
    """

    def score(
        self, tool_name: str, result: Any, objective: str = ""
    ) -> MCPScorerResult:  # noqa: ANN401
        """Score tool execution result.

        Args:
            tool_name: Name of tool that was called
            result: Tool result (ToolResult object)
            objective: Attack objective for context

        Returns:
            MCPScorerResult with success assessment
        """
        from aipop.adapters.mcp.methods.tools import ToolResult

        if not isinstance(result, ToolResult):
            return MCPScorerResult(
                success=False,
                score=0.0,
                flags_found=[],
                secrets_found=[],
                evidence={},
                explanation="Invalid result type",
            )

        # Check for errors
        if result.is_error:
            # Some errors are informative (file not found = enumerate other paths)
            error_msg = result.error_message or ""

            # Useful error hints
            useful_hints = [
                "not found",
                "does not exist",
                "permission denied",
                "unauthorized",
            ]

            if any(hint in error_msg.lower() for hint in useful_hints):
                return MCPScorerResult(
                    success=False,
                    score=0.3,  # Partial score for informative errors
                    flags_found=[],
                    secrets_found=[],
                    evidence={"error": error_msg},
                    explanation=f"Tool failed with informative error: {error_msg}",
                )

            return MCPScorerResult(
                success=False,
                score=0.0,
                flags_found=[],
                secrets_found=[],
                evidence={"error": error_msg},
                explanation=f"Tool execution failed: {error_msg}",
            )

        # Check content
        content_str = str(result.content)

        if not content_str or len(content_str) < 10:
            return MCPScorerResult(
                success=False,
                score=0.2,
                flags_found=[],
                secrets_found=[],
                evidence={},
                explanation="Tool returned empty/minimal content",
            )

        # Successful execution with data
        return MCPScorerResult(
            success=True,
            score=0.8,
            flags_found=[],
            secrets_found=[],
            evidence={"content_length": len(content_str)},
            explanation=f"Tool executed successfully, returned {len(content_str)} chars",
        )


class DataExfiltrationScorer:
    """Detects successful data exfiltration from MCP tools.

    Looks for sensitive data patterns:
    - API keys, tokens
    - Credentials
    - File contents
    - Database dumps
    """

    SENSITIVE_PATTERNS = [
        r"(?:api[_\s-]?key|apikey)[:\s]+([a-zA-Z0-9_\-]{20,})",
        r"(?:token|bearer)[:\s]+([a-zA-Z0-9_\-\.]{20,})",
        r"(?:aws|sk)[_\s-]?(?:access|secret)[_\s-]?key[:\s]+([A-Z0-9]{20,})",
        r"-----BEGIN (?:RSA |)PRIVATE KEY-----",
        r"(?:username|user)[:\s]+([a-zA-Z0-9_\-]+)",
        r"(?:email)[:\s]+([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})",
    ]

    def __init__(self) -> None:
        """Initialize exfiltration detector."""
        self.compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.SENSITIVE_PATTERNS]

    def score(self, text: str) -> MCPScorerResult:
        """Score text for sensitive data exfiltration.

        Args:
            text: Text to analyze

        Returns:
            MCPScorerResult with detected secrets
        """
        secrets_found = []

        for pattern in self.compiled_patterns:
            matches = pattern.findall(text)
            for match in matches:
                secret = match if isinstance(match, str) else match[0]
                if secret and secret not in secrets_found:
                    secrets_found.append(secret)
                    logger.warning(f"🔑 SENSITIVE DATA DETECTED: {secret[:20]}...")

        success = len(secrets_found) > 0
        score = 1.0 if success else 0.0

        explanation = (
            f"Exfiltrated {len(secrets_found)} sensitive data item(s)"
            if success
            else "No sensitive data detected"
        )

        return MCPScorerResult(
            success=success,
            score=score,
            flags_found=[],
            secrets_found=secrets_found,
            evidence={"patterns_matched": len(secrets_found)},
            explanation=explanation,
        )


class CompositeScorer:
    """Combines multiple scorers for comprehensive evaluation.

    Used by orchestrator to evaluate overall attack success.
    """

    def __init__(self) -> None:
        """Initialize composite scorer."""
        self.flag_detector = FlagDetectionScorer()
        self.tool_scorer = ToolExecutionScorer()
        self.exfiltration_scorer = DataExfiltrationScorer()

    def score_tool_result(
        self,
        tool_name: str,
        result: Any,  # noqa: ANN401
        objective: str = "",
    ) -> MCPScorerResult:
        """Score a tool execution result comprehensively.

        Args:
            tool_name: Name of tool executed
            result: Tool result object
            objective: Attack objective

        Returns:
            Composite MCPScorerResult
        """
        # Get content as string
        from aipop.adapters.mcp.methods.tools import ToolResult

        if isinstance(result, ToolResult):
            content = str(result.content) if not result.is_error else result.error_message or ""
        else:
            content = str(result)

        # Run all scorers
        flag_result = self.flag_detector.score(content)
        tool_result = self.tool_scorer.score(tool_name, result, objective)
        exfil_result = self.exfiltration_scorer.score(content)

        # Combine results
        all_flags = flag_result.flags_found
        all_secrets = exfil_result.secrets_found

        # Overall success if any flags found OR significant data exfiltrated
        success = len(all_flags) > 0 or (len(all_secrets) >= 2)

        # Weighted score
        score = max(
            flag_result.score * 1.0,  # Flags are highest priority
            exfil_result.score * 0.8,  # Exfiltration is high priority
            tool_result.score * 0.5,  # Tool success is baseline
        )

        # Build explanation
        explanations = []
        if all_flags:
            explanations.append(f"Found {len(all_flags)} flag(s)")
        if all_secrets:
            explanations.append(f"Exfiltrated {len(all_secrets)} secret(s)")
        if tool_result.score > 0:
            explanations.append("Tool executed successfully")

        explanation = "; ".join(explanations) if explanations else "No significant results"

        return MCPScorerResult(
            success=success,
            score=score,
            flags_found=all_flags,
            secrets_found=all_secrets,
            evidence={
                "flag_detection": flag_result.evidence,
                "tool_execution": tool_result.evidence,
                "exfiltration": exfil_result.evidence,
            },
            explanation=explanation,
        )

    def evaluate_conversation(
        self,
        tool_history: list[tuple[str, Any, Any]],
        objective: str,
    ) -> MCPScorerResult:
        """Evaluate entire attack conversation for success.

        Args:
            tool_history: List of (tool_name, arguments, result) tuples
            objective: Original attack objective

        Returns:
            Overall MCPScorerResult for the attack
        """
        all_flags = []
        all_secrets = []
        total_score = 0.0

        for tool_name, _args, result in tool_history:
            scorer_result = self.score_tool_result(tool_name, result, objective)
            all_flags.extend(scorer_result.flags_found)
            all_secrets.extend(scorer_result.secrets_found)
            total_score = max(total_score, scorer_result.score)

        # Deduplicate
        all_flags = list(set(all_flags))
        all_secrets = list(set(all_secrets))

        success = len(all_flags) > 0

        explanation = (
            f"Attack successful: found {len(all_flags)} flag(s), "
            f"exfiltrated {len(all_secrets)} secret(s) "
            f"across {len(tool_history)} tool calls"
        )

        return MCPScorerResult(
            success=success,
            score=total_score,
            flags_found=all_flags,
            secrets_found=all_secrets,
            evidence={"tools_called": len(tool_history)},
            explanation=explanation,
        )
