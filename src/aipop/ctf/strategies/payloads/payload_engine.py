"""MCP payload engine for intelligent exploitation.

Selects and generates payloads based on tool types and objectives.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class MCPPayloadEngine:
    """Intelligent payload generator for MCP tool exploitation.

    Automatically selects appropriate payloads based on:
    - Tool name and description
    - Attack objective
    - Previous attempt results

    Example:
        >>> engine = MCPPayloadEngine()
        >>> payloads = engine.get_payloads_for_tool("read_file")
        >>> # Returns path traversal payloads
    """

    def __init__(self) -> None:
        """Initialize payload engine."""
        self.payloads: dict[str, Any] = self._load_payloads()
        self.attempt_history: dict[str, list[str]] = {}  # Track tried payloads

    def _load_payloads(self) -> dict[str, Any]:
        """Load payload library from JSON file.

        Returns:
            Payload dictionary
        """
        payload_file = Path(__file__).parent / "mcp_exploits.json"

        try:
            with open(payload_file) as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load payloads from {payload_file}: {e}")
            return {}

    def get_payloads_for_tool(
        self,
        tool_name: str,
        tool_description: str = "",
        objective: str = "",
        exclude_tried: bool = True,
    ) -> list[str]:
        """Get appropriate payloads for a given tool.

        Args:
            tool_name: Name of the MCP tool
            tool_description: Tool description for context
            objective: Attack objective (e.g., "extract flag")
            exclude_tried: Skip payloads already attempted

        Returns:
            List of payloads to try
        """
        matched_payloads = []

        # Match by tool name patterns
        tool_lower = tool_name.lower()
        desc_lower = tool_description.lower()

        for category, config in self.payloads.items():
            if category.startswith("_"):
                continue  # Skip metadata

            # Check if tool matches this category
            targets = config.get("targets", [])

            matches = False
            for target in targets:
                if target == "any":
                    matches = True
                    break
                if target.lower() in tool_lower or target.lower() in desc_lower:
                    matches = True
                    break

            if matches:
                category_payloads = config.get("payloads", [])
                matched_payloads.extend(category_payloads)
                logger.debug(
                    f"Tool '{tool_name}' matched category '{category}': "
                    f"{len(category_payloads)} payloads"
                )

        # Add objective-specific payloads
        if "flag" in objective.lower():
            matched_payloads.extend(self.payloads.get("common_secrets", {}).get("payloads", []))

        # Deduplicate
        matched_payloads = list(dict.fromkeys(matched_payloads))

        # Exclude already-tried payloads
        if exclude_tried and tool_name in self.attempt_history:
            tried = set(self.attempt_history[tool_name])
            matched_payloads = [p for p in matched_payloads if p not in tried]

        logger.info(f"Generated {len(matched_payloads)} payloads for tool '{tool_name}'")
        return matched_payloads

    def mark_attempted(self, tool_name: str, payload: str) -> None:
        """Mark a payload as attempted for a tool.

        Args:
            tool_name: Tool name
            payload: Payload that was tried
        """
        if tool_name not in self.attempt_history:
            self.attempt_history[tool_name] = []

        if payload not in self.attempt_history[tool_name]:
            self.attempt_history[tool_name].append(payload)

    def get_fuzzing_payloads(self, base_input: str) -> list[str]:
        """Generate fuzzing variations of an input.

        Args:
            base_input: Base input string

        Returns:
            List of fuzzed variants
        """
        fuzzing_chars = self.payloads.get("fuzzing_characters", {}).get("payloads", [])

        variants = [base_input]  # Include original

        # Add fuzzing characters at start, middle, end
        for char in fuzzing_chars[:10]:  # Limit to avoid explosion
            variants.append(char + base_input)
            variants.append(base_input + char)

            # Middle insertion (if input long enough)
            if len(base_input) > 5:
                mid = len(base_input) // 2
                variants.append(base_input[:mid] + char + base_input[mid:])

        return variants

    def get_encoding_variants(self, payload: str) -> list[str]:
        """Generate encoding variants of a payload.

        Args:
            payload: Original payload

        Returns:
            List of encoded variants
        """
        import base64
        import urllib.parse

        variants = [payload]

        # URL encoding
        variants.append(urllib.parse.quote(payload))
        variants.append(urllib.parse.quote(urllib.parse.quote(payload)))  # Double encode

        # Base64
        try:
            b64 = base64.b64encode(payload.encode()).decode()
            variants.append(b64)
        except Exception:
            pass

        # Hex encoding
        hex_encoded = "".join(f"%{ord(c):02x}" for c in payload)
        variants.append(hex_encoded)

        return variants

    def suggest_next_payload(
        self,
        tool_name: str,
        previous_result: str,
        objective: str = "",
    ) -> str | None:
        """Intelligently suggest next payload based on previous result.

        Args:
            tool_name: Tool being exploited
            previous_result: Result from previous attempt
            objective: Attack objective

        Returns:
            Next payload to try, or None if no suggestions
        """
        result_lower = previous_result.lower()

        # Hint detection: response suggests what to try next
        if "file not found" in result_lower or "does not exist" in result_lower:
            # Try common secret paths
            common = self.payloads.get("common_secrets", {}).get("payloads", [])
            for path in common:
                if path not in self.attempt_history.get(tool_name, []):
                    return path

        if "permission denied" in result_lower or "unauthorized" in result_lower:
            # Try path traversal to escape restricted directory
            traversal = self.payloads.get("path_traversal", {}).get("payloads", [])
            for path in traversal:
                if path not in self.attempt_history.get(tool_name, []):
                    return path

        if "syntax error" in result_lower or "invalid" in result_lower:
            # Try encoding variants
            tried = self.attempt_history.get(tool_name, [])
            if tried:
                last_payload = tried[-1]
                variants = self.get_encoding_variants(last_payload)
                for variant in variants:
                    if variant not in tried:
                        return variant

        # Default: get next untried payload
        payloads = self.get_payloads_for_tool(tool_name, objective=objective)
        if payloads:
            return payloads[0]

        return None

    def get_polyglot_payloads(self) -> list[str]:
        """Get polyglot payloads that work across multiple injection types.

        Returns:
            List of polyglot payloads
        """
        return self.payloads.get("polyglot_payloads", {}).get("payloads", [])
