"""Base protocol for tool wrapper integration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from aipop.core.adapters import Adapter


@dataclass
class ToolResult:
    """Result from a tool execution."""

    tool_name: str
    success: bool
    findings: list[dict[str, Any]]
    raw_output: str | dict[str, Any] | None = None
    error: str | None = None
    execution_time: float = 0.0


class ToolWrapper(Protocol):
    """Standard interface for external tool integration."""

    def is_available(self) -> bool:
        """Check if tool is installed and configured.

        Returns:
            True if tool can be executed, False otherwise
        """
        ...

    def execute(self, config: dict[str, Any], adapter: Adapter | None = None) -> ToolResult:
        """Run tool with recipe configuration.

        Args:
            config: Tool-specific configuration from recipe
            adapter: Optional model adapter for tool to use

        Returns:
            ToolResult with findings and metadata

        Raises:
            ToolExecutionError: If tool execution fails
        """
        ...

    def parse_output(self, raw: Any) -> list[dict[str, Any]]:
        """Normalize tool output to our schema.

        Args:
            raw: Raw output from tool (format depends on tool)

        Returns:
            List of normalized findings, each with:
            - id: Unique finding ID
            - source: Tool name
            - category: OWASP LLM category
            - severity: critical, high, medium, low
            - attack_vector: Type of attack
            - payload: Attack payload used
            - response: Model response
            - success: Whether attack succeeded
            - evidence: Additional evidence dict
            - remediation: Optional remediation guidance
        """
        ...


# Normalization helpers for consistent finding schema
def normalize_category(check_name: str, default: str = "LLM01") -> str:
    """Map check/probe name to OWASP LLM category.

    Args:
        check_name: Check or probe name from tool
        default: Default category if no match found

    Returns:
        OWASP LLM category (LLM01-LLM10)
    """
    check_lower = check_name.lower()

    # LLM01: Prompt Injection
    if any(
        term in check_lower for term in ["injection", "jailbreak", "encoding", "bypass", "escape"]
    ):
        return "LLM01"

    # LLM02: Insecure Output Handling
    if any(term in check_lower for term in ["harmful", "toxicity", "output", "xss"]):
        return "LLM02"

    # LLM03: Training Data Poisoning
    if any(term in check_lower for term in ["poisoning", "training", "data"]):
        return "LLM03"

    # LLM04: Model Denial of Service
    if any(term in check_lower for term in ["dos", "denial", "resource", "timeout"]):
        return "LLM04"

    # LLM05: Supply Chain Vulnerabilities
    if any(term in check_lower for term in ["supply", "chain", "dependency"]):
        return "LLM05"

    # LLM06: Sensitive Information Disclosure
    if any(term in check_lower for term in ["pii", "leak", "disclosure", "secret", "credential"]):
        return "LLM06"

    # LLM07: Insecure Plugin Design
    if any(term in check_lower for term in ["plugin", "function", "tool"]):
        return "LLM07"

    # LLM08: Excessive Agency
    if any(term in check_lower for term in ["agency", "autonomy", "action"]):
        return "LLM08"

    # LLM09: Overreliance
    if any(term in check_lower for term in ["overreliance", "trust", "hallucination"]):
        return "LLM09"

    # LLM10: Model Theft
    if any(term in check_lower for term in ["theft", "extraction", "clone"]):
        return "LLM10"

    return default


def normalize_severity(check_name: str, default: str = "medium") -> str:
    """Map check/probe name to severity level.

    Args:
        check_name: Check or probe name from tool
        default: Default severity if no match found

    Returns:
        Severity: critical, high, medium, low
    """
    check_lower = check_name.lower()

    # Critical: Direct security exploits
    if any(
        term in check_lower
        for term in [
            "injection",
            "jailbreak",
            "bypass",
            "escape",
            "pii",
            "leak",
            "credential",
            "secret",
        ]
    ):
        return "critical"

    # High: Significant security risks
    if any(
        term in check_lower for term in ["harmful", "toxicity", "poisoning", "theft", "extraction"]
    ):
        return "high"

    # Medium: Moderate risks (default)
    if any(term in check_lower for term in ["encoding", "output", "plugin"]):
        return "medium"

    return default


def normalize_remediation(check_name: str) -> str | None:
    """Get remediation guidance for check/probe.

    Args:
        check_name: Check or probe name from tool

    Returns:
        Remediation guidance or None
    """
    check_lower = check_name.lower()

    remediation_map = {
        "injection": "Implement input sanitization and output validation",
        "jailbreak": "Add system prompts and content filtering",
        "harmful": "Enable content moderation filters",
        "pii": "Implement PII detection and redaction",
        "leak": "Implement data leakage prevention and output filtering",
        "poisoning": "Validate and sanitize training data sources",
        "encoding": "Normalize and validate encoded inputs",
        "bypass": "Strengthen security controls and validation",
        "escape": "Implement proper input escaping and sanitization",
        "toxicity": "Enable toxicity detection and filtering",
        "plugin": "Review and secure plugin/function call interfaces",
        "theft": "Implement rate limiting and access controls",
    }

    for key, guidance in remediation_map.items():
        if key in check_lower:
            return guidance

    return None
