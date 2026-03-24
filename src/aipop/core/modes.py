"""Test mode configurations with budget guardrails.

Defines presets for different use cases:
- quick: Bug bounty hunters needing fast ROI
- full: Comprehensive security assessments
- compliance: Enterprise/regulatory requirements
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ModeConfig:
    """Configuration for a test mode.

    Attributes:
        test_selection: Which tests to run (high_impact_only/all/all_extended)
        max_concurrency: Maximum parallel test execution
        stop_on_first_finding: Stop after first vulnerability found
        min_confidence: Minimum confidence threshold for findings (0-1)
        evidence_level: How much evidence to collect (minimal/standard/comprehensive)
        timeout_per_test: Timeout for individual tests in seconds
        max_requests: Maximum total requests (None = unlimited)
        max_cost_usd: Maximum cost in USD (None = unlimited)
        time_budget_s: Maximum time budget in seconds (None = unlimited)
        rate_limit: Rate limit string (e.g., "10/min")
        capture_traffic: Whether to capture HTTP traffic
        generate_pdf: Whether to generate PDF reports
        generate_sarif: Whether to generate SARIF output
        enable_stealth: Whether to enable stealth features
    """

    test_selection: str = "all"
    max_concurrency: int = 4
    stop_on_first_finding: bool = False
    min_confidence: float = 0.5
    evidence_level: str = "standard"
    timeout_per_test: int = 30
    max_requests: int | None = None
    max_cost_usd: float | None = None
    time_budget_s: int | None = None
    rate_limit: str | None = None
    capture_traffic: bool = False
    generate_pdf: bool = False
    generate_sarif: bool = False
    enable_stealth: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "test_selection": self.test_selection,
            "max_concurrency": self.max_concurrency,
            "stop_on_first_finding": self.stop_on_first_finding,
            "min_confidence": self.min_confidence,
            "evidence_level": self.evidence_level,
            "timeout_per_test": self.timeout_per_test,
            "max_requests": self.max_requests,
            "max_cost_usd": self.max_cost_usd,
            "time_budget_s": self.time_budget_s,
            "rate_limit": self.rate_limit,
            "capture_traffic": self.capture_traffic,
            "generate_pdf": self.generate_pdf,
            "generate_sarif": self.generate_sarif,
            "enable_stealth": self.enable_stealth,
            "metadata": self.metadata,
        }


# Predefined mode configurations
MODES: dict[str, ModeConfig] = {
    "quick": ModeConfig(
        test_selection="high_impact_only",
        max_concurrency=10,
        stop_on_first_finding=True,
        min_confidence=0.7,  # Higher threshold to reduce false positives
        evidence_level="minimal",
        timeout_per_test=10,
        max_requests=100,
        max_cost_usd=5.0,
        time_budget_s=600,  # 10 minutes
        enable_stealth=False,  # Speed over stealth
        metadata={
            "description": "Fast scan for bug bounty hunters",
            "target_audience": "bug_bounty",
        },
    ),
    "full": ModeConfig(
        test_selection="all",
        max_concurrency=4,
        stop_on_first_finding=False,
        min_confidence=0.5,
        evidence_level="standard",
        timeout_per_test=30,
        max_requests=None,  # Unlimited
        max_cost_usd=None,
        time_budget_s=None,
        capture_traffic=True,
        metadata={
            "description": "Comprehensive security assessment",
            "target_audience": "red_team",
        },
    ),
    "compliance": ModeConfig(
        test_selection="all_extended",
        max_concurrency=2,
        stop_on_first_finding=False,
        min_confidence=0.3,  # Lower threshold for completeness
        evidence_level="comprehensive",
        timeout_per_test=60,
        rate_limit="1/sec",  # Conservative rate limiting
        capture_traffic=True,
        generate_pdf=True,
        generate_sarif=True,
        enable_stealth=True,
        metadata={
            "description": "Enterprise compliance audit",
            "target_audience": "compliance_team",
        },
    ),
}


def get_mode_config(mode: str) -> ModeConfig:
    """Get configuration for a mode.

    Args:
        mode: Mode name (quick/full/compliance)

    Returns:
        ModeConfig for the mode

    Raises:
        ValueError: If mode not found
    """
    if mode not in MODES:
        available = ", ".join(MODES.keys())
        raise ValueError(f"Unknown mode: {mode}. Available: {available}")

    return MODES[mode]


def list_modes() -> list[str]:
    """Get list of available modes.

    Returns:
        List of mode names
    """
    return list(MODES.keys())


def merge_mode_with_overrides(
    mode: str,
    overrides: dict[str, Any],
) -> ModeConfig:
    """Merge mode config with CLI overrides.

    CLI flags take precedence over mode defaults.

    Args:
        mode: Base mode name
        overrides: Dictionary of override values

    Returns:
        Merged ModeConfig
    """
    config = get_mode_config(mode)

    # Create a new config with overrides
    config_dict = config.to_dict()

    for key, value in overrides.items():
        if value is not None and key in config_dict:
            config_dict[key] = value

    return ModeConfig(**config_dict)


def describe_mode(mode: str) -> str:
    """Get human-readable description of a mode.

    Args:
        mode: Mode name

    Returns:
        Description string
    """
    try:
        config = get_mode_config(mode)
        desc = config.metadata.get("description", "No description")
        target = config.metadata.get("target_audience", "general")

        details = []
        details.append(f"Test Selection: {config.test_selection}")
        details.append(f"Concurrency: {config.max_concurrency}")
        details.append(f"Min Confidence: {config.min_confidence}")

        if config.max_requests:
            details.append(f"Max Requests: {config.max_requests}")
        if config.max_cost_usd:
            details.append(f"Max Cost: ${config.max_cost_usd}")
        if config.time_budget_s:
            details.append(f"Time Budget: {config.time_budget_s}s")

        if config.stop_on_first_finding:
            details.append("Stops on first finding")

        if config.rate_limit:
            details.append(f"Rate Limit: {config.rate_limit}")

        features = []
        if config.capture_traffic:
            features.append("Traffic Capture")
        if config.generate_pdf:
            features.append("PDF Reports")
        if config.generate_sarif:
            features.append("SARIF Export")
        if config.enable_stealth:
            features.append("Stealth Mode")

        output = f"Mode: {mode}\n"
        output += f"Description: {desc}\n"
        output += f"Target Audience: {target}\n"
        output += "\nSettings:\n"
        output += "\n".join(f"  - {d}" for d in details)

        if features:
            output += "\n\nFeatures:\n"
            output += "\n".join(f"  - {f}" for f in features)

        return output

    except ValueError:
        return f"Mode '{mode}' not found"
