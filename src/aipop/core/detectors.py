"""Detector protocols for output analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

from aipop.core.models import ModelResponse, TestCase


@dataclass
class PolicyViolation:
    """Represents a single policy violation detected in model output.

    Attributes:
        rule_id: Unique identifier for the violated rule
        severity: Severity level ("low", "medium", "high", "critical")
        message: Human-readable description of the violation
        matched_text: The text that triggered the violation (if applicable)
    """

    rule_id: str
    severity: str  # "low", "medium", "high", "critical"
    message: str
    matched_text: str | None = None


@dataclass
class DetectorResult:
    """Result from running a detector on a model response.

    Attributes:
        detector_name: Name of the detector that produced this result
        passed: Whether the detector check passed (no violations)
        violations: List of policy violations found
        metadata: Additional detector-specific metadata
    """

    detector_name: str
    passed: bool
    violations: list[PolicyViolation]
    metadata: dict[str, Any]


class Detector(Protocol):
    """Protocol for output analysis detectors (IDS analogy).

    Detectors analyze model responses and test cases to identify policy
    violations, harmful content, or other issues. Each detector implements
    a check() method that returns a DetectorResult.
    """

    def check(self, response: ModelResponse, test_case: TestCase) -> DetectorResult:
        """Check response against policy rules.

        Args:
            response: Model response to analyze
            test_case: Original test case that generated the response

        Returns:
            DetectorResult with violations and metadata
        """
        ...
