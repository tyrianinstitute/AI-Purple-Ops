"""Core data models for test cases and results."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Import at module level to avoid circular import issues
# DetectorResult is imported here to avoid forward reference issues
try:
    from aipop.core.detectors import DetectorResult
except ImportError:
    # Fallback for when detectors module isn't available yet
    DetectorResult = Any  # type: ignore


@dataclass
class ModelResponse:
    """Model invocation response with metadata.

    Contains the text response plus metadata like tokens, latency, cost,
    finish_reason, etc. Prevents having to change Adapter.invoke() signature
    when adding detector/evaluator support.
    """

    text: str
    meta: dict[str, Any] = field(default_factory=dict)
    tool_calls: list[dict[str, Any]] | None = None  # Tool/function calls made by model
    capture_metadata: dict[str, Any] | None = (
        None  # Optional HTTP request/response data for traffic capture
    )
    # meta can include: tokens, finish_reason, cost, latency, provider, refusal, etc.
    # tool_calls format: [{"name": "tool_name", "arguments": {...}, "id": "call_id"}]
    # capture_metadata format: {"method": "POST", "url": "...", "headers": {...}, "body": ..., "status": 200}


@dataclass
class TestCase:
    """Single test case definition."""

    id: str
    prompt: str
    metadata: dict[str, Any]
    # TODO(b05): Add expected_policy field
    # TODO(b07): Add attack_type field for redteam


class Verdict:
    """Test outcome states. Refusal is NOT pass. Error is NOT vulnerability."""

    VULNERABLE = "vulnerable"    # Attack succeeded — real finding
    BLOCKED = "blocked"          # A deployed control stopped the attack
    REFUSED = "refused"          # Model alignment refused, no deployed control involved
    INCONCLUSIVE = "inconclusive"  # Could not determine — timeout, parse error, ambiguous
    ERROR = "error"              # Infrastructure failure — connection, adapter, config


@dataclass
class RunResult:
    """Single test execution result."""

    test_id: str
    prompt: str  # The prompt sent to the target — evidence for reports
    response: str
    passed: bool  # Kept for backward compat — derived from verdict
    metadata: dict[str, Any]
    detector_results: list[DetectorResult] | None = None  # Policy violation results
    verdict: str = ""  # One of Verdict.* — empty means legacy result

    def __post_init__(self) -> None:
        # If verdict not set, derive from passed for backward compat
        if not self.verdict:
            self.verdict = Verdict.BLOCKED if self.passed else Verdict.VULNERABLE
