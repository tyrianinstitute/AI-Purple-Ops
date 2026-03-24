"""Gate protocol for quality gates and thresholds."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class GateResult:
    """Result of a gate evaluation."""

    passed: bool
    reason: str
    metrics: Mapping[str, float]


class Gate(Protocol):
    """Quality gate protocol.

    Gates evaluate metrics and determine pass/fail outcomes.
    Used by recipe engine to enforce SLOs and thresholds.
    """

    def evaluate(self, metrics: Mapping[str, float]) -> GateResult:
        """Evaluate metrics against gate criteria.

        Args:
            metrics: Dictionary of metric name to value

        Returns:
            GateResult with pass/fail and explanation
        """
        ...

    def explain(self) -> str:
        """Return human-readable explanation of gate criteria.

        Returns:
            String describing what this gate checks
        """
        ...


@dataclass(frozen=True)
class ThresholdGate:
    """Simple threshold gate: pass when metric >= threshold.

    Example:
        gate = ThresholdGate(name="success_rate", threshold=0.95)
        result = gate.evaluate({"success_rate": 0.98})
        assert result.passed
    """

    name: str
    threshold: float

    def evaluate(self, metrics: Mapping[str, float]) -> GateResult:
        """Evaluate if metric meets or exceeds threshold."""
        value = float(metrics.get(self.name, 0.0))
        ok = value >= self.threshold
        reason = f"{self.name}={value:.3f} threshold={self.threshold:.3f}"
        return GateResult(ok, reason, dict(metrics))

    def explain(self) -> str:
        """Explain the threshold requirement."""
        return f"Requires {self.name} to meet or exceed {self.threshold}"
