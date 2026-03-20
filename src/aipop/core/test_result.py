"""Structured test result system with findings and confidence scores.

Implements 1:N test-to-findings relationship for accurate security reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4


class Status(str, Enum):
    """Test execution status."""

    PASSED = "passed"
    FAILED = "failed"
    ERROR = "error"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class Severity(str, Enum):
    """Finding severity levels."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Category(str, Enum):
    """Finding categories for classification."""

    SECURITY_FINDING = "security_finding"
    POLICY_VIOLATION = "policy_violation"
    INFRASTRUCTURE_ERROR = "infrastructure_error"


@dataclass
class EvidenceRef:
    """Reference to evidence artifacts (HAR, screenshots, etc)."""

    kind: str  # "har", "screenshot", "text", "raw_response"
    path: str
    description: str | None = None


@dataclass
class Finding:
    """Individual security finding with metadata.

    A test can produce 0..N findings. Each finding represents a distinct
    security issue with its own rule mapping, severity, and confidence.

    Attributes:
        finding_id: Unique identifier
        rule_id: Maps to OWASP LLM Top 10, CWE, MITRE ATLAS, or internal rules
        title: Short finding title
        description: Detailed finding description
        severity: Finding severity level
        confidence: 0.0-1.0 score for false-positive filtering
        tags: Additional classification tags
        evidence: List of evidence references
    """

    finding_id: str = field(default_factory=lambda: str(uuid4()))
    rule_id: str = ""
    title: str = ""
    description: str = ""
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5  # 0..1
    tags: list[str] = field(default_factory=list)
    evidence: list[EvidenceRef] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value if isinstance(self.severity, Enum) else self.severity,
            "confidence": self.confidence,
            "tags": self.tags,
            "evidence": [
                {"kind": e.kind, "path": e.path, "description": e.description}
                for e in self.evidence
            ],
        }


@dataclass
class TestResult:
    """Test execution result with findings.

    Separates test execution status from security findings. A test can:
    - Pass with 0 findings (no issues detected)
    - Fail with N findings (security issues detected)
    - Error (infrastructure/adapter failure)
    - Skip/Block (preflight failure, quota exceeded)

    Attributes:
        result_id: Unique result identifier
        test_id: ID of the test that was executed
        status: Execution status (passed/failed/error/skipped/blocked)
        category: High-level category for reporting
        severity: Overall severity (derived from findings)
        started_at: Test start timestamp
        finished_at: Test end timestamp
        prompt: Input prompt (may be None for privacy)
        response: Model response (may be None for privacy)
        adapter_name: Adapter used
        model: Model name/identifier
        metadata: Additional test metadata
        findings: List of security findings (0..N)
    """

    result_id: str = field(default_factory=lambda: str(uuid4()))
    test_id: str = ""
    status: Status = Status.PASSED
    category: Category = Category.POLICY_VIOLATION
    severity: Severity = Severity.INFO
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    prompt: str | None = None
    response: str | None = None
    adapter_name: str = ""
    model: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary for JSON export."""
        return {
            "result_id": self.result_id,
            "test_id": self.test_id,
            "status": self.status.value if isinstance(self.status, Enum) else self.status,
            "category": self.category.value if isinstance(self.category, Enum) else self.category,
            "severity": self.severity.value if isinstance(self.severity, Enum) else self.severity,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "prompt": self.prompt,
            "response": self.response,
            "adapter_name": self.adapter_name,
            "model": self.model,
            "metadata": self.metadata,
            "findings": [f.to_dict() for f in self.findings],
        }

    @property
    def duration_ms(self) -> float:
        """Calculate test duration in milliseconds."""
        if self.started_at and self.finished_at:
            delta = self.finished_at - self.started_at
            return delta.total_seconds() * 1000
        return 0.0

    def add_finding(
        self,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        confidence: float = 0.8,
        tags: list[str] | None = None,
        evidence: list[EvidenceRef] | None = None,
    ) -> Finding:
        """Add a finding to this test result.

        Args:
            rule_id: Rule identifier (OWASP LLM/CWE/MITRE)
            title: Finding title
            description: Finding description
            severity: Severity level
            confidence: Confidence score 0-1
            tags: Optional tags
            evidence: Optional evidence references

        Returns:
            The created Finding object
        """
        finding = Finding(
            rule_id=rule_id,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            tags=tags or [],
            evidence=evidence or [],
        )
        self.findings.append(finding)

        # Update test result severity to highest finding severity if needed
        severity_order = {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
        if severity_order.get(severity, 0) > severity_order.get(self.severity, 0):
            self.severity = severity

        # Mark as failed if security finding
        if self.category == Category.SECURITY_FINDING and self.status == Status.PASSED:
            self.status = Status.FAILED

        return finding
