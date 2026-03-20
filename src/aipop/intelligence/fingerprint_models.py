"""Data models for guardrail fingerprinting."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal

from aipop.core.models import ModelResponse


@dataclass
class Probe:
    """A single probe payload for guardrail detection."""

    id: str
    category: str
    prompt: str
    expected_behavior: str
    signature: str
    severity: str | None = None  # low, medium, high


@dataclass
class ProbeResult:
    """Result from executing a single probe."""

    probe: Probe
    response: ModelResponse
    latency_ms: float
    error_code: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DetectionResult:
    """Result from pattern matching detection."""

    guardrail_type: str
    confidence: float
    all_scores: dict[str, float]
    evidence: list[dict[str, Any]]


@dataclass
class LLMDetectionResult:
    """Result from LLM-based classification."""

    guardrail_type: str
    confidence: float
    reasoning: str
    contradictions: list[str] = field(default_factory=list)


@dataclass
class FingerprintResult:
    """Complete fingerprinting result with all metadata."""

    guardrail_type: Literal[
        "promptguard",
        "llama_guard_3",
        "azure_content_safety",
        "nemo_guardrails",
        "rebuff",
        "constitutional_ai",
        "unknown",
    ]
    confidence: float  # 0.0 - 1.0
    all_scores: dict[str, float]
    evidence: list[dict[str, Any]]
    detection_method: Literal["regex", "llm", "hybrid"]
    uncertain: bool
    suggestions: list[str]
    model_id: str
    adapter_type: str
    probe_count: int
    avg_latency_ms: float
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "guardrail_type": self.guardrail_type,
            "confidence": self.confidence,
            "all_scores": self.all_scores,
            "evidence": self.evidence,
            "detection_method": self.detection_method,
            "uncertain": self.uncertain,
            "suggestions": self.suggestions,
            "model_id": self.model_id,
            "adapter_type": self.adapter_type,
            "probe_count": self.probe_count,
            "avg_latency_ms": self.avg_latency_ms,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_row(cls, row: tuple) -> FingerprintResult:
        """Create from database row.

        Schema order: id, model_id, adapter_type, guardrail_type, confidence,
                      detection_method, all_scores, evidence, timestamp,
                      probe_count, avg_latency_ms, uncertain, suggestions
        """
        return cls(
            guardrail_type=row[3],
            confidence=row[4],
            all_scores=json.loads(row[6]) if row[6] else {},
            evidence=json.loads(row[7]) if row[7] else [],
            detection_method=row[5],
            uncertain=row[11],
            suggestions=json.loads(row[12]) if row[12] else [],
            model_id=row[1],
            adapter_type=row[2],
            probe_count=row[9],
            avg_latency_ms=row[10],
            timestamp=row[8].isoformat() if row[8] else datetime.now().isoformat(),
        )
