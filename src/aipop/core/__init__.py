"""Core interfaces for AI Purple Ops evaluation framework."""

from __future__ import annotations

from .adapters import Adapter
from .detectors import Detector, DetectorResult, PolicyViolation
from .gates import Gate, GateResult, ThresholdGate
from .models import ModelResponse, RunResult, TestCase
from .reporters import Reporter
from .runners import Runner

__all__ = [
    "Adapter",
    "Detector",
    "DetectorResult",
    "Gate",
    "GateResult",
    "ModelResponse",
    "PolicyViolation",
    "Reporter",
    "RunResult",
    "Runner",
    "TestCase",
    "ThresholdGate",
]
