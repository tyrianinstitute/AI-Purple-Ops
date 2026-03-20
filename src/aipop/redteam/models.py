"""Redteam result models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class RedteamFinding:
    """Normalized finding from any redteam tool."""

    id: str
    source: str  # "promptfoo", "garak", "indirect_injection"
    category: str  # OWASP LLM category
    severity: str  # critical, high, medium, low
    attack_vector: str
    payload: str
    response: str
    success: bool
    evidence: dict[str, Any]
    remediation: str | None = None
