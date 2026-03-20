"""Engagement phase management for AI security assessments.

Implements a recon -> attack -> report lifecycle where each phase
produces artifacts that feed the next. Phase gates prevent running
attacks before recon completes.

Based on OWASP GenAI Red Teaming Guide phases: model evaluation,
implementation testing, infrastructure assessment, runtime analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from aipop.core.session_store import SessionStore
from aipop.core.target_profile import TargetProfile

PHASES = ["recon", "attack", "report", "complete"]


@dataclass
class PhaseResult:
    """Result of a phase execution."""

    phase: str
    status: str  # success | failed | skipped
    artifacts: list[str] = field(default_factory=list)
    findings_count: int = 0
    notes: str = ""


@dataclass
class Engagement:
    """A multi-phase security assessment against a target."""

    engagement_id: str
    target: TargetProfile
    store: SessionStore
    current_phase: str = "recon"

    def __post_init__(self) -> None:
        """Initialize or resume engagement in session store."""
        existing = self.store.get_session(self.engagement_id)
        if existing:
            self.current_phase = existing.get("phase", "recon")
        else:
            self.store.create_session(
                self.engagement_id,
                target_name=self.target.name,
                metadata={
                    "target_url": self.target.base_url,
                    "model": f"{self.target.model.provider}/{self.target.model.name}",
                    "created": datetime.now(UTC).isoformat(),
                },
            )

    def advance_phase(self) -> str:
        """Advance to the next phase. Returns the new phase name."""
        idx = PHASES.index(self.current_phase)
        if idx >= len(PHASES) - 1:
            return self.current_phase  # Already complete

        self.current_phase = PHASES[idx + 1]
        self.store.update_phase(self.engagement_id, self.current_phase)
        return self.current_phase

    def can_attack(self) -> bool:
        """Check if recon phase is complete (prerequisite for attack)."""
        if self.current_phase == "recon":
            # Check if fingerprinting has been done
            fingerprints = self.store.get_discoveries(self.engagement_id, "fingerprint")
            return len(fingerprints) > 0
        return PHASES.index(self.current_phase) >= PHASES.index("attack")

    def can_report(self) -> bool:
        """Check if attack phase has produced results."""
        runs = self.store.get_runs(self.engagement_id)
        return len(runs) > 0

    def record_recon(self, discovery_type: str, key: str, value: Any) -> None:
        """Record a recon discovery (fingerprint, capability, surface)."""
        self.store.add_discovery(self.engagement_id, discovery_type, key, value)

    def record_run(self, run_id: str, suite: str, adapter: str, model: str,
                   total: int, passed: int, failed: int,
                   summary_path: str = "", evidence_path: str = "") -> None:
        """Record a completed attack run."""
        self.store.add_run(
            self.engagement_id, run_id, suite, adapter, model,
            total, passed, failed, summary_path, evidence_path,
        )

    def get_status(self) -> dict[str, Any]:
        """Get current engagement status."""
        discoveries = self.store.get_discoveries(self.engagement_id)
        runs = self.store.get_runs(self.engagement_id)

        total_findings = sum(r.get("failed", 0) for r in runs)

        return {
            "engagement_id": self.engagement_id,
            "target": self.target.name,
            "phase": self.current_phase,
            "recon_complete": self.can_attack(),
            "discoveries": len(discoveries),
            "runs_completed": len(runs),
            "total_findings": total_findings,
            "can_attack": self.can_attack(),
            "can_report": self.can_report(),
        }

    def export(self) -> dict[str, Any]:
        """Export full engagement state."""
        return {
            "engagement": self.get_status(),
            **self.store.export_session(self.engagement_id),
        }
