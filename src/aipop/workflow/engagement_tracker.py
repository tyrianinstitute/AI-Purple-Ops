"""Engagement tracking for security assessments.

Manages project metadata, scope definition, test runs, and finding aggregation
for professional security engagements.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class EngagementStatus(Enum):
    """Engagement lifecycle status."""

    PLANNING = "planning"
    IN_PROGRESS = "in_progress"
    REPORTING = "reporting"
    COMPLETED = "completed"
    ARCHIVED = "archived"


@dataclass
class Scope:
    """Engagement scope definition.

    Attributes:
        in_scope: List of in-scope targets (URLs, APIs, etc.)
        out_of_scope: List of out-of-scope targets
        compliance_frameworks: Frameworks to test against (NIST, OWASP, etc.)
        test_types: Types of tests to perform
    """

    in_scope: list[str]
    out_of_scope: list[str]
    compliance_frameworks: list[str]
    test_types: list[str]


@dataclass
class Engagement:
    """Security engagement metadata.

    Attributes:
        id: Unique engagement identifier
        name: Engagement name
        client: Client name
        status: Current engagement status
        created_at: ISO 8601 timestamp of creation
        scope: Scope definition
        test_runs: List of test session IDs
        findings: List of findings discovered
        metadata: Additional metadata
    """

    id: str
    name: str
    client: str
    status: EngagementStatus
    created_at: str
    scope: Scope
    test_runs: list[str]
    findings: list[dict[str, Any]]
    metadata: dict[str, Any]


class EngagementTracker:
    """Track security engagements and aggregate findings.

    Example:
        >>> tracker = EngagementTracker()
        >>> engagement = tracker.create_engagement(
        ...     name="AI Chatbot Assessment",
        ...     client="Acme Corp",
        ...     in_scope=["api.example.com/ai", "chat.example.com"]
        ... )
        >>> tracker.add_test_run(engagement.id, "sess_20241117_143022")
        >>> tracker.add_finding(engagement.id, {
        ...     "title": "Prompt Injection Vulnerability",
        ...     "severity": "high"
        ... })
    """

    def __init__(self, engagements_dir: str = "engagements") -> None:
        """Initialize engagement tracker.

        Args:
            engagements_dir: Directory to store engagement files
        """
        self.engagements_dir = Path(engagements_dir)
        self.engagements_dir.mkdir(parents=True, exist_ok=True)

    def create_engagement(
        self,
        name: str,
        client: str,
        in_scope: list[str],
        out_of_scope: list[str] | None = None,
        compliance_frameworks: list[str] | None = None,
        test_types: list[str] | None = None,
    ) -> Engagement:
        """Create new engagement.

        Args:
            name: Engagement name
            client: Client name
            in_scope: List of in-scope targets
            out_of_scope: List of out-of-scope targets
            compliance_frameworks: Compliance frameworks to test
            test_types: Types of tests to perform

        Returns:
            Created Engagement object
        """
        engagement_id = f"eng_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        scope = Scope(
            in_scope=in_scope,
            out_of_scope=out_of_scope or [],
            compliance_frameworks=compliance_frameworks or [],
            test_types=test_types or [],
        )

        engagement = Engagement(
            id=engagement_id,
            name=name,
            client=client,
            status=EngagementStatus.PLANNING,
            created_at=datetime.now().isoformat(),
            scope=scope,
            test_runs=[],
            findings=[],
            metadata={},
        )

        self._save_engagement(engagement)
        return engagement

    def list_engagements(
        self,
        status: EngagementStatus | None = None,
    ) -> list[Engagement]:
        """List all engagements.

        Args:
            status: Filter by status (optional)

        Returns:
            List of Engagement objects
        """
        engagements = []
        for file in self.engagements_dir.glob("*.json"):
            try:
                engagement = self._load_engagement(file)
                if status is None or engagement.status == status:
                    engagements.append(engagement)
            except Exception:
                # Skip invalid engagement files
                continue

        # Sort by creation date (newest first)
        engagements.sort(key=lambda e: e.created_at, reverse=True)
        return engagements

    def get_engagement(self, engagement_id: str) -> Engagement | None:
        """Get specific engagement by ID.

        Args:
            engagement_id: Engagement identifier

        Returns:
            Engagement object or None if not found
        """
        file = self.engagements_dir / f"{engagement_id}.json"
        if file.exists():
            return self._load_engagement(file)
        return None

    def add_test_run(self, engagement_id: str, session_id: str) -> None:
        """Add test run to engagement.

        Args:
            engagement_id: Engagement identifier
            session_id: Test session identifier
        """
        engagement = self.get_engagement(engagement_id)
        if engagement:
            engagement.test_runs.append(session_id)
            self._save_engagement(engagement)

    def add_finding(
        self,
        engagement_id: str,
        finding: dict[str, Any],
    ) -> None:
        """Add finding to engagement.

        Args:
            engagement_id: Engagement identifier
            finding: Finding dictionary with keys like:
                - title: Finding title
                - severity: Severity level
                - description: Description
                - etc.
        """
        engagement = self.get_engagement(engagement_id)
        if engagement:
            finding["added_at"] = datetime.now().isoformat()
            engagement.findings.append(finding)
            self._save_engagement(engagement)

    def update_status(
        self,
        engagement_id: str,
        status: EngagementStatus,
    ) -> None:
        """Update engagement status.

        Args:
            engagement_id: Engagement identifier
            status: New status
        """
        engagement = self.get_engagement(engagement_id)
        if engagement:
            engagement.status = status
            engagement.metadata["status_updated_at"] = datetime.now().isoformat()
            self._save_engagement(engagement)

    def generate_summary(self, engagement_id: str) -> dict[str, Any]:
        """Generate engagement summary report.

        Args:
            engagement_id: Engagement identifier

        Returns:
            Dictionary with engagement summary
        """
        engagement = self.get_engagement(engagement_id)
        if not engagement:
            return {}

        return {
            "engagement_id": engagement.id,
            "name": engagement.name,
            "client": engagement.client,
            "status": engagement.status.value,
            "created_at": engagement.created_at,
            "test_runs": len(engagement.test_runs),
            "total_findings": len(engagement.findings),
            "findings_by_severity": self._count_by_severity(engagement.findings),
            "scope": asdict(engagement.scope),
        }

    def _count_by_severity(
        self,
        findings: list[dict[str, Any]],
    ) -> dict[str, int]:
        """Count findings by severity level.

        Args:
            findings: List of finding dictionaries

        Returns:
            Dictionary mapping severity to count
        """
        counts = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity in counts:
                counts[severity] += 1

        return counts

    def _save_engagement(self, engagement: Engagement) -> None:
        """Save engagement to file.

        Args:
            engagement: Engagement object to save
        """
        file = self.engagements_dir / f"{engagement.id}.json"

        # Convert Enum and dataclass to dict
        data = asdict(engagement)
        data["status"] = engagement.status.value
        data["scope"] = asdict(engagement.scope)

        with open(file, "w") as f:
            json.dump(data, f, indent=2)

    def _load_engagement(self, file: Path) -> Engagement:
        """Load engagement from file.

        Args:
            file: Path to engagement JSON file

        Returns:
            Engagement object
        """
        with open(file) as f:
            data = json.load(f)

        # Convert status string back to Enum
        data["status"] = EngagementStatus(data["status"])
        data["scope"] = Scope(**data["scope"])

        return Engagement(**data)
