"""Probe library loader for guardrail fingerprinting."""

from __future__ import annotations

from pathlib import Path

import yaml

from aipop.intelligence.fingerprint_models import Probe


class ProbeLibrary:
    """Load and manage probe payloads from YAML."""

    def __init__(self, probes: list[Probe]):
        """Initialize with list of probes."""
        self.probes = probes

    @classmethod
    def load(cls, yaml_path: Path | str) -> ProbeLibrary:
        """Load probes from YAML file.

        Args:
            yaml_path: Path to guardrail_probes.yaml

        Returns:
            ProbeLibrary instance
        """
        path = Path(yaml_path)
        if not path.exists():
            # Try relative to project root
            path = Path(__file__).parent.parent.parent.parent / "configs" / "data" / "guardrail_probes.yaml"

        if not path.exists():
            raise FileNotFoundError(f"Probe library not found: {yaml_path}")

        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)

        probes = []
        for probe_data in data.get("probes", []):
            probes.append(
                Probe(
                    id=probe_data["id"],
                    category=probe_data["category"],
                    prompt=probe_data["prompt"],
                    expected_behavior=probe_data["expected_behavior"],
                    signature=probe_data["signature"],
                    severity=probe_data.get("severity"),
                )
            )

        return cls(probes)

    def get_all_probes(self) -> list[Probe]:
        """Get all probes."""
        return self.probes

    def get_by_category(self, category: str) -> list[Probe]:
        """Get probes for specific category."""
        return [p for p in self.probes if p.category == category]

    def get_by_signature(self, signature: str) -> list[Probe]:
        """Get probes with specific signature."""
        return [p for p in self.probes if p.signature == signature]
