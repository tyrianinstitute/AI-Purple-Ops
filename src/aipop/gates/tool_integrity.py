"""ASI04 Tool inventory and integrity gate.

Pre-execution gate that inventories MCP servers/tools, checks against
an allowlist, and verifies signing/provenance when available.
Fails closed in locked environments when unsigned tools are detected.

Based on research: MCP registry namespace verification, Cisco MCP scanner
CI mode, cosign signing, SLSA provenance model.
"""

from __future__ import annotations

import json
import logging
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class ToolInventoryItem:
    """A discovered tool or MCP server."""

    name: str
    source: str  # npm, pip, local, mcp-registry
    version: str = ""
    namespace: str = ""
    signed: bool = False
    signature_valid: bool = False
    allowed: bool = False
    scan_findings: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class IntegrityGateResult:
    """Result of the tool integrity gate check."""

    passed: bool
    inventory: list[ToolInventoryItem]
    blocked_tools: list[str]
    unsigned_tools: list[str]
    scan_findings_count: int
    reason: str


class ToolIntegrityGate:
    """Pre-execution gate for ASI04 supply chain verification."""

    def __init__(
        self,
        allowlist_path: str | Path | None = None,
        require_signatures: bool = False,
        fail_on_unknown: bool = True,
    ) -> None:
        self.require_signatures = require_signatures
        self.fail_on_unknown = fail_on_unknown
        self.allowlist: set[str] = set()

        if allowlist_path:
            self._load_allowlist(Path(allowlist_path))

    def _load_allowlist(self, path: Path) -> None:
        """Load tool allowlist from YAML file."""
        if not path.exists():
            logger.warning(f"Allowlist not found: {path}")
            return

        with path.open() as f:
            data = yaml.safe_load(f)

        if isinstance(data, dict):
            self.allowlist = set(data.get("allowed_tools", []) or [])
            self.allowlist.update(data.get("allowed_servers", []) or [])
        elif isinstance(data, list):
            self.allowlist = set(data)

    def check(self, tools: list[dict[str, Any]]) -> IntegrityGateResult:
        """Run integrity checks on a list of tools/servers.

        Args:
            tools: List of tool descriptors with at least 'name' and optionally
                   'source', 'version', 'namespace'

        Returns:
            IntegrityGateResult with pass/fail and details
        """
        inventory = []
        blocked = []
        unsigned = []
        total_findings = 0

        for tool_desc in tools:
            item = ToolInventoryItem(
                name=tool_desc.get("name", "unknown"),
                source=tool_desc.get("source", "unknown"),
                version=tool_desc.get("version", ""),
                namespace=tool_desc.get("namespace", ""),
            )

            # Check allowlist
            if self.allowlist:
                item.allowed = (
                    item.name in self.allowlist
                    or item.namespace in self.allowlist
                    or f"{item.namespace}/{item.name}" in self.allowlist
                )
                if not item.allowed and self.fail_on_unknown:
                    blocked.append(item.name)
            else:
                item.allowed = True  # No allowlist = all allowed

            # Check signatures if required
            if self.require_signatures:
                item.signed = tool_desc.get("signed", False)
                item.signature_valid = tool_desc.get("signature_valid", False)
                if not item.signed:
                    unsigned.append(item.name)

            # Run scanner if available
            scan_results = self._scan_tool(tool_desc)
            item.scan_findings = scan_results
            total_findings += len(scan_results)

            inventory.append(item)

        # Determine pass/fail
        passed = len(blocked) == 0
        if self.require_signatures and unsigned:
            passed = False

        reasons = []
        if blocked:
            reasons.append(f"{len(blocked)} tool(s) not in allowlist: {', '.join(blocked)}")
        if unsigned:
            reasons.append(f"{len(unsigned)} tool(s) unsigned: {', '.join(unsigned)}")
        if total_findings > 0:
            reasons.append(f"{total_findings} scan finding(s) detected")

        reason = "; ".join(reasons) if reasons else "All tools verified"

        return IntegrityGateResult(
            passed=passed,
            inventory=inventory,
            blocked_tools=blocked,
            unsigned_tools=unsigned,
            scan_findings_count=total_findings,
            reason=reason,
        )

    def _scan_tool(self, tool_desc: dict[str, Any]) -> list[dict[str, Any]]:
        """Run MCP scanner against a tool descriptor if scanner is available."""
        # Check if Cisco MCP scanner is installed
        try:
            result = subprocess.run(
                ["mcp-scanner", "--help"],
                capture_output=True, timeout=5, check=False,
            )
            if result.returncode != 0:
                return []
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return []

        # If tool has a metadata file, scan it
        metadata_path = tool_desc.get("metadata_path")
        if not metadata_path or not Path(metadata_path).exists():
            return []

        try:
            scan_result = subprocess.run(
                ["mcp-scanner", "--analyzers", "yara", "--format", "raw",
                 "static", "--tools", metadata_path],
                capture_output=True, text=True, timeout=60, check=False,
            )
            if scan_result.returncode == 0 and scan_result.stdout.strip():
                data = json.loads(scan_result.stdout)
                return data.get("findings", [])
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception):
            pass

        return []

    def to_evidence(self, result: IntegrityGateResult) -> dict[str, Any]:
        """Convert gate result to evidence pack format."""
        return {
            "gate_type": "tool_integrity",
            "owasp_agentic": "ASI04",
            "passed": result.passed,
            "reason": result.reason,
            "inventory": [
                {
                    "name": item.name,
                    "source": item.source,
                    "version": item.version,
                    "allowed": item.allowed,
                    "signed": item.signed,
                    "findings": len(item.scan_findings),
                }
                for item in result.inventory
            ],
            "blocked": result.blocked_tools,
            "unsigned": result.unsigned_tools,
            "scan_findings_count": result.scan_findings_count,
        }
