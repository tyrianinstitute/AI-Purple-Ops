"""Session history — every interaction saved, replayable, inspectable.

The REPL's memory. Records every prompt/response pair, tool invocations,
morph operations, and recon results. Supports replay, inspect, and export.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aipop.core.models import RunResult


@dataclass
class SessionEntry:
    """Single entry in the session history."""

    index: int
    timestamp: str
    entry_type: str  # "scan", "run", "recon", "tool", "morph"
    command: str  # what the user typed
    summary: str  # one-line result
    data: dict[str, Any] = field(default_factory=dict)  # full details


class SessionHistory:
    """In-memory session history for the REPL.

    Every operation is recorded. The pentester can:
    - inspect <N> — see full details of entry N
    - replay <N> — re-run entry N
    - export — save session as JSON for evidence
    - history — list all entries
    """

    def __init__(self) -> None:
        self._entries: list[SessionEntry] = []

    def record_scan(self, command: str, results: list[RunResult]) -> SessionEntry:
        """Record a scan/run execution."""
        passed = sum(1 for r in results if r.passed)
        failed = len(results) - passed
        entry = SessionEntry(
            index=len(self._entries),
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            entry_type="scan",
            command=command,
            summary=f"{len(results)} tests: {passed} passed, {failed} failed",
            data={
                "total": len(results),
                "passed": passed,
                "failed": failed,
                "results": [
                    {
                        "test_id": r.test_id,
                        "passed": r.passed,
                        "response": r.response[:500],
                        "metadata": r.metadata,
                        "detector_results": (
                            [
                                {
                                    "name": dr.detector_name,
                                    "passed": dr.passed,
                                    "violations": [
                                        {"severity": v.severity, "message": v.message}
                                        for v in dr.violations
                                    ],
                                }
                                for dr in r.detector_results
                            ]
                            if r.detector_results
                            else []
                        ),
                    }
                    for r in results
                ],
            },
        )
        self._entries.append(entry)
        return entry

    def record_recon(self, command: str, recon_data: dict[str, Any]) -> SessionEntry:
        """Record a recon operation."""
        entry = SessionEntry(
            index=len(self._entries),
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            entry_type="recon",
            command=command,
            summary=f"framework={recon_data.get('framework', '?')} guardrail={recon_data.get('guardrail_type', '?')}",
            data=recon_data,
        )
        self._entries.append(entry)
        return entry

    def record_tool(self, command: str, tool_result: dict[str, Any]) -> SessionEntry:
        """Record an external tool invocation."""
        entry = SessionEntry(
            index=len(self._entries),
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            entry_type="tool",
            command=command,
            summary=f"{tool_result.get('tool', '?')} exit={tool_result.get('exit_code', '?')} ({tool_result.get('elapsed_secs', 0):.1f}s)",
            data=tool_result,
        )
        self._entries.append(entry)
        return entry

    def record_morph(self, command: str, before: str, after: str, strategy: str) -> SessionEntry:
        """Record a payload morph operation."""
        entry = SessionEntry(
            index=len(self._entries),
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            entry_type="morph",
            command=command,
            summary=f"{strategy}: {len(before)} chars → {len(after)} chars",
            data={"strategy": strategy, "before": before, "after": after},
        )
        self._entries.append(entry)
        return entry

    def get(self, index: int) -> SessionEntry | None:
        """Get a specific entry by index."""
        if 0 <= index < len(self._entries):
            return self._entries[index]
        return None

    @property
    def last(self) -> SessionEntry | None:
        """Get the most recent entry."""
        return self._entries[-1] if self._entries else None

    @property
    def entries(self) -> list[SessionEntry]:
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def export(self, path: Path | None = None) -> str:
        """Export session history as JSON."""
        data = {
            "session_entries": len(self._entries),
            "entries": [
                {
                    "index": e.index,
                    "timestamp": e.timestamp,
                    "type": e.entry_type,
                    "command": e.command,
                    "summary": e.summary,
                    "data": e.data,
                }
                for e in self._entries
            ],
        }
        json_str = json.dumps(data, indent=2, ensure_ascii=False)
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json_str, encoding="utf-8")
        return json_str
