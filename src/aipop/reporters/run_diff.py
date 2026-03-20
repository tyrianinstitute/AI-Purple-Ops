"""Run-to-run diff for tracking changes between assessments.

Compares two summary.json files and produces a structured diff showing
new findings, resolved findings, severity changes, and regressions.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def diff_runs(before_path: str | Path, after_path: str | Path) -> dict[str, Any]:
    """Compare two summary.json files and produce a structured diff.

    Args:
        before_path: Path to the earlier summary.json
        after_path: Path to the later summary.json

    Returns:
        Structured diff with new, resolved, changed, and regression counts
    """
    with Path(before_path).open() as f:
        before = json.load(f)
    with Path(after_path).open() as f:
        after = json.load(f)

    before_results = {r["test_id"]: r for r in before.get("results", [])}
    after_results = {r["test_id"]: r for r in after.get("results", [])}

    before_failed = {tid for tid, r in before_results.items() if not r.get("passed")}
    after_failed = {tid for tid, r in after_results.items() if not r.get("passed")}

    new_findings = after_failed - before_failed
    resolved_findings = before_failed - after_failed
    persistent_findings = before_failed & after_failed

    # Check for severity changes in persistent findings
    severity_changes = []
    for tid in persistent_findings:
        before_risk = before_results[tid].get("metadata", {}).get("risk", "unknown")
        after_risk = after_results[tid].get("metadata", {}).get("risk", "unknown")
        if before_risk != after_risk:
            severity_changes.append({
                "test_id": tid,
                "before_severity": before_risk,
                "after_severity": after_risk,
            })

    # New test cases (not in before at all)
    new_tests = set(after_results.keys()) - set(before_results.keys())
    removed_tests = set(before_results.keys()) - set(after_results.keys())

    # Regressions: tests that passed before but fail now
    regressions = []
    for tid in new_findings:
        if tid in before_results and before_results[tid].get("passed"):
            regressions.append(tid)

    return {
        "before": {
            "run_id": before.get("run_id", "unknown"),
            "suite": before.get("suite", "unknown"),
            "total": before.get("total", 0),
            "failed": before.get("failed", 0),
        },
        "after": {
            "run_id": after.get("run_id", "unknown"),
            "suite": after.get("suite", "unknown"),
            "total": after.get("total", 0),
            "failed": after.get("failed", 0),
        },
        "new_findings": sorted(new_findings),
        "resolved_findings": sorted(resolved_findings),
        "regressions": sorted(regressions),
        "persistent_findings": sorted(persistent_findings),
        "severity_changes": severity_changes,
        "new_tests_added": sorted(new_tests),
        "tests_removed": sorted(removed_tests),
        "summary": {
            "new_findings_count": len(new_findings),
            "resolved_count": len(resolved_findings),
            "regression_count": len(regressions),
            "persistent_count": len(persistent_findings),
            "severity_changes_count": len(severity_changes),
            "net_change": len(after_failed) - len(before_failed),
        },
    }


def print_diff(diff: dict[str, Any], output_json: bool = False) -> None:
    """Print a human-readable or JSON diff."""
    import sys

    if output_json:
        sys.stdout.write(json.dumps(diff, indent=2) + "\n")
        return

    from rich.console import Console
    console = Console()

    b = diff["before"]
    a = diff["after"]
    s = diff["summary"]

    console.print(f"\n[bold]Run Diff: {b['run_id']} -> {a['run_id']}[/bold]")
    console.print(f"  Before: {b['failed']}/{b['total']} failed")
    console.print(f"  After:  {a['failed']}/{a['total']} failed")
    console.print()

    net = s["net_change"]
    if net > 0:
        console.print(f"  [red]Net change: +{net} findings (worse)[/red]")
    elif net < 0:
        console.print(f"  [green]Net change: {net} findings (better)[/green]")
    else:
        console.print("  [yellow]Net change: 0 (same)[/yellow]")
    console.print()

    if diff["new_findings"]:
        console.print(f"  [red]New findings ({len(diff['new_findings'])}):[/red]")
        for tid in diff["new_findings"][:10]:
            console.print(f"    + {tid}")
        if len(diff["new_findings"]) > 10:
            console.print(f"    ... and {len(diff['new_findings']) - 10} more")

    if diff["resolved_findings"]:
        console.print(f"  [green]Resolved ({len(diff['resolved_findings'])}):[/green]")
        for tid in diff["resolved_findings"][:10]:
            console.print(f"    - {tid}")
        if len(diff["resolved_findings"]) > 10:
            console.print(f"    ... and {len(diff['resolved_findings']) - 10} more")

    if diff["regressions"]:
        console.print(f"  [bold red]Regressions ({len(diff['regressions'])}):[/bold red]")
        for tid in diff["regressions"]:
            console.print(f"    ! {tid}")

    if diff["severity_changes"]:
        console.print(f"  [yellow]Severity changes ({len(diff['severity_changes'])}):[/yellow]")
        for sc in diff["severity_changes"]:
            console.print(f"    ~ {sc['test_id']}: {sc['before_severity']} -> {sc['after_severity']}")

    console.print()
