"""Result aggregator for deduplication and unified reporting."""

from __future__ import annotations

from typing import Any

from aipop.integrations.base import ToolResult


def aggregate_results(tool_results: list[ToolResult]) -> dict[str, Any]:
    """Aggregate findings from multiple tools.

    Args:
        tool_results: List of ToolResult from various tools

    Returns:
        Aggregated results dictionary with:
        - total_findings: Total count
        - findings_by_tool: Findings grouped by tool
        - findings_by_category: Findings grouped by OWASP category
        - findings_by_severity: Findings grouped by severity
        - unique_findings: Deduplicated findings
    """
    all_findings = []

    # Collect all findings
    for tool_result in tool_results:
        for finding in tool_result.findings:
            all_findings.append(finding)

    # Group by tool
    findings_by_tool: dict[str, list[dict[str, Any]]] = {}
    for tool_result in tool_results:
        findings_by_tool[tool_result.tool_name] = tool_result.findings

    # Group by category
    findings_by_category: dict[str, list[dict[str, Any]]] = {}
    for finding in all_findings:
        category = finding.get("category", "unknown")
        if category not in findings_by_category:
            findings_by_category[category] = []
        findings_by_category[category].append(finding)

    # Group by severity
    findings_by_severity: dict[str, list[dict[str, Any]]] = {}
    for finding in all_findings:
        severity = finding.get("severity", "unknown")
        if severity not in findings_by_severity:
            findings_by_severity[severity] = []
        findings_by_severity[severity].append(finding)

    # Deduplicate findings (simple approach: by attack_vector + payload hash)
    unique_findings = deduplicate_findings(all_findings)

    return {
        "total_findings": len(all_findings),
        "unique_findings": len(unique_findings),
        "findings_by_tool": findings_by_tool,
        "findings_by_category": findings_by_category,
        "findings_by_severity": findings_by_severity,
        "unique_findings_list": unique_findings,
        "tools_executed": [tr.tool_name for tr in tool_results],
        "tools_successful": [tr.tool_name for tr in tool_results if tr.success],
    }


def deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate findings based on attack vector and payload similarity.

    Args:
        findings: List of finding dictionaries

    Returns:
        Deduplicated list of findings
    """
    seen = set()
    unique = []

    for finding in findings:
        # Create signature from attack_vector and payload
        attack_vector = finding.get("attack_vector", "")
        payload = finding.get("payload", "")[:100]  # First 100 chars
        signature = f"{attack_vector}:{payload}"

        if signature not in seen:
            seen.add(signature)
            unique.append(finding)

    return unique


def rank_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Rank findings by severity and confidence.

    Args:
        findings: List of finding dictionaries

    Returns:
        Ranked list (most severe first)
    """
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    def rank_key(finding: dict[str, Any]) -> tuple[int, bool]:
        severity = finding.get("severity", "low")
        success = finding.get("success", False)
        return (severity_order.get(severity, 0), success)

    return sorted(findings, key=rank_key, reverse=True)
