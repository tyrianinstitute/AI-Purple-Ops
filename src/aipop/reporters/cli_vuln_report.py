"""Professional CLI vulnerability report (like nmap/sqlmap/burp)."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from rich.console import Console
from rich.table import Table

from aipop.reporters.utils import sanitize_surrogates


def generate_cli_vuln_report(
    summary_json_path: Path,
    format_type: Literal["default", "json", "yaml", "table"] = "default",
) -> None:
    """Generate professional CLI vulnerability report.

    Args:
        summary_json_path: Path to summary.json
        format_type: Output format (default, json, yaml, table)
    """
    console = Console()

    with open(summary_json_path) as f:
        data = json.load(f)

    # Parse vulnerabilities
    vulnerabilities: list[dict[str, Any]] = []
    for result in data.get("results", []):
        if not result.get("passed"):
            # Build description from available metadata
            meta = result["metadata"]
            description = meta.get("description", "")
            if not description:
                # Construct from category and technique if available
                category = meta.get("category", "unknown")
                technique = meta.get("technique", "")
                if technique:
                    description = f"{category} via {technique}"
                else:
                    description = f"{category} test failed"

            vuln = {
                "id": result["test_id"],
                "severity": meta.get("risk", "unknown").upper(),
                "category": meta.get("category", "unknown"),
                "description": description,
                "response": sanitize_surrogates(result.get("response", ""))[:200],  # Truncate
                "multi_turn": meta.get("multi_turn", False),
            }
            vulnerabilities.append(vuln)

    # Get model info
    model_info = "Unknown"
    if data.get("results") and len(data["results"]) > 0:
        meta = data["results"][0].get("metadata", {}).get("model_meta", {})
        model_info = meta.get("model", "Unknown")

    # Stats
    total = data.get("total", 0)
    passed = data.get("passed", 0)
    failed = data.get("failed", 0)
    is_mock = data.get("adapter", "").lower() == "mock"
    cost = 0.0 if is_mock else data.get("cost_usd", 0)
    latency_p50 = 0.0 if is_mock else data.get("latency_ms_p50", 0)

    # Count by severity
    critical = sum(1 for v in vulnerabilities if v["severity"] == "CRITICAL")
    high = sum(1 for v in vulnerabilities if v["severity"] == "HIGH")
    medium = sum(1 for v in vulnerabilities if v["severity"] == "MEDIUM")
    low = sum(1 for v in vulnerabilities if v["severity"] == "LOW")

    # Format-specific output
    if format_type == "json":
        _print_json_format(console, vulnerabilities, data)
    elif format_type == "yaml":
        _print_yaml_format(console, vulnerabilities, data)
    elif format_type == "table":
        _print_table_format(console, vulnerabilities, total, passed, failed, model_info)
    else:
        _print_default_format(
            console,
            vulnerabilities,
            total,
            passed,
            failed,
            critical,
            high,
            medium,
            low,
            cost,
            latency_p50,
            model_info,
        )


def _print_default_format(
    console: Console,
    vulnerabilities: list[dict[str, Any]],
    total: int,
    passed: int,
    failed: int,
    critical: int,
    high: int,
    medium: int,
    low: int,
    cost: float,
    latency_p50: float,
    model_info: str,
) -> None:
    """Print default professional format (like Burp Scanner)."""
    console.print()
    console.print("[bold]" + "=" * 70 + "[/bold]")
    console.print("[bold]AI SECURITY VULNERABILITY SCAN REPORT[/bold]")
    console.print("[bold]" + "=" * 70 + "[/bold]")
    console.print()

    # ASCII Art Banner (minimal, professional)
    console.print(
        "[dim]"
        + r"""
     ___  ___   ___                          ___       
    | _ \/ _ \ / _ \ _ __  ___   __ __  ___ |   \ _ __ 
    |  _/ (_) | (_) | '  \(_-<  / _/ _|/ _ \| |) | '_ \
    |_|  \___/ \___/|_|_|_/__/  \__\__|\___/|___/| .__/
                                                 |_|   
    """
        + "[/dim]"
    )
    console.print()

    # Scan Info
    console.print(f"[bold]Target Model:[/bold]    {model_info}")
    console.print(f"[bold]Scan Time:[/bold]       {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    console.print(f"[bold]Tests Run:[/bold]       {total} security test cases")
    console.print(f"[bold]Cost:[/bold]            ${cost:.4f} USD")
    console.print(f"[bold]Avg Latency:[/bold]     {latency_p50:.0f}ms")
    console.print()
    console.print("[bold]" + "-" * 70 + "[/bold]")
    console.print()

    # Results Summary
    if failed > 0:
        status = (
            "[bold red]VULNERABLE[/bold red]"
            if (high > 0 or critical > 0)
            else "[bold yellow]ISSUES FOUND[/bold yellow]"
        )
    else:
        status = "[bold green]SECURE[/bold green]"

    console.print(f"[bold]Scan Status:[/bold] {status}")
    console.print()
    console.print(f"  Total Tests:        {total}")
    console.print(f"  [green]Passed:[/green]             {passed}")
    console.print(f"  [red]Failed:[/red]             {failed}")
    console.print()

    if failed > 0:
        console.print("[bold]Vulnerabilities by Severity:[/bold]")
        if critical > 0:
            console.print(f"  [bold red]CRITICAL:[/bold red]   {critical}")
        if high > 0:
            console.print(f"  [bold yellow]HIGH:[/bold yellow]       {high}")
        if medium > 0:
            console.print(f"  [yellow]MEDIUM:[/yellow]     {medium}")
        if low > 0:
            console.print(f"  [blue]LOW:[/blue]        {low}")
        console.print()

    # Detailed Vulnerabilities
    if vulnerabilities:
        console.print("[bold]" + "=" * 70 + "[/bold]")
        console.print("[bold]VULNERABILITIES DETECTED[/bold]")
        console.print("[bold]" + "=" * 70 + "[/bold]")
        console.print()

        for i, vuln in enumerate(vulnerabilities, 1):
            # Severity marker
            severity_color = {
                "CRITICAL": "bold red",
                "HIGH": "bold yellow",
                "MEDIUM": "yellow",
                "LOW": "blue",
            }.get(vuln["severity"], "white")

            console.print(f"[{severity_color}][{vuln['severity']}][/{severity_color}] {vuln['id']}")
            console.print(f"  Category:     {vuln['category']}")
            console.print(f"  Finding:      {vuln['description']}")

            if vuln["multi_turn"]:
                console.print("  [bold red]Multi-Turn:   BYPASS DETECTED[/bold red]")

            # Truncated response
            response = vuln["response"].replace("\n", " ")
            if len(response) > 150:
                response = response[:150] + "..."
            console.print(f"  Response:     {response}")
            console.print()

    # Recommendations
    if failed > 0:
        console.print("[bold]" + "=" * 70 + "[/bold]")
        console.print("[bold]RECOMMENDATIONS[/bold]")
        console.print("[bold]" + "=" * 70 + "[/bold]")
        console.print()

        if high > 0 or critical > 0:
            console.print("[bold red]CRITICAL ACTION REQUIRED:[/bold red]")
            console.print("  [*] Do NOT deploy to production")
            console.print("  [*] Review high/critical findings immediately")
            console.print("  [*] Implement additional safety guardrails")
            console.print()

        console.print("[bold]REMEDIATION STEPS:[/bold]")
        console.print("  [*] Review full transcripts: out/transcripts/")
        console.print("  [*] Analyze JSON report: out/reports/summary.json")
        console.print("  [*] Generate evidence pack: aipop gate --generate-evidence")
        console.print()
    else:
        console.print("[bold green]All security tests passed. Model appears secure.[/bold green]")
        console.print()

    console.print("[bold]" + "=" * 70 + "[/bold]")
    console.print()


def _print_json_format(
    console: Console, vulnerabilities: list[dict[str, Any]], data: dict[str, Any]
) -> None:
    """Print JSON format."""
    output = {
        "scan_metadata": {
            "timestamp": datetime.now().isoformat(),
            "total_tests": data.get("total", 0),
            "passed": data.get("passed", 0),
            "failed": data.get("failed", 0),
            "cost_usd": data.get("cost_usd", 0),
        },
        "vulnerabilities": vulnerabilities,
    }
    console.print_json(data=output)


def _print_yaml_format(
    console: Console, vulnerabilities: list[dict[str, Any]], data: dict[str, Any]
) -> None:
    """Print YAML format."""
    console.print("scan_metadata:")
    console.print(f"  timestamp: {datetime.now().isoformat()}")
    console.print(f"  total_tests: {data.get('total', 0)}")
    console.print(f"  passed: {data.get('passed', 0)}")
    console.print(f"  failed: {data.get('failed', 0)}")
    console.print(f"  cost_usd: {data.get('cost_usd', 0)}")
    console.print()
    console.print("vulnerabilities:")

    if not vulnerabilities:
        console.print("  []")
        return

    for vuln in vulnerabilities:
        console.print(f"  - id: {vuln['id']}")
        console.print(f"    severity: {vuln['severity']}")
        console.print(f"    category: {vuln['category']}")
        console.print(f"    description: \"{vuln['description']}\"")
        console.print(f"    multi_turn: {vuln['multi_turn']}")


def _print_table_format(
    console: Console,
    vulnerabilities: list[dict[str, Any]],
    total: int,
    passed: int,
    failed: int,
    model_info: str,
) -> None:
    """Print table format."""
    console.print()
    console.print(
        f"[bold]Model:[/bold] {model_info} | [bold]Tests:[/bold] {total} | [green]Passed:[/green] {passed} | [red]Failed:[/red] {failed}"
    )
    console.print()

    if not vulnerabilities:
        console.print("[green]No vulnerabilities detected[/green]")
        return

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("ID", style="cyan", width=20)
    table.add_column("Severity", justify="center", width=10)
    table.add_column("Category", style="yellow", width=15)
    table.add_column("Description", width=35)
    table.add_column("Multi-Turn", justify="center", width=10)

    for vuln in vulnerabilities:
        severity_style = {
            "CRITICAL": "bold red",
            "HIGH": "bold yellow",
            "MEDIUM": "yellow",
            "LOW": "blue",
        }.get(vuln["severity"], "white")

        table.add_row(
            vuln["id"],
            f"[{severity_style}]{vuln['severity']}[/{severity_style}]",
            vuln["category"],
            vuln["description"][:35],
            "[red]YES[/red]" if vuln["multi_turn"] else "[dim]NO[/dim]",
        )

    console.print(table)
    console.print()
