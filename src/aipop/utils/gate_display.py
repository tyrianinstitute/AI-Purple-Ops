"""Rich-based display for gate results."""

from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.table import Table

from aipop.core.gates import GateResult


def display_gate_results(
    gate_result: GateResult,
    evidence_pack_path: Path | None = None,
) -> None:
    """Display gate evaluation results in a formatted table.

    Args:
        gate_result: Result of gate evaluation
        evidence_pack_path: Optional path to generated evidence pack
    """
    console = Console()

    # Create table for threshold checks
    table = Table(title="Gate Evaluation Results", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", justify="right", style="yellow")
    table.add_column("Status", justify="center", style="bold")

    # Parse reason string to extract individual checks
    # Format: "Gate passed: metric1=0.05 <= 0.05 (PASS); metric2=0.10 > 0.05 (FAIL)"
    reason = gate_result.reason
    if reason.startswith("Gate passed: "):
        reason = reason[13:]  # Remove "Gate passed: " prefix
    elif reason.startswith("Gate failed: "):
        reason = reason[13:]  # Remove "Gate failed: " prefix

    # Split by semicolon to get individual checks
    checks = [c.strip() for c in reason.split(";")]

    for check in checks:
        if not check:
            continue

        # Parse check format: "metric=value comparison threshold (STATUS)"
        # Example: "harmful_output_rate=0.05 <= 0.05 (PASS)"
        parts = check.split("(")
        if len(parts) >= 2:
            status_str = parts[-1].rstrip(")")
            metric_part = parts[0].strip()

            # Extract metric name and value
            if "=" in metric_part:
                metric_name, rest = metric_part.split("=", 1)
                metric_name = metric_name.strip()

                # Try to extract value (first number)
                value_str = rest.split()[0] if rest.split() else "0.0"
                try:
                    value = float(value_str)
                except ValueError:
                    # Log warning but continue - this is display code, shouldn't crash
                    from aipop.utils.log_utils import log

                    log.warn(f"Could not parse metric value from gate result: {check}")
                    value = 0.0

                # Determine status color
                if status_str == "PASS":
                    status_color = "[green]✓ PASS[/]"
                elif status_str == "FAIL" or "FAIL_ON" in status_str:
                    status_color = "[red]✗ FAIL[/]"
                else:
                    status_color = f"[yellow]{status_str}[/]"

                table.add_row(metric_name, f"{value:.4f}", status_color)

    # Display table
    console.print()
    console.print(table)

    # Display overall result
    console.print()
    if gate_result.passed:
        console.print("[bold green]✓ Gate PASSED[/] - All thresholds met")
    else:
        console.print("[bold red]✗ Gate FAILED[/] - Threshold(s) breached")

    # Display evidence pack location if generated
    if evidence_pack_path:
        console.print()
        console.print(f"[dim]Evidence pack: {evidence_pack_path}[/]")
