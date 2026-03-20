"""Cinematic terminal output — designed for asciinema recordings.

Every component is optimized for the 3-5 second first impression:
compact, color-coded, streams fast. Panels for structure, one-liners
for findings. No wasted vertical space.
"""

from __future__ import annotations

from datetime import UTC, datetime

from rich.console import Console
from rich.panel import Panel

# Severity styles — calibrated for dark terminals (the pentester default)
SEVERITY_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH": "bold red",
    "MEDIUM": "yellow",
    "LOW": "dim cyan",
    "UNKNOWN": "dim",
}

SEVERITY_BADGE = {
    "CRITICAL": "[bold white on red] CRIT [/]",
    "HIGH": "[bold red] HIGH [/]",
    "MEDIUM": "[yellow] MED  [/]",
    "LOW": "[dim cyan] LOW  [/]",
    "UNKNOWN": "[dim] ??   [/]",
}


def mode_banner(
    adapter_name: str,
    model_name: str,
    test_count: int,
    is_static: bool = False,
    console: Console | None = None,
) -> None:
    """Print the scan mode header — first thing the viewer sees."""
    console = console or Console(stderr=True)

    if is_static:
        mode_line = "[dim]mode:[/] [yellow]STATIC[/] [dim](no LLM — canned responses for pipeline validation)[/]"
    else:
        mode_line = f"[dim]mode:[/] [green]LIVE[/] [dim]({adapter_name}/{model_name})[/]"

    console.print()
    console.print(f"  [bold cyan]◎ aipop scan[/]  {mode_line}")
    console.print(f"  [dim]{test_count} tests loaded[/]")
    console.print()


def recon_panel(
    target: str,
    capabilities: dict[str, bool],
    recommended_suites: list[str],
    console: Console | None = None,
) -> None:
    """Display recon/discovery results — compact, capability indicators."""
    console = console or Console(stderr=True)

    # Capabilities as a single line with icons
    cap_parts = []
    for cap, detected in capabilities.items():
        icon = "[green]●[/]" if detected else "[dim]○[/]"
        label = cap.replace("_", " ").replace("system prompt visible", "sysinfo leak")
        cap_parts.append(f"{icon} {label}")

    caps_line = "  ".join(cap_parts)

    suites_str = ", ".join(recommended_suites[:5])
    if len(recommended_suites) > 5:
        suites_str += f" (+{len(recommended_suites) - 5})"

    content = (
        f"[bold]target:[/]  {target}\n[bold]surface:[/] {caps_line}\n[bold]suites:[/]  {suites_str}"
    )

    console.print(
        Panel(
            content,
            title="[bold cyan]recon[/]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
    console.print()


def finding_line(
    test_id: str,
    severity: str,
    category: str,
    description: str,
    is_static: bool = False,
    console: Console | None = None,
) -> None:
    """Print a single finding as one compact line — Nuclei-style.

    Static mode uses a dim SIM badge so findings can't be mistaken for real.
    Live mode uses severity-colored badges (CRIT, HIGH, MED, LOW).
    """
    console = console or Console(stderr=True)

    sev = severity.upper()
    ts = datetime.now(UTC).strftime("%H:%M:%S")

    if is_static:
        badge = "[dim] SIM  [/]"
        console.print(
            f"  [dim]{ts}[/] {badge} [dim]{test_id} | {category} | {description}[/]",
            highlight=False,
        )
    else:
        badge = SEVERITY_BADGE.get(sev, SEVERITY_BADGE["UNKNOWN"])
        console.print(
            f"  [dim]{ts}[/] {badge} [bold]{test_id}[/] [dim]|[/] {category} [dim]|[/] {description}",
            highlight=False,
        )


def pass_line(
    test_id: str,
    console: Console | None = None,
) -> None:
    """Print a passing test as a dim one-liner (optional, for verbose mode)."""
    console = console or Console(stderr=True)
    ts = datetime.now(UTC).strftime("%H:%M:%S")
    console.print(f"  [dim]{ts}  pass  {test_id}[/]", highlight=False)


def progress_line(
    completed: int,
    total: int,
    passed: int,
    failed: int,
    console: Console | None = None,
) -> None:
    """Print inline progress counter — updates every N tests."""
    console = console or Console(stderr=True)
    pct = (completed / total * 100) if total > 0 else 0
    console.print(
        f"  [dim]progress:[/] {completed}/{total} ({pct:.0f}%) "
        f"[green]{passed} pass[/] [red]{failed} fail[/]",
        highlight=False,
    )


def scan_summary(
    total: int,
    passed: int,
    failed: int,
    severity_counts: dict[str, int],
    evidence_path: str | None = None,
    adapter_name: str = "unknown",
    model_name: str = "unknown",
    elapsed_secs: float = 0.0,
    cost_usd: float = 0.0,
    is_static: bool = False,
    console: Console | None = None,
) -> None:
    """Display end-of-scan summary panel."""
    console = console or Console(stderr=True)

    if is_static:
        status = "[yellow]STATIC COMPLETE[/]"
        border = "yellow"
    elif failed > 0:
        status = "[bold red]VULNERABLE[/]"
        border = "red"
    else:
        status = "[bold green]CLEAN[/]"
        border = "green"

    lines = [
        f"[bold]status:[/]  {status}",
        f"[bold]target:[/]  {adapter_name}/{model_name}",
        f"[bold]tests:[/]   {total} ({passed} passed, {failed} failed)",
    ]

    if elapsed_secs > 0:
        lines.append(f"[bold]time:[/]    {elapsed_secs:.1f}s")

    if cost_usd > 0 and not is_static:
        lines.append(f"[bold]cost:[/]    ${cost_usd:.4f}")

    # Severity breakdown — compact, one line
    if severity_counts and any(v > 0 for v in severity_counts.values()):
        sev_parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = severity_counts.get(sev, 0)
            if count > 0:
                style = SEVERITY_STYLE.get(sev, "dim")
                sev_parts.append(f"[{style}]{count} {sev.lower()}[/]")
        if sev_parts:
            label = "simulated" if is_static else "vulns"
            lines.append(f"[bold]{label}:[/]  {', '.join(sev_parts)}")

    if evidence_path:
        lines.append(f"[bold]report:[/]  {evidence_path}")

    if is_static:
        lines.append("")
        lines.append("[dim]static mode — no LLM, no adaptive attacks, no real model interaction[/]")
        lines.append("[dim]validated: suite loading, detectors, reporters, evidence pipeline[/]")
        lines.append("[dim]next: aipop scan --adapter openai --model gpt-4o-mini[/]")

    if failed > 0 and not is_static:
        lines.append("")
        lines.append("[dim]next: aipop gate --generate-evidence[/]")

    content = "\n".join(lines)
    console.print()
    console.print(
        Panel(content, title="[bold cyan]scan complete[/]", border_style=border, padding=(0, 1))
    )
    console.print()
