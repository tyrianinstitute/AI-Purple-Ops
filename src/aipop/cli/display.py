"""Cinematic terminal output — designed for asciinema recordings.

Every component is optimized for the 3-5 second first impression:
compact, color-coded, streams fast. Panels for structure, one-liners
for findings. No wasted vertical space.
"""

from __future__ import annotations

from datetime import UTC, datetime

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn, MofNCompleteColumn

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
    target_url: str | None = None,
    console: Console | None = None,
) -> None:
    """Print the scan mode header — first thing the viewer sees."""
    console = console or Console(stderr=True)

    if is_static:
        mode_line = "[yellow]STATIC[/] [dim](pipeline validation, no LLM)[/]"
    elif target_url:
        mode_line = f"[green]LIVE[/] → [bold]{target_url}[/]"
    else:
        mode_line = f"[green]LIVE[/] [dim]({adapter_name}/{model_name})[/]"

    console.print()
    console.print(f"  [bold magenta]▸ aipop scan[/]  {mode_line}")
    console.print(f"  [dim]{test_count} tests loaded[/]")
    console.print()


def recon_panel(
    target: str,
    capabilities: dict[str, bool],
    recommended_suites: list[str],
    details: dict[str, str] | None = None,
    console: Console | None = None,
    recon_report: "ReconReport | None" = None,
) -> None:
    """Display recon/discovery results — compact, capability grid.

    If a ReconReport is provided, renders the full HTTP + behavioral
    panel. Otherwise falls back to the legacy capability grid.
    """
    console = console or Console(stderr=True)

    # ── New-style panel from ReconReport ────────────────────────
    if recon_report is not None:
        content = recon_report.to_rich_panel()
        console.print(
            Panel(
                content,
                title="[bold cyan]recon[/]",
                border_style="cyan",
                padding=(0, 1),
            )
        )
        console.print()
        return

    # ── Legacy panel (backward compat) ──────────────────────────
    details = details or {}

    # Capabilities as a clean grid
    cap_parts = []
    for cap, detected in capabilities.items():
        label = cap.replace("_", " ").replace("system prompt visible", "sysinfo leak")
        if detected:
            cap_parts.append(f"[green]■[/] {label}")
        else:
            cap_parts.append(f"[dim]□ {label}[/]")

    # Two-column layout for capabilities
    caps_lines = []
    for i in range(0, len(cap_parts), 2):
        left = cap_parts[i] if i < len(cap_parts) else ""
        right = cap_parts[i + 1] if i + 1 < len(cap_parts) else ""
        if right:
            caps_lines.append(f"  {left:<40s}{right}")
        else:
            caps_lines.append(f"  {left}")

    caps_block = "\n".join(caps_lines)

    # Key findings from discovery — one-liner assessments
    findings = []
    if "file_upload" in details and isinstance(details["file_upload"], str):
        if "NO content scanning" in details["file_upload"]:
            findings.append("[red]▸ Upload: unguarded — injection payloads accepted into RAG pipeline[/]")
        elif "ACTIVE" in details["file_upload"]:
            findings.append("[green]▸ Upload: content scanning active[/]")
    if capabilities.get("rag_retrieval"):
        findings.append("[yellow]▸ RAG: grounded responses detected — knowledge base is attack surface[/]")

    findings_block = ""
    if findings:
        findings_block = "\n[bold]findings:[/]\n" + "\n".join(f"  {f}" for f in findings)

    suites_str = ", ".join(recommended_suites[:5])
    if len(recommended_suites) > 5:
        suites_str += f" (+{len(recommended_suites) - 5})"

    content = (
        f"[bold]target:[/]  {target}\n"
        f"[bold]surface:[/]\n{caps_block}"
        f"{findings_block}\n"
        f"[bold]suites:[/]  {suites_str}"
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
    latency_ms: float = 0,
    is_static: bool = False,
    console: Console | None = None,
    raw_ids: bool = False,
) -> None:
    """Print a single finding as one compact line — Nuclei-style.

    Static mode uses a dim SIM badge so findings can't be mistaken for real.
    Live mode uses severity-colored badges (CRIT, HIGH, MED, LOW).
    Uses human-readable titles from the finding taxonomy when available.
    """
    console = console or Console(stderr=True)

    # Resolve human-readable title from taxonomy
    display_name = test_id
    if not raw_ids:
        try:
            from aipop.data import get_finding_title
            title = get_finding_title(test_id)
            if title != test_id:
                display_name = title
        except ImportError:
            pass

    sev = severity.upper()
    ts = datetime.now(UTC).strftime("%H:%M:%S")
    latency_str = f" [dim]({latency_ms:.0f}ms)[/]" if latency_ms > 0 else ""

    if is_static:
        badge = "[dim] SIM  [/]"
        console.print(
            f"  [dim]{ts}[/] {badge} [dim]{display_name} | {category} | {description}[/]",
            highlight=False,
        )
    else:
        badge = SEVERITY_BADGE.get(sev, SEVERITY_BADGE["UNKNOWN"])
        console.print(
            f"  [dim]{ts}[/] {badge} [bold]{display_name}[/] [dim]|[/] {category}{latency_str}",
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


def create_scan_progress(total: int, console: Console | None = None) -> Progress:
    """Create a Rich progress bar for scan execution.

    Returns a Progress context manager. Use with:
        with create_scan_progress(total) as progress:
            task = progress.add_task("scanning", total=total)
            progress.update(task, advance=1)
    """
    console = console or Console(stderr=True)
    return Progress(
        SpinnerColumn("dots", style="magenta"),
        TextColumn("[bold magenta]scanning[/]"),
        BarColumn(bar_width=30, style="dim", complete_style="magenta", finished_style="green"),
        MofNCompleteColumn(),
        TextColumn("[dim]•[/]"),
        TimeRemainingColumn(compact=True),
        console=console,
        transient=False,
    )


def progress_line(
    completed: int,
    total: int,
    passed: int,
    failed: int,
    console: Console | None = None,
) -> None:
    """Print inline progress counter — fallback when progress bar isn't used."""
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
    target_url: str | None = None,
    elapsed_secs: float = 0.0,
    cost_usd: float = 0.0,
    is_static: bool = False,
    console: Console | None = None,
    errors: int = 0,
    overall_verdict: str = "",
    verdicts: dict[str, int] | None = None,
) -> None:
    """Display end-of-scan summary panel."""
    console = console or Console(stderr=True)

    if is_static:
        status = "[yellow]STATIC COMPLETE[/]"
        border = "yellow"
    elif overall_verdict:
        # Use the verdict model when available
        verdict_display = {
            "VULNERABLE": ("[bold red]VULNERABLE[/]", "red"),
            "CLEAN": ("[bold green]CLEAN[/]", "green"),
            "INCONCLUSIVE": ("[bold yellow]INCONCLUSIVE[/]", "yellow"),
            "ERROR": ("[bold yellow]ERROR[/]", "yellow"),
        }
        status, border = verdict_display.get(
            overall_verdict, ("[bold yellow]INCONCLUSIVE[/]", "yellow")
        )
    elif errors > 0 and passed == 0 and failed == 0:
        status = "[bold yellow]ERROR — target unreachable[/]"
        border = "yellow"
    elif errors > 0 and failed == 0:
        status = f"[bold yellow]INCONCLUSIVE — {errors} errors[/]"
        border = "yellow"
    elif failed > 0:
        status = "[bold red]VULNERABLE[/]"
        border = "red"
    else:
        status = "[bold green]CLEAN[/]"
        border = "green"

    # Target display — prefer URL, fall back to adapter/model
    if target_url:
        target_display = target_url
    elif adapter_name and adapter_name not in ("unknown", "None", "static", "mock"):
        target_display = f"{adapter_name}/{model_name}"
    else:
        target_display = model_name

    test_summary = f"{total} ({passed} passed, {failed} failed"
    if errors > 0:
        test_summary += f", [yellow]{errors} errors[/]"
    test_summary += ")"

    lines = [
        f"[bold]status:[/]  {status}",
        f"[bold]target:[/]  {target_display}",
        f"[bold]tests:[/]   {test_summary}",
    ]

    if errors > 0 and passed == 0:
        lines.append("")
        lines.append("[yellow]all tests returned connection errors — the target may be down,[/]")
        lines.append("[yellow]misconfigured, or using different API field names.[/]")
        lines.append("[yellow]try: aipop scan <url> --prompt-field message --response-field reply[/]")

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
        lines.append("[bold]next:[/] [magenta]aipop gate --generate-evidence[/]")
        lines.append("")
        lines.append("[dim]this was a default scan. go deeper:[/]")
        lines.append("[dim]  aipop morph  — transform payloads through 17 bypass strategies[/]")
        lines.append("[dim]  aipop repl   — interactive workbench for manual exploration[/]")
        lines.append("[dim]  aipop diff   — compare before/after defenses (purple team)[/]")

    if not is_static and failed == 0:
        lines.append("")
        lines.append("[dim]clean on default scan. try targeted suites:[/]")
        lines.append("[dim]  aipop scan <target> --suite rag_injection[/]")
        lines.append("[dim]  aipop scan <target> --suite encoding_chains[/]")
        lines.append("[dim]  aipop morph 'your payload' --strategy evaluation_reframe[/]")

    content = "\n".join(lines)
    console.print()
    console.print(
        Panel(content, title="[bold cyan]scan complete[/]", border_style=border, padding=(0, 1))
    )
    console.print()
