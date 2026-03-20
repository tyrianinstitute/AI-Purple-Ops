"""Nuclei-style progress bars and status indicators using Rich."""

from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager

from rich.console import Console
from rich.markup import escape
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskID,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from aipop.core.models import RunResult

import sys as _sys

console = Console()
_stderr_console = Console(stderr=True)


def get_console() -> Console:
    """Get the appropriate console -- stderr when JSON output is active."""
    import os
    if os.environ.get("AIPOP_JSON_OUTPUT") == "1":
        return _stderr_console
    return console


@contextmanager
def test_progress(
    total: int, suite_name: str = "tests", show_progress: bool = True
) -> Iterator[TestProgressTracker]:
    """Context manager for test execution progress tracking.

    Provides Nuclei-style progress bars with live updates during test execution.

    Args:
        total: Total number of tests to execute
        suite_name: Name of the test suite
        show_progress: Whether to show progress bar (False for quiet mode)

    Yields:
        TestProgressTracker for updating progress

    Example:
        >>> with test_progress(10, "normal") as tracker:
        ...     for test in tests:
        ...         result = run_test(test)
        ...         tracker.update(result)
    """
    if not show_progress:
        # Minimal mode - just yield tracker without progress display
        tracker = TestProgressTracker(None, total, suite_name)
        yield tracker
        return

    # Display header
    get_console().print(f"\n[bold blue][*][/] Running suite: {suite_name} ({total} tests)\n")

    # Create Rich progress bar
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        TimeRemainingColumn(),
        console=console,
    )

    with progress:
        task_id = progress.add_task("[cyan]Executing tests...", total=total)
        tracker = TestProgressTracker(progress, total, suite_name, task_id)
        yield tracker

    # Display summary after progress bar completes
    tracker.print_summary()


class TestProgressTracker:
    """Track test execution progress and results.

    Updates Rich progress bar and collects results for final summary.
    """

    def __init__(
        self,
        progress: Progress | None,
        total: int,
        suite_name: str,
        task_id: TaskID | None = None,
    ) -> None:
        """Initialize progress tracker."""
        self.progress = progress
        self.total = total
        self.suite_name = suite_name
        self.task_id = task_id
        self.results: list[RunResult] = []
        self.start_time = time.time()

    def update(self, result: RunResult) -> None:
        """Update progress with a completed test result.

        Args:
            result: Completed test result
        """
        self.results.append(result)

        if self.progress and self.task_id is not None:
            # Update progress bar
            self.progress.update(self.task_id, advance=1)

            # Print per-test status line (Nuclei style)
            status_icon = "✓" if result.passed else "✗"
            status_color = "green" if result.passed else "red"

            # Extract timing
            timing = ""
            if "elapsed_ms" in result.metadata:
                ms = result.metadata["elapsed_ms"]
                timing = f"[{ms:.0f}ms]"

            # Print single status line per test (avoids Rich progress bar interleaving)
            line = f"[{status_color}]{status_icon}[/] {result.test_id:40} {timing}"
            if not result.passed:
                if "error" in result.metadata:
                    line += f" [dim red]- {result.metadata['error']}[/]"
                elif result.detector_results:
                    violations = []
                    for detector_result in result.detector_results:
                        for violation in detector_result.violations:
                            violations.append(f"{violation.severity.upper()}: {violation.message}")
                    if violations:
                        line += f" [dim]- {'; '.join(violations[:2])}[/]"
            get_console().print(line)

    def print_summary(self) -> None:
        """Print final summary table after all tests complete."""
        if not self.results:
            return

        elapsed_sec = time.time() - self.start_time
        passed = sum(1 for r in self.results if r.passed)
        failed = len(self.results) - passed

        # Count policy violations
        total_violations = 0
        critical_violations = 0
        for result in self.results:
            if result.detector_results:
                for detector_result in result.detector_results:
                    total_violations += len(detector_result.violations)
                    critical_violations += sum(
                        1 for v in detector_result.violations if v.severity == "critical"
                    )

        # Summary stats line (Nuclei style)
        get_console().print()
        summary_parts = []
        if passed > 0:
            summary_parts.append(f"[green]{passed} passed[/]")
        if failed > 0:
            summary_parts.append(f"[red]{failed} failed[/]")

        summary_parts.append("[dim]0 skipped[/]")
        if total_violations > 0:
            violation_color = "bold red" if critical_violations > 0 else "red"
            summary_parts.append(f"[{violation_color}]{total_violations} violations[/]")
        summary_parts.append(f"[dim]({elapsed_sec:.1f}s total)[/]")

        get_console().print(f"[bold]Results:[/] {', '.join(summary_parts)}\n")

    def get_results(self) -> list[RunResult]:
        """Get all collected test results.

        Returns:
            List of test results
        """
        return self.results


def print_test_result_table(results: list[RunResult]) -> None:
    """Print a detailed table of test results.

    Args:
        results: List of test results to display
    """
    if not results:
        get_console().print("[yellow]No results to display[/]")
        return

    table = Table(title="Test Results", show_header=True, header_style="bold cyan")
    table.add_column("Test ID", style="cyan", no_wrap=True)
    table.add_column("Status", justify="center")
    table.add_column("Time", justify="right")
    table.add_column("Response Preview", style="dim", max_width=50)

    for result in results:
        # Status icon
        status = "✓" if result.passed else "✗"
        status_style = "green" if result.passed else "red"

        # Timing
        timing = ""
        if "elapsed_ms" in result.metadata:
            timing = f"{result.metadata['elapsed_ms']:.0f}ms"

        # Response preview (first 50 chars)
        response_preview = result.response[:50]
        if len(result.response) > 50:
            response_preview += "..."

        table.add_row(
            result.test_id,
            f"[{status_style}]{status}[/]",
            timing,
            response_preview,
        )

    get_console().print(table)


def print_error(message: str) -> None:
    """Print an error message with Nuclei-style formatting.

    Args:
        message: Error message to display
    """
    # Use Rich's escape() function to properly escape markup in user-provided strings
    escaped_message = escape(message)
    get_console().print(f"[bold red][!][/] {escaped_message}")


def print_warning(message: str) -> None:
    """Print a warning message with Nuclei-style formatting.

    Args:
        message: Warning message to display
    """
    # Use Rich's escape() function to properly escape markup in user-provided strings
    escaped_message = escape(message)
    get_console().print(f"[bold yellow][!][/] {escaped_message}")


def print_info(message: str) -> None:
    """Print an info message with Nuclei-style formatting.

    Args:
        message: Info message to display
    """
    # Use Rich's escape() function to properly escape markup in user-provided strings
    escaped_message = escape(message)
    get_console().print(f"[bold blue][*][/] {escaped_message}")


def print_success(message: str) -> None:
    """Print a success message with Nuclei-style formatting.

    Args:
        message: Success message to display
    """
    # Use Rich's escape() function to properly escape markup in user-provided strings
    escaped_message = escape(message)
    get_console().print(f"[bold green][✓][/] {escaped_message}")
