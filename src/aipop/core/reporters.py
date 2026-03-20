"""Reporter protocol for metrics and logging."""

from __future__ import annotations

from typing import Protocol

from .models import RunResult


class Reporter(Protocol):
    """Metrics and logging (telemetry backend analogy)."""

    def start(self, path: str) -> None:
        """Start a new report at the given path.

        Initializes output file/stream. Supports streaming large test runs
        without buffering all results in memory.
        """
        ...

    def write_case(self, result: RunResult) -> None:
        """Write a single test case result.

        Called as each test completes, enabling progress tracking and
        incremental output for long-running suites.
        """
        ...

    def finalize(self) -> None:
        """Finalize and close the report.

        Writes summary statistics, closes file handles, and ensures
        all buffered data is flushed.
        """
        ...

    def write_summary(self, results: list[RunResult], path: str) -> None:
        """Convenience method: write all results at once.

        Calls start(), write_case() for each result, then finalize().
        Useful for small test runs or backward compatibility.
        """
        ...

    # TODO(b04): JSON reporter implementation
    # TODO(b04): JUnit XML reporter implementation
    # TODO: not yet implemented - CI/CD status check integration
