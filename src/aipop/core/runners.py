"""Runner protocol for test execution logic."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Protocol

from .models import RunResult, TestCase


class Runner(Protocol):
    """Execution logic (CI/CD controller analogy)."""

    def execute(self, test_case: TestCase) -> RunResult:
        """Execute a single test case and return result."""
        ...

    def execute_many(self, cases: list[TestCase]) -> Iterator[RunResult]:
        """Execute multiple test cases, yielding results as they complete.

        Supports streaming to reporters and progress logging without
        buffering all results in memory.
        """
        ...

    # TODO(b05): Add policy oracle integration
    # TODO(b06): Add gate threshold checks
