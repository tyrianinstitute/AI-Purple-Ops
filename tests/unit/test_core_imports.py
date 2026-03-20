"""Smoke test for core interface imports."""

from __future__ import annotations


def test_core_imports() -> None:
    """Verify all core interfaces are importable."""
    from aipop.core import (
        Adapter,
        ModelResponse,
        Reporter,
        Runner,
        RunResult,
        TestCase,
    )

    assert all([Adapter, ModelResponse, Reporter, RunResult, Runner, TestCase])
