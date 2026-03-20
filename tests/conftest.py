"""Global pytest fixtures for all tests."""

from __future__ import annotations

from pathlib import Path

import pytest


def pytest_addoption(parser):
    """Add custom command-line options."""
    parser.addoption(
        "--run-slow",
        action="store_true",
        default=False,
        help="Run slow tests (Monte Carlo, stress tests)",
    )


def pytest_configure(config):
    """Configure pytest markers."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )


def pytest_collection_modifyitems(config, items):
    """Skip slow tests unless --run-slow is specified."""
    if config.getoption("--run-slow"):
        # Run all tests
        return

    skip_slow = pytest.mark.skip(reason="need --run-slow option to run")
    for item in items:
        if "slow" in item.keywords:
            item.add_marker(skip_slow)


@pytest.fixture
def project_root() -> Path:
    """Return the project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture
def temp_policy_dir(tmp_path: Path) -> Path:
    """Create a temporary directory for policy files."""
    policy_dir = tmp_path / "policies"
    policy_dir.mkdir(parents=True)
    return policy_dir
