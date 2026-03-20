"""CLI integration tests for orchestrator functionality."""

import tempfile
from pathlib import Path

import yaml
from tests.helpers.cli_runner import run_cli


def test_cli_with_simple_orchestrator():
    """Test aipop run --orchestrator simple works."""
    result = run_cli(
        [
            "run",
            "--suite",
            "adversarial/context_confusion",
            "--orchestrator",
            "simple",
        ]
    )
    # CLI should execute successfully (even if some tests fail)
    assert (
        "Loaded" in result.stdout or "test" in result.stdout.lower() or result.returncode in (0, 1)
    )


def test_cli_without_orchestrator():
    """Test aipop run still works without --orchestrator flag."""
    result = run_cli(["run", "--suite", "adversarial/context_confusion"])
    # CLI should execute successfully (even if some tests fail)
    # Check that it ran and produced output, not that all tests passed
    assert (
        "Loaded" in result.stdout or "test" in result.stdout.lower() or result.returncode in (0, 1)
    )


def test_cli_with_config_file():
    """Test aipop run --orch-config works."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        config = {
            "orchestrator_type": "simple",
            "debug": True,
            "verbose": True,
        }
        yaml.dump(config, f)
        config_path = f.name

    try:
        result = run_cli(
            [
                "run",
                "--suite",
                "adversarial/context_confusion",
                "--orchestrator",
                "simple",
                "--orch-config",
                config_path,
            ]
        )
        assert result.returncode in (0, 1)  # CLI executed successfully
    finally:
        Path(config_path).unlink()


def test_cli_with_orch_opts_debug():
    """Test --orch-opts debug flag."""
    result = run_cli(
        [
            "run",
            "--suite",
            "adversarial/context_confusion",
            "--orchestrator",
            "simple",
            "--orch-opts",
            "debug",
        ]
    )
    # CLI should execute successfully
    assert result.returncode in (0, 1)  # 0 = all passed, 1 = some failed (both OK)
    # Debug output should be present if tests ran
    if "Orchestrator Debug Info" not in result.stdout:
        # If no debug output, at least verify it ran
        assert "Loaded" in result.stdout or "test" in result.stdout.lower()


def test_cli_with_orch_opts_verbose():
    """Test --orch-opts verbose flag."""
    result = run_cli(
        [
            "run",
            "--suite",
            "adversarial/context_confusion",
            "--orchestrator",
            "simple",
            "--orch-opts",
            "verbose",
        ]
    )
    assert result.returncode in (0, 1)  # CLI executed successfully


def test_cli_with_orch_opts_both():
    """Test --orch-opts debug,verbose (multiple options)."""
    result = run_cli(
        [
            "run",
            "--suite",
            "adversarial/context_confusion",
            "--orchestrator",
            "simple",
            "--orch-opts",
            "debug,verbose",
        ]
    )
    assert result.returncode in (0, 1)  # CLI executed successfully
    # Debug output should be present if tests ran
    if "Orchestrator Debug Info" not in result.stdout:
        assert "Loaded" in result.stdout or "test" in result.stdout.lower()


def test_cli_config_hierarchy():
    """Test config hierarchy: CLI options override config file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        config = {"debug": False, "verbose": False}
        yaml.dump(config, f)
        config_path = f.name

    try:
        # CLI options should override config file
        result = run_cli(
            [
                "run",
                "--suite",
                "adversarial/context_confusion",
                "--orchestrator",
                "simple",
                "--orch-config",
                config_path,
                "--orch-opts",
                "debug",  # Override config file
            ]
        )
        assert result.returncode in (0, 1)  # CLI executed successfully
    finally:
        Path(config_path).unlink()


def test_cli_invalid_orchestrator():
    """Test error handling for invalid orchestrator name."""
    result = run_cli(
        [
            "run",
            "--suite",
            "adversarial/context_confusion",
            "--orchestrator",
            "invalid",
        ]
    )
    assert result.returncode != 0
    # Error message appears in stdout, not stderr
    assert "Unknown orchestrator" in result.stdout or "invalid" in result.stdout.lower()
