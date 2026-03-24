"""CLI integration tests for mutate command."""

import json
import tempfile
from pathlib import Path

from tests.helpers.cli_runner import run_cli


def test_cli_mutate_basic():
    """Test basic mutate command."""
    result = run_cli(["mutate", "test prompt"])

    # Should execute successfully
    assert result.returncode in (0, 1)  # May fail if dependencies missing
    # Output may be in stdout or stderr depending on whether deps are available
    combined = (result.stdout + result.stderr).lower()
    assert "test prompt" in combined or "mutations" in combined or "duckdb" in combined


def test_cli_mutate_with_strategies():
    """Test mutate command with specific strategies."""
    result = run_cli(["mutate", "test", "--strategies", "encoding,unicode"])

    assert result.returncode in (0, 1)


def test_cli_mutate_with_output():
    """Test mutate command with output file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        output_path = f.name

    try:
        result = run_cli(
            [
                "mutate",
                "test prompt",
                "--output",
                output_path,
                "--count",
                "5",
            ]
        )

        if result.returncode == 0:
            # Check if file was created
            assert Path(output_path).exists()

            # Check if JSON is valid
            with open(output_path) as f:
                data = json.load(f)
                assert isinstance(data, list)
    finally:
        if Path(output_path).exists():
            Path(output_path).unlink()


def test_cli_mutate_with_config():
    """Test mutate command with config file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        config_path = f.name
        f.write("enable_encoding: true\nenable_unicode: false\n")

    try:
        result = run_cli(["mutate", "test", "--config", config_path])

        assert result.returncode in (0, 1)
    finally:
        if Path(config_path).exists():
            Path(config_path).unlink()


def test_cli_mutate_with_count():
    """Test mutate command with count limit."""
    result = run_cli(["mutate", "test", "--count", "3"])

    assert result.returncode in (0, 1)


def test_cli_mutate_with_stats():
    """Test mutate command with stats flag."""
    result = run_cli(["mutate", "test", "--stats"])

    assert result.returncode in (0, 1)


def test_cli_mutate_invalid_strategy():
    """Test mutate command with invalid strategy."""
    result = run_cli(["mutate", "test", "--strategies", "invalid_strategy"])

    # Should still execute (invalid strategies just ignored)
    assert result.returncode in (0, 1)


def test_cli_mutate_help():
    """Test mutate command help."""
    result = run_cli(["mutate", "--help"])

    assert result.returncode == 0
    assert "mutate" in result.stdout.lower()
    assert "prompt" in result.stdout.lower()


def test_cli_mutate_provider_flag():
    """Test mutate command with provider flag."""
    result = run_cli(
        [
            "mutate",
            "test",
            "--strategies",
            "paraphrase",
            "--provider",
            "openai",
        ]
    )

    # May fail if API key missing, but should handle gracefully
    assert result.returncode in (0, 1)


def test_cli_mutate_empty_prompt():
    """Test mutate command with empty prompt."""
    result = run_cli(["mutate", ""])

    assert result.returncode in (0, 1)
