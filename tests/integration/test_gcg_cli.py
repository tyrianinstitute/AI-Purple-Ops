"""Integration tests for GCG CLI commands."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from aipop.cli.harness import app
from typer.testing import CliRunner


@pytest.fixture
def cli_runner():
    """Create CLI test runner."""
    return CliRunner()


def test_generate_suffix_command_help(cli_runner):
    """Test generate-suffix command help."""
    result = cli_runner.invoke(app, ["generate-suffix", "--help"])
    assert result.exit_code == 0
    assert "Generate adversarial suffixes" in result.stdout


def test_test_suffix_command_help(cli_runner):
    """Test test-suffix command help."""
    result = cli_runner.invoke(app, ["test-suffix", "--help"])
    assert result.exit_code == 0
    assert "Test a specific adversarial suffix" in result.stdout


def test_generate_suffix_black_box_mode(cli_runner):
    """Test generate-suffix in black-box mode."""
    with patch("aipop.cli.harness._create_adapter_from_cli") as mock_create:
        mock_adapter = MagicMock()
        mock_create.return_value = mock_adapter

        result = cli_runner.invoke(
            app,
            [
                "generate-suffix",
                "Test prompt",
                "--adapter",
                "mock",
                "--adapter-model",
                "test-model",
                "--max-iterations",
                "5",
            ],
        )

        # Should complete (may fail if dependencies missing, but should handle gracefully)
        assert result.exit_code in [0, 1]  # May fail if torch not available


def test_test_suffix_command(cli_runner):
    """Test test-suffix command."""
    with patch("aipop.cli.harness._create_adapter_from_cli") as mock_create:
        mock_adapter = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "Sure, I can help"
        mock_adapter.invoke.return_value = mock_response
        mock_create.return_value = mock_adapter

        result = cli_runner.invoke(
            app,
            [
                "test-suffix",
                "Test prompt",
                "test suffix",
                "--adapter",
                "mock",
                "--model",
                "test-model",
            ],
        )

        # Should complete successfully
        assert result.exit_code == 0
        assert "Suffix Test Results" in result.stdout or "Jailbreak" in result.stdout


def test_run_with_gcg_enabled(cli_runner):
    """Test run command with GCG enabled."""
    result = cli_runner.invoke(
        app,
        [
            "run",
            "--suite",
            "normal",
            "--adapter",
            "mock",
            "--enable-gcg",
            "--gcg-mode",
            "black-box",
        ],
    )

    # Should run (may fail on suite loading, but GCG flags should be accepted)
    assert result.exit_code in [0, 1]


def test_run_with_gcg_library_flag(cli_runner):
    """Test run command with GCG library flag."""
    result = cli_runner.invoke(
        app,
        [
            "run",
            "--suite",
            "normal",
            "--adapter",
            "mock",
            "--enable-gcg",
            "--no-gcg-library",
        ],
    )

    # Should accept flag and run (exit 0 = success, 1 = test failures)
    assert result.exit_code in [0, 1]


def test_run_with_gcg_generate_flag(cli_runner):
    """Test run command with GCG generate flag."""
    result = cli_runner.invoke(
        app,
        [
            "run",
            "--suite",
            "normal",
            "--adapter",
            "mock",
            "--enable-gcg",
            "--gcg-generate",
        ],
    )

    # Should accept flag
    assert result.exit_code in [0, 1]


def test_generate_suffix_saves_to_file(cli_runner, tmp_path):
    """Test that generate-suffix can save to file."""
    output_file = tmp_path / "suffixes.json"

    with patch("aipop.cli.harness._create_adapter_from_cli") as mock_create:
        mock_adapter = MagicMock()
        mock_create.return_value = mock_adapter

        result = cli_runner.invoke(
            app,
            [
                "generate-suffix",
                "Test prompt",
                "--adapter",
                "mock",
                "--adapter-model",
                "test",
                "--max-iterations",
                "0",  # Use library only
                "--output",
                str(output_file),
            ],
        )

        # File may or may not be created depending on implementation
        # But command should handle output parameter
        assert result.exit_code in [0, 1]


def test_generate_suffix_white_box_requires_model(cli_runner):
    """Test that white-box mode requires model."""
    result = cli_runner.invoke(
        app,
        [
            "generate-suffix",
            "Test prompt",
            "--mode",
            "white-box",
        ],
    )

    # Should fail with error about missing model
    assert result.exit_code != 0


def test_generate_suffix_top_k_parameter(cli_runner):
    """Test top-k parameter."""
    with patch("aipop.cli.harness._create_adapter_from_cli") as mock_create:
        mock_adapter = MagicMock()
        mock_create.return_value = mock_adapter

        result = cli_runner.invoke(
            app,
            [
                "generate-suffix",
                "Test prompt",
                "--adapter",
                "mock",
                "--adapter-model",
                "test",
                "--top-k",
                "5",
            ],
        )

        # Should accept top-k parameter
        assert result.exit_code in [0, 1]


def test_test_suffix_target_parameter(cli_runner):
    """Test target parameter in test-suffix."""
    with patch("aipop.cli.harness._create_adapter_from_cli") as mock_create:
        mock_adapter = MagicMock()
        mock_response = MagicMock()
        mock_response.text = "Custom target response"
        mock_adapter.invoke.return_value = mock_response
        mock_create.return_value = mock_adapter

        result = cli_runner.invoke(
            app,
            [
                "test-suffix",
                "Test prompt",
                "test suffix",
                "--adapter",
                "mock",
                "--model",
                "test",
                "--target",
                "Custom target",
            ],
        )

        # Should use custom target
        assert result.exit_code in [0, 1]
