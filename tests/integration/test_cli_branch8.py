"""Integration tests for attack and plugin CLI commands.

Tests:
- aipop generate-suffix
- aipop batch-attack
- aipop multi-model
- aipop cache-stats
- aipop cache-clear
- aipop plugins
- aipop check
"""

from __future__ import annotations

import importlib.util
import os

import pytest
from aipop.cli.harness import app
from typer.testing import CliRunner

_has_duckdb = importlib.util.find_spec("duckdb") is not None

runner = CliRunner()


class TestGenerateSuffixCLI:
    """Test generate-suffix command."""

    def test_generate_suffix_help(self):
        """Test that generate-suffix help works."""
        result = runner.invoke(app, ["generate-suffix", "--help"])
        assert result.exit_code == 0
        assert "generate-suffix" in result.output
        assert "GCG" in result.output or "gcg" in result.output

    def test_generate_suffix_requires_prompt(self):
        """Test that generate-suffix requires a prompt."""
        result = runner.invoke(app, ["generate-suffix"])
        assert result.exit_code != 0

    @pytest.mark.skipif(os.getenv("OPENAI_API_KEY") is None, reason="No API key available")
    def test_generate_suffix_legacy_pair(self):
        """Test generate-suffix with legacy PAIR (should work without plugins)."""
        result = runner.invoke(
            app,
            [
                "generate-suffix",
                "Test prompt",
                "--method",
                "pair",
                "--implementation",
                "legacy",
                "--streams",
                "1",
                "--iterations",
                "1",
            ],
        )
        # Should either succeed or fail gracefully with clear error
        assert "Error" not in result.output or "API key" in result.output


class TestBatchAttackCLI:
    """Test batch-attack command."""

    def test_batch_attack_help(self):
        """Test that batch-attack help works."""
        result = runner.invoke(app, ["batch-attack", "--help"])
        assert result.exit_code == 0
        assert "batch" in result.output.lower()

    def test_batch_attack_requires_input_file(self):
        """Test that batch-attack requires input file."""
        result = runner.invoke(app, ["batch-attack"])
        assert result.exit_code != 0

    def test_batch_attack_nonexistent_file(self):
        """Test batch-attack with non-existent file."""
        result = runner.invoke(
            app,
            ["batch-attack", "nonexistent_file.txt"],
        )
        assert result.exit_code != 0


class TestMultiModelCLI:
    """Test multi-model command."""

    def test_multi_model_help(self):
        """Test that multi-model help works."""
        result = runner.invoke(app, ["multi-model", "--help"])
        assert result.exit_code == 0
        assert "multi-model" in result.output or "model" in result.output

    def test_multi_model_requires_prompt(self):
        """Test that multi-model requires a prompt."""
        result = runner.invoke(app, ["multi-model"])
        assert result.exit_code != 0


class TestCacheCLI:
    """Test cache management commands."""

    def test_cache_stats_help(self):
        """Test that cache-stats help works."""
        result = runner.invoke(app, ["cache-stats", "--help"])
        assert result.exit_code == 0

    @pytest.mark.skipif(not _has_duckdb, reason="duckdb not installed")
    def test_cache_stats_runs(self):
        """Test that cache-stats command runs."""
        result = runner.invoke(app, ["cache-stats"])
        # Should succeed even if no cache exists
        assert result.exit_code == 0
        assert "Cache" in result.output or "cache" in result.output

    def test_cache_clear_help(self):
        """Test that cache-clear help works."""
        result = runner.invoke(app, ["cache-clear", "--help"])
        assert result.exit_code == 0

    @pytest.mark.skipif(not _has_duckdb, reason="duckdb not installed")
    def test_cache_clear_dry_run(self):
        """Test cache-clear without --all (only expired)."""
        result = runner.invoke(app, ["cache-clear"])
        # Should succeed even if no cache exists
        assert result.exit_code == 0


class TestPluginsCLI:
    """Test plugins management commands."""

    def test_plugins_list_help(self):
        """Test that plugins list help works."""
        result = runner.invoke(app, ["plugins", "list", "--help"])
        assert result.exit_code == 0

    def test_plugins_list_runs(self):
        """Test that plugins list command runs."""
        result = runner.invoke(app, ["plugins", "list"])
        assert result.exit_code == 0
        # Should show gcg, pair, autodan
        assert "gcg" in result.output.lower() or "GCG" in result.output

    def test_plugins_info_gcg(self):
        """Test plugins info for GCG."""
        result = runner.invoke(app, ["plugins", "info", "gcg"])
        assert result.exit_code == 0
        assert "gcg" in result.output.lower() or "GCG" in result.output

    def test_plugins_info_invalid(self):
        """Test plugins info with invalid plugin name."""
        result = runner.invoke(app, ["plugins", "info", "nonexistent"])
        assert result.exit_code != 0

    def test_plugins_install_help(self):
        """Test plugins install help."""
        result = runner.invoke(app, ["plugins", "install", "--help"])
        assert result.exit_code == 0


class TestCheckCLI:
    """Test check command."""

    def test_check_help(self):
        """Test that check help works."""
        result = runner.invoke(app, ["check", "--help"])
        assert result.exit_code == 0

    def test_check_runs(self):
        """Test that check command runs."""
        result = runner.invoke(app, ["check"])
        assert result.exit_code == 0
        # Should show system capabilities
        assert "Python" in result.output or "python" in result.output


class TestSecurityNoAPIKeyLeak:
    """Test that no API keys leak in outputs."""

    @pytest.mark.skipif(
        os.getenv("OPENAI_API_KEY") is None, reason="No API key to test leak protection"
    )
    def test_help_doesnt_leak_api_key(self):
        """Test that help output doesn't leak API keys."""
        api_key = os.getenv("OPENAI_API_KEY", "")
        if not api_key:
            pytest.skip("No API key to test")

        result = runner.invoke(app, ["--help"])
        assert api_key not in result.output

    @pytest.mark.skipif(
        os.getenv("OPENAI_API_KEY") is None, reason="No API key to test leak protection"
    )
    def test_version_doesnt_leak_api_key(self):
        """Test that version output doesn't leak API keys."""
        api_key = os.getenv("OPENAI_API_KEY", "")
        if not api_key:
            pytest.skip("No API key to test")

        result = runner.invoke(app, ["version"])
        assert api_key not in result.output

    def test_error_messages_safe(self):
        """Test that error messages don't leak sensitive data."""
        # Try command that will fail
        result = runner.invoke(
            app,
            ["generate-suffix", "test", "--implementation", "invalid"],
        )
        # Should not contain environment variable values
        if "OPENAI_API_KEY" in os.environ:
            assert os.environ["OPENAI_API_KEY"] not in result.output


class TestBackwardCompatibility:
    """Test that existing v0.7.2 commands still work."""

    def test_run_command_exists(self):
        """Test that 'run' command still exists."""
        result = runner.invoke(app, ["run", "--help"])
        assert result.exit_code == 0

    def test_gate_command_exists(self):
        """Test that 'gate' command still exists."""
        result = runner.invoke(app, ["gate", "--help"])
        assert result.exit_code == 0

    def test_recipe_command_exists(self):
        """Test that 'recipe' command still exists."""
        result = runner.invoke(app, ["recipe", "--help"])
        assert result.exit_code == 0

    def test_suites_command_exists(self):
        """Test that 'suites' command still exists."""
        result = runner.invoke(app, ["suites", "list", "--help"])
        assert result.exit_code == 0

    def test_version_command_exists(self):
        """Test that 'version' command still exists."""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "version" in result.output.lower()
